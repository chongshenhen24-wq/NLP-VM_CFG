import os
import tempfile
import unittest
from unittest import mock

from cve_pipeline import pipeline
from cve_pipeline.config import Config
from cve_pipeline.domain import spec as spec_mod
from cve_pipeline.domain.generators import distro_kernel, kernel_qemu
from cve_pipeline.interfaces.server import Handler
from official_fixtures import official_bundle

KERNEL_SPEC = {
    "package": "linux-image-generic", "package_manager": "apt",
    "version_constraint": "<6.8.0-124.124",
    "concrete_kernel_constraint": "<6.8.0-124.124", "os_family": "ubuntu",
    "os_version": "24.04", "config_directives": [], "setup_commands": [],
}


class DistroKernelTests(unittest.TestCase):
    def test_normalizes_ubuntu_lts_release_label(self):
        normalized = spec_mod.normalize({
            "os_family": "ubuntu", "os_version": "Ubuntu 22.04 LTS (Jammy)"
        }, "ubuntu")
        self.assertEqual(normalized["os_version"], "22.04")
        codename = spec_mod.normalize({
            "os_family": "ubuntu", "os_version": "jammy"
        }, "ubuntu")
        self.assertEqual(codename["os_version"], "22.04")

    def test_kernel_detection_uses_package_or_cpe(self):
        self.assertTrue(distro_kernel.is_kernel_spec(KERNEL_SPEC))
        truth = {"products": [{"part": "o", "product": "linux_kernel"}]}
        self.assertTrue(distro_kernel.is_kernel_spec({"package": "unknown"}, truth))
        self.assertFalse(distro_kernel.is_kernel_spec({"package": "requests"}))
        with self.assertRaisesRegex(ValueError, "installable"):
            distro_kernel.build(dict(KERNEL_SPEC, package="linux"))

    def test_generated_workflow_is_reboot_gated_and_vm_only(self):
        script = distro_kernel.build(KERNEL_SPEC)
        self.assertIn('version_matches_constraint "$_cve_v"', script)
        self.assertIn('dpkg --compare-versions "$version" "$op" "$boundary"', script)
        self.assertIn("CONCRETE_CONSTRAINT='<6.8.0-124.124'", script)
        self.assertIn('version_matches_constraint "$concrete_version" "$CONCRETE_CONSTRAINT"', script)
        self.assertIn('FAILED concrete_kernel_constraint', script)
        self.assertIn('dpkg --compare-versions "$_cve_v" gt "$selected"', script)
        self.assertNotIn('//-/.', script)
        self.assertIn("EXPECTED_OS_FAMILY='ubuntu'", script)
        self.assertIn("EXPECTED_OS_VERSION='24.04'", script)
        self.assertIn('this recipe requires %s %s; detected %s %s', script)
        self.assertIn('apt-get install -s --allow-downgrades --no-remove', script)
        self.assertIn('apt-get install -y -q --allow-downgrades --no-remove', script)
        self.assertIn('/boot/vmlinuz-$expected', script)
        self.assertIn('matching headers package $header is unavailable', script)
        self.assertIn('grub-reboot "$grub_target"', script)
        self.assertIn('$2 == image', script)
        self.assertNotIn('"with Linux " kernel', script)
        self.assertNotIn('/Advanced options/', script)
        self.assertIn('ExecStart=/usr/local/sbin/cve-kernel-reproduction verify', script)
        self.assertIn('! [ "$0" -ef "$script_target" ]', script)
        self.assertIn('FAILED expected_kernel=', script)
        self.assertIn('READY kernel=', script)
        self.assertIn('manual_validation=true', script)
        self.assertNotIn('POC_', script)
        self.assertNotIn('runuser', script)
        self.assertNotIn('VERIFIED', script)
        self.assertNotIn('lineinfile', script)
        self.assertNotIn('>> /boot/config-', script)

    def test_ubuntu_package_constraint_stays_in_the_selected_binary_namespace(self):
        focal_meta = dict(
            KERNEL_SPEC,
            os_version="20.04",
            version_constraint="<5.4.0.105.109",
            concrete_kernel_constraint="<5.4.0-105.119",
        )
        meta_script = distro_kernel.build(focal_meta)
        self.assertIn("PACKAGE='linux-image-generic'", meta_script)
        self.assertIn("CONSTRAINT='<5.4.0.105.109'", meta_script)
        self.assertIn('apt-cache madison "$PACKAGE"', meta_script)
        self.assertIn("CONCRETE_CONSTRAINT='<5.4.0-105.119'", meta_script)

        focal_concrete = dict(
            focal_meta,
            package="linux-image-5.4.0-105-generic",
            version_constraint="<5.4.0-105.119",
        )
        concrete_script = distro_kernel.build(focal_concrete)
        self.assertIn("PACKAGE='linux-image-5.4.0-105-generic'", concrete_script)
        self.assertIn("CONSTRAINT='<5.4.0-105.119'", concrete_script)

        noble_meta = distro_kernel.build(KERNEL_SPEC)
        self.assertIn("PACKAGE='linux-image-generic'", noble_meta)
        self.assertIn("CONSTRAINT='<6.8.0-124.124'", noble_meta)

    def test_browser_rejects_poc_settings(self):
        handler = object.__new__(Handler)
        with self.assertRaisesRegex(ValueError, "outside this pipeline"):
            handler._generate({"environment": {}, "configuration": {"configuration_status": "not_required"},
                               "poc_success": "true"})

    def test_kernel_meta_package_requires_independent_concrete_constraint(self):
        spec = dict(KERNEL_SPEC)
        spec["concrete_kernel_constraint"] = ""
        with self.assertRaisesRegex(ValueError, "concrete_kernel_constraint"):
            distro_kernel.build(spec)

    def test_kernel_generation_requires_os_version(self):
        with self.assertRaisesRegex(ValueError, "exact OS version"):
            distro_kernel.build(dict(KERNEL_SPEC, os_version=""))

    def test_browser_generates_configuration_only_script(self):
        handler = object.__new__(Handler)
        configuration = {"configuration_status": "required", "kernel_modules": [
            {"name": "algif_aead", "state": "loaded", "persistent": True}
        ], "evidence": [{"claim": "module required", "source": "Primary CVE description",
                          "excerpt": "The algif_aead module must be loaded."}]}
        environment = {"status": "selected", "os_family": "ubuntu", "os_version": "24.04",
                       "vulnerable_constraints": {}}
        out = handler._generate({"environment": environment, "configuration": configuration,
                                 "sources": official_bundle(
                                     cve="CVE-2026-31431",
                                     description="The algif_aead module must be loaded.",
                                     os_version="24.04", suite="noble",
                                 ),
                                 "description": "The algif_aead module must be loaded.",
                                 "cve": "CVE-2026-31431"})
        self.assertNotIn("POC_", out["script"])
        self.assertNotIn("qemu-system", out["script"])
        self.assertNotIn("grub-reboot", out["script"])
        self.assertIn("modprobe algif_aead", out["script"])
        self.assertIn("guest-configuration", out["generator_used"])

    def test_analyst_note_does_not_skip_official_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Config(machines_dir=os.path.join(directory, "machines"), register=False)
            bundle = official_bundle(
                cve="CVE-2026-46333", description="No extra configuration is required."
            )
            extracted = {"configuration_status": "not_required", "summary": "Default is sufficient.",
                         "evidence": [{"claim": "No extra setting", "source": "Primary CVE description",
                                       "excerpt": "No extra configuration is required."}]}
            with mock.patch("cve_pipeline.adapters.sources.collect", return_value=bundle) as collect, \
                 mock.patch("cve_pipeline.adapters.ollama.extract_configuration", return_value=(extracted, "{}")):
                result = pipeline.run_one("CVE-2026-46333", cfg, "ubuntu", "analyst note",
                                          kernel_target="guest")
            collect.assert_called_once()
            self.assertEqual(result["workflow"], "vulnerable-vm+guest-configuration")
            self.assertEqual(result["sources"]["mode"], "enrich")
            self.assertEqual(result["sources"]["analyst_note"], "analyst note")
            self.assertTrue(result["official_source_policy"]["satisfied"])
            self.assertIn("No additional guest configuration", result["script"])
            self.assertNotIn("grub-reboot", result["script"])
            self.assertNotIn("POC_", result["script"])

    def test_browser_analyst_note_does_not_skip_official_sources(self):
        handler = object.__new__(Handler)
        bundle = official_bundle(
            cve="CVE-2024-35195", description="No extra configuration is required."
        )
        extracted = {"configuration_status": "not_required", "summary": "No extra configuration.",
                     "evidence": [{"claim": "No extra setting", "source": "Primary CVE description",
                                   "excerpt": "No extra configuration is required."}]}
        with mock.patch("cve_pipeline.interfaces.server.sources.collect", return_value=bundle) as collect, \
             mock.patch("cve_pipeline.interfaces.server.ollama.extract_configuration", return_value=(extracted, "{}")):
            out = handler._extract({"cve": "CVE-2024-35195", "description": "analyst note",
                                    "os_hint": "ubuntu"})
        collect.assert_called_once()
        self.assertEqual(out["sources"]["mode"], "enrich")
        self.assertTrue(out["official_source_policy"]["satisfied"])
        self.assertEqual(out["workflow"], "vulnerable-vm+guest-configuration")
        self.assertEqual(out["environment"]["status"], "selected")
        self.assertEqual(out["build_target"]["status"], "selected")

    def test_browser_returns_fail_closed_unknown_after_two_invalid_attempts(self):
        handler = object.__new__(Handler)
        invalid = {
            "configuration_status": "unknown", "summary": "No requirements found.",
            "kernel_modules": [], "kernel_config": [], "kernel_config_alternatives": [],
            "sysctls": [], "packages": [], "services": [], "file_settings": [],
            "manual_steps": [], "evidence": [],
        }
        description = "Requirements: Kernel configuration: CONFIG_DEMO=y"
        with mock.patch(
            "cve_pipeline.interfaces.server.sources.collect",
            return_value=official_bundle(description=description, os_version="24.04", suite="noble"),
        ), mock.patch(
            "cve_pipeline.interfaces.server.ollama.extract_configuration",
            return_value=(invalid, "{}"),
        ) as extract:
            out = handler._extract({
                "cve": "CVE-2026-12345",
                "os_hint": "ubuntu", "os_version_hint": "24.04",
            })
        self.assertEqual(extract.call_count, 2)
        self.assertTrue(out["configuration_fallback"])
        self.assertEqual(out["configuration"]["configuration_status"], "unknown")
        self.assertEqual(len(out["validation_errors"]), 2)

    def test_legacy_source_qemu_path_is_unprivileged_and_offline(self):
        verify = kernel_qemu.verify_script("v6.8.1", poc_cmd="/opt/cve/poc", poc_success="true")
        launch = kernel_qemu.launch_script()
        self.assertIn("runuser -u cvepoc", verify)
        self.assertIn("-nic none -nodefaults", launch)


if __name__ == "__main__":
    unittest.main()
