import base64
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from cve_pipeline import pipeline
from cve_pipeline.config import Config
from cve_pipeline.domain.generators import (
    configuration_check, configuration_qemu, distro_kernel, guest_configuration, qemu_vm,
)
from cve_pipeline.interfaces.server import Handler
from official_fixtures import official_bundle


ENVIRONMENT = {
    "status": "selected",
    "os_family": "ubuntu",
    "os_version": "22.04",
    "suite": "jammy",
    "architecture": "amd64",
    "vulnerable_constraints": {
        "package": "linux-image-generic",
        "meta_package_constraint": "<5.15.0.100.110",
        "running_kernel_package_constraint": "<5.15.0-100.110",
    },
    "build_target": {
        "status": "selected",
        "os_family": "ubuntu",
        "os_version": "22.04",
        "suite": "jammy",
        "architecture": "amd64",
        "kernel": {
            "meta_package": "linux-image-generic",
            "meta_package_version": "5.15.0.25.27",
            "concrete_package": "linux-image-5.15.0-25-generic",
            "running_kernel_release": "5.15.0-25-generic",
            "meta_package_constraint": "<5.15.0.100.110",
            "concrete_package_constraint": "<5.15.0-100.110",
        },
    },
}

KERNEL_SCRIPT = distro_kernel.build({
    "package": "linux-image-generic",
    "version_constraint": "<5.15.0.100.110",
    "concrete_kernel_constraint": "<5.15.0-100.110",
    "target_meta_version": "5.15.0.25.27",
    "target_kernel_release": "5.15.0-25-generic",
    "os_family": "ubuntu",
    "os_version": "22.04",
    "package_manager": "apt",
})


def embedded_guest(host_script: str) -> str:
    match = re.search(
        r"path: /usr/local/sbin/configure_[^\s]+.*?content: ([A-Za-z0-9+/=]+)",
        host_script,
        re.S,
    )
    if not match:
        raise AssertionError("embedded guest configuration script was not found")
    return base64.b64decode(match.group(1)).decode("utf-8")


def generated_environment_id(script: str) -> str:
    match = re.search(r"^ENVIRONMENT_ID='?([0-9a-f]{64})'?$", script, re.MULTILINE)
    if not match:
        raise AssertionError("generated environment identity was not found")
    return match.group(1)


class ConfigurationQemuTests(unittest.TestCase):
    def test_split_builder_and_checker_have_separate_responsibilities(self):
        configuration = {"configuration_status": "not_required", "manual_steps": []}
        builder = qemu_vm.build(
            ENVIRONMENT, "CVE-2026-12345", kernel_script=KERNEL_SCRIPT
        )
        checker = configuration_check.build(ENVIRONMENT, configuration, "CVE-2026-12345")
        guest = guest_configuration.build(ENVIRONMENT, configuration, "CVE-2026-12345")

        self.assertEqual(qemu_vm.filename("CVE-2026-12345"),
                         "build_qemu_CVE-2026-12345.sh")
        self.assertEqual(configuration_check.filename("CVE-2026-12345"),
                         "check_configuration_CVE-2026-12345.sh")
        self.assertIn("qemu-system-x86_64", builder)
        self.assertIn("SENTINEL='##CVE-VM-RESULT##'", builder)
        self.assertIn('echo "$SENTINEL READY exact_kernel=', builder)
        self.assertIn("RESULT: EXACT_KERNEL_VM_BUILT", builder)
        self.assertIn("full environment is not READY yet", builder)
        self.assertNotIn("PAYLOAD_B64", builder)
        self.assertNotIn("CONFIGURATION_STATUS", builder)
        self.assertNotIn("qemu-system-x86_64", checker)
        self.assertNotIn("qemu-img", checker)
        self.assertIn("PAYLOAD_B64", checker)
        self.assertIn('REMOTE_SCRIPT="/tmp/configure_CVE-2026-12345.sh"', checker)
        self.assertIn("sudo '$REMOTE_SCRIPT' apply", checker)
        self.assertIn("SENTINEL='##CVE-CONFIG-RESULT##'", checker)
        self.assertIn('echo "$SENTINEL READY', checker)
        self.assertIn("RESULT: VULNERABLE_REPRODUCTION_ENVIRONMENT_READY", checker)
        self.assertEqual(generated_environment_id(builder), generated_environment_id(checker))
        self.assertEqual(generated_environment_id(builder), generated_environment_id(guest))
        self.assertIn('ENVIRONMENT_FILE="$WORK_DIR/environment.identity"', builder)
        self.assertIn("printf '%s\\n' \"$ENVIRONMENT_ID\" > \"$ENVIRONMENT_FILE\"", builder)
        self.assertIn('VM_ENVIRONMENT_ID < "$ENVIRONMENT_FILE"', checker)
        self.assertIn("different environment selections", checker)

    def test_checker_rejects_payload_from_a_different_environment_selection(self):
        configuration = {"configuration_status": "not_required", "manual_steps": []}
        focal = dict(ENVIRONMENT, os_version="20.04", suite="focal")
        noble = dict(ENVIRONMENT, os_version="24.04", suite="noble")
        focal_guest = guest_configuration.build(focal, configuration, "CVE-2026-12345")

        with self.assertRaisesRegex(ValueError, "environment identity does not match"):
            configuration_check.build(
                noble, configuration, "CVE-2026-12345", guest_script=focal_guest,
            )

    def test_identity_changes_with_kernel_constraint(self):
        configuration = {"configuration_status": "not_required", "manual_steps": []}
        first = dict(
            ENVIRONMENT,
            vulnerable_constraints={"running_kernel_package_constraint": "<5.15.0-100.1"},
        )
        second = dict(
            ENVIRONMENT,
            vulnerable_constraints={"running_kernel_package_constraint": "<5.15.0-200.1"},
        )

        self.assertNotEqual(
            generated_environment_id(qemu_vm.build(
                first, "CVE-2026-12345", kernel_script=KERNEL_SCRIPT
            )),
            generated_environment_id(qemu_vm.build(
                second, "CVE-2026-12345", kernel_script=KERNEL_SCRIPT
            )),
        )

    def test_complete_report_continues_after_kernel_version_mismatch(self):
        environment = dict(
            ENVIRONMENT,
            vulnerable_constraints={
                "running_kernel_package_constraint": "<5.15.0-181.191"
            },
        )
        configuration = {
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_AF_RXRPC", "value": "enabled"}],
            "manual_steps": [],
        }
        guest = guest_configuration.build(
            environment, configuration, "CVE-2026-12345"
        )
        checker = configuration_check.build(
            environment, configuration, "CVE-2026-12345", guest_script=guest,
        )

        report = guest.split("report_configuration() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("report_fail kernel-package-version", report)
        self.assertIn("kernel-config:CONFIG_AF_RXRPC", report)
        self.assertLess(
            report.index("kernel-package-version"),
            report.index("kernel-config:CONFIG_AF_RXRPC"),
        )
        self.assertIn("CHECK SUMMARY", report)
        self.assertNotIn(" fail ", report)
        self.assertIn("report) report_configuration", guest)
        self.assertIn("sudo '$REMOTE_SCRIPT' apply", checker)
        self.assertIn("sudo '$REMOTE_SCRIPT' report", checker)
        self.assertIn("apply_rc=", checker)
        self.assertIn("report_rc=", checker)

    def test_rejects_inconsistent_ubuntu_version_and_suite(self):
        inconsistent = dict(ENVIRONMENT, os_version="24.04", suite="focal")
        configuration = {"configuration_status": "not_required", "manual_steps": []}
        with self.assertRaisesRegex(ValueError, "version and suite disagree"):
            qemu_vm.build(inconsistent, "CVE-2026-12345", kernel_script=KERNEL_SCRIPT)
        with self.assertRaisesRegex(ValueError, "version and suite disagree"):
            configuration_check.build(inconsistent, configuration, "CVE-2026-12345")

    def test_builds_disposable_configuration_check(self):
        configuration = {
            "configuration_status": "not_required",
            "summary": "The default guest is sufficient.",
            "manual_steps": [],
        }
        script = configuration_qemu.build(ENVIRONMENT, configuration, "CVE-2026-12345")
        guest = embedded_guest(script)

        self.assertIn("cloud-images.ubuntu.com/jammy/current", script)
        self.assertIn("sha256sum --check --status", script)
        self.assertIn("qemu-img create -q -f qcow2", script)
        self.assertIn('cloud-localds "$SEED"', script)
        self.assertIn("hostfwd=tcp:127.0.0.1:", script)
        self.assertIn("ssh_pwauth: false", script)
        self.assertIn("##CVE-CONFIG-RESULT## READY", script)
        self.assertIn("##CVE-CONFIG-RESULT## FAILED", script)
        self.assertIn("automatic guest configuration checks PASSED", script)
        self.assertIn("configuration readiness, not CVE exploitability", script)
        self.assertIn("CVE_ACTION=stop", script)
        self.assertIn("CVE_ACTION must be create, stop, status, or ssh-command", script)
        self.assertIn("-accel tcg,thread=single", script)
        self.assertIn("-accel kvm -cpu host", script)
        self.assertIn("verify_environment", guest)
        self.assertNotIn("grub-reboot", script)
        self.assertNotIn("linux-image-generic", script)
        self.assertNotIn("POC_", script)
        self.assertNotIn("meterpreter", script.casefold())

    def test_manual_prerequisite_reports_incomplete_not_ready(self):
        configuration = {
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_DEMO", "value": "enabled"}],
            "manual_steps": ["Ensure the test process has CAP_NET_ADMIN."],
        }
        script = configuration_qemu.build(ENVIRONMENT, configuration, "CVE-2026-12345")
        self.assertIn("MANUAL_REQUIRED=1", script)
        self.assertIn("##CVE-CONFIG-RESULT## MANUAL_REQUIRED", script)
        self.assertIn("automatic_checks_passed=true manual_validation=true", script)
        self.assertIn("exit 3", script)

    def test_rejects_unresolved_and_non_ubuntu_plans(self):
        with self.assertRaisesRegex(ValueError, "selected base environment"):
            configuration_qemu.build(
                {"status": "needs-input"}, {"configuration_status": "not_required"}, "CVE-X"
            )
        with self.assertRaisesRegex(ValueError, "supports Ubuntu only"):
            configuration_qemu.build(
                dict(ENVIRONMENT, os_family="debian"),
                {"configuration_status": "not_required"}, "CVE-X",
            )

    def test_unknown_plan_generates_diagnostic_wrapper_but_cannot_report_ready(self):
        script = configuration_qemu.build(
            ENVIRONMENT, {"configuration_status": "unknown"}, "CVE-2026-12345"
        )
        guest = embedded_guest(script)
        self.assertIn("##CVE-CONFIG-RESULT## UNCERTIFIED", script)
        self.assertIn("RESULT: UNCERTIFIED", script)
        self.assertIn("CONFIGURATION_STATUS='unknown'", script)
        self.assertIn("configuration evidence remains unknown", guest)
        self.assertIn("exit 4", script)

    def test_pipeline_option_writes_both_scripts(self):
        extracted = {
            "configuration_status": "not_required",
            "summary": "No extra configuration.",
            "evidence": [{
                "claim": "No extra setting",
                "source": "Primary CVE description",
                "excerpt": "No extra configuration is required.",
            }],
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "cve_pipeline.adapters.ollama.extract_configuration",
            return_value=(extracted, json.dumps(extracted)),
        ):
            bundle = official_bundle(description="No extra configuration is required.")
            result = pipeline.run_one(
                "CVE-2026-12345", Config(machines_dir=directory, register=False),
                os_hint="ubuntu", os_version_hint="22.04",
                source_bundle=bundle, qemu_check=True,
                qemu_memory_mb=2048, qemu_cpus=1, qemu_disk_size="12G", qemu_timeout_s=600,
            )
            self.assertTrue(os.path.isfile(result["script_path"]))
            self.assertTrue(os.path.isfile(result["qemu_script_path"]))
            self.assertTrue(os.path.isfile(result["configuration_check_script_path"]))
            self.assertEqual(result["workflow"], "vulnerable-qemu-vm+guest-configuration-check")
            self.assertIn("-m 2048 -smp 1", result["qemu_script"])
            self.assertIn("qemu-img resize -q \"$DISK\" '12G'", result["qemu_script"])
            self.assertIn('TIMEOUT_S="${CVE_QEMU_TIMEOUT:-600}"', result["qemu_script"])
            self.assertNotIn("PAYLOAD_B64", result["qemu_script"])
            self.assertNotIn("qemu-system-x86_64", result["configuration_check_script"])

    def test_pipeline_unknown_decision_still_writes_uncertified_qemu_wrapper(self):
        extracted = {
            "configuration_status": "unknown",
            "summary": "The official material does not state configuration prerequisites.",
            "evidence": [],
        }
        description = "The available official record has no configuration details."
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "cve_pipeline.adapters.ollama.extract_configuration",
            return_value=(extracted, json.dumps(extracted)),
        ):
            result = pipeline.run_one(
                "CVE-2026-12345", Config(machines_dir=directory, register=False),
                os_hint="ubuntu", os_version_hint="22.04",
                source_bundle=official_bundle(description=description), qemu_check=True,
            )
            self.assertTrue(os.path.isfile(result["qemu_script_path"]))
            self.assertTrue(os.path.isfile(result["configuration_check_script_path"]))
        self.assertEqual(result["configuration"]["configuration_status"], "unknown")
        self.assertIn("RESULT: UNCERTIFIED", result["configuration_check_script"])
        self.assertNotIn("Cannot launch a QEMU check", result["configuration_check_script"])

    def test_browser_generates_qemu_wrapper_only_when_requested(self):
        handler = object.__new__(Handler)
        request = {
            "environment": ENVIRONMENT,
            "configuration": {
                "configuration_status": "not_required",
                "evidence": [{
                    "claim": "No extra setting",
                    "source": "Primary CVE description",
                    "excerpt": "No extra configuration is required.",
                }],
            },
            "sources": official_bundle(),
            "description": "No extra configuration is required.",
            "cve": "CVE-2026-12345",
            "qemu_check": True,
        }
        out = handler._generate(request)
        self.assertEqual(out["filename"], "build_qemu_CVE-2026-12345.sh")
        self.assertEqual(out["check_filename"], "check_configuration_CVE-2026-12345.sh")
        self.assertEqual(out["guest_filename"], "configure_CVE-2026-12345.sh")
        self.assertIn("qemu-system-x86_64", out["script"])
        self.assertNotIn("qemu-system-x86_64", out["check_script"])
        self.assertNotIn("qemu-system-x86_64", out["guest_script"])


if __name__ == "__main__":
    unittest.main()
