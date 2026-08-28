import unittest

from cve_pipeline.domain import vulnerable_target
from cve_pipeline.domain.generators import (
    distro_kernel, guest_configuration, packer_handoff, qemu_vm,
)
from official_fixtures import official_bundle


class VulnerableTargetTests(unittest.TestCase):
    def _environment(self):
        return {
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
        }

    def test_official_candidate_becomes_exact_infrastructure_target(self):
        environment = self._environment()
        target = vulnerable_target.select(official_bundle(), environment)
        self.assertEqual(target["status"], "selected")
        self.assertEqual(target["kernel"]["meta_package_version"], "5.15.0.25.27")
        self.assertEqual(target["kernel"]["running_kernel_release"], "5.15.0-25-generic")
        self.assertIn("launchpad.net", target["evidence_urls"][-1])

    def test_missing_concrete_publication_stops_kernel_target(self):
        bundle = official_bundle()
        ubuntu = next(
            item for item in bundle["sources"]
            if item["name"] == "Ubuntu Security Tracker"
        )
        del ubuntu["selected_kernel"]["vulnerable_candidate"]
        target = vulnerable_target.select(bundle, self._environment())
        self.assertEqual(target["status"], "needs-input")
        self.assertIn("concrete vulnerable kernel publication", target["reason"])

    def test_candidate_cannot_predate_machine_readable_introduction(self):
        bundle = official_bundle()
        cna = next(
            item for item in bundle["sources"]
            if item["name"] == "CVE.org / CNA record"
        )
        cna["affected"] = [{
            "vendor": "Linux", "product": "Linux",
            "versions": [{"version": "6.0", "status": "affected"}],
        }]
        target = vulnerable_target.select(bundle, self._environment())
        self.assertEqual(target["status"], "needs-input")
        self.assertIn("predates", target["reason"])

    def test_candidate_publication_must_be_official_launchpad_https(self):
        bundle = official_bundle()
        ubuntu = next(
            item for item in bundle["sources"]
            if item["name"] == "Ubuntu Security Tracker"
        )
        ubuntu["selected_kernel"]["vulnerable_candidate"]["publication_url"] = (
            "https://example.invalid/linux-image-generic"
        )
        target = vulnerable_target.select(bundle, self._environment())
        self.assertEqual(target["status"], "needs-input")
        self.assertIn("internally inconsistent", target["reason"])

    def test_structured_cna_versions_are_labelled_fallback_not_cpe(self):
        bundle = official_bundle()
        nvd = next(item for item in bundle["sources"] if item["name"] == "NVD")
        nvd["cpe_matches"] = []
        environment = self._environment()
        target = vulnerable_target.select(bundle, environment)
        evidence = target["machine_readable_version_evidence"]
        self.assertEqual(target["status"], "selected")
        self.assertEqual(evidence["status"], "structured-version-fallback")
        self.assertEqual(evidence["nvd_cpe_status"], "unavailable")
        self.assertTrue(evidence["fallback_used"])
        self.assertNotIn("NVD", evidence["source_names"])

    def test_prose_and_tracker_without_machine_range_stop_selection(self):
        bundle = official_bundle()
        nvd = next(item for item in bundle["sources"] if item["name"] == "NVD")
        cna = next(
            item for item in bundle["sources"]
            if item["name"] == "CVE.org / CNA record"
        )
        nvd["cpe_matches"] = []
        cna.pop("affected")
        target = vulnerable_target.select(bundle, self._environment())
        self.assertEqual(target["status"], "needs-input")
        self.assertIn("Neither NVD CPE", target["reason"])

    def test_exact_target_is_pinned_and_verified_across_all_scripts(self):
        environment = self._environment()
        target = vulnerable_target.select(official_bundle(), environment)
        environment["build_target"] = target
        kernel = target["kernel"]
        provisioner = distro_kernel.build({
            "package": kernel["meta_package"],
            "version_constraint": kernel["meta_package_constraint"],
            "concrete_kernel_constraint": kernel["concrete_package_constraint"],
            "target_meta_version": kernel["meta_package_version"],
            "target_kernel_release": kernel["running_kernel_release"],
            "os_family": target["os_family"],
            "os_version": target["os_version"],
            "package_manager": "apt",
        })
        guest = guest_configuration.build(
            environment, {"configuration_status": "not_required"}, "CVE-2026-12345"
        )
        builder = qemu_vm.build(
            environment, "CVE-2026-12345", kernel_script=provisioner
        )
        self.assertIn("TARGET_META_VERSION='5.15.0.25.27'", provisioner)
        self.assertIn("TARGET_KERNEL_RELEASE='5.15.0-25-generic'", provisioner)
        self.assertIn("EXPECTED_KERNEL_RELEASE=5.15.0-25-generic", guest)
        self.assertIn("EXPECTED_META_PACKAGE_VERSION=5.15.0.25.27", guest)
        self.assertIn("EXPECTED_KERNEL_RELEASE='5.15.0-25-generic'", builder)
        self.assertNotIn("meterpreter", (provisioner + guest + builder).lower())

    def test_qemu_rejects_kernel_payload_for_another_target(self):
        environment = self._environment()
        environment["build_target"] = vulnerable_target.select(
            official_bundle(), environment
        )
        wrong = distro_kernel.build({
            "package": "linux-image-generic",
            "version_constraint": "<5.15.0.100.110",
            "concrete_kernel_constraint": "<5.15.0-100.110",
            "target_meta_version": "5.15.0.26.28",
            "target_kernel_release": "5.15.0-26-generic",
            "os_family": "ubuntu",
            "os_version": "22.04",
            "package_manager": "apt",
        })
        with self.assertRaisesRegex(ValueError, "does not match"):
            qemu_vm.build(environment, "CVE-2026-12345", kernel_script=wrong)

    def test_packer_handoff_preserves_reboot_before_configuration(self):
        environment = self._environment()
        environment["build_target"] = vulnerable_target.select(
            official_bundle(), environment
        )
        fragment = packer_handoff.build(
            environment, "CVE-2026-12345",
            "provision_kernel_CVE-2026-12345.sh",
            "configure_CVE-2026-12345.sh",
        )
        self.assertIn("CVE_AUTO_REBOOT=1", fragment)
        self.assertIn("expect_disconnect = true", fragment)
        self.assertIn("cve-kernel-reproduction verify", fragment)
        self.assertIn("configure_CVE-2026-12345.sh", fragment)
        self.assertLess(
            fragment.index("provision_kernel_CVE-2026-12345.sh"),
            fragment.index("configure_CVE-2026-12345.sh"),
        )
        self.assertIn("{{ .Path }}", fragment)


if __name__ == "__main__":
    unittest.main()
