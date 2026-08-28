import json
import os
import tempfile
import unittest
from unittest import mock

from cve_pipeline import kernel_pipeline, pipeline
from cve_pipeline.adapters import sources
from cve_pipeline.config import Config
from cve_pipeline.domain import generators, kernel, ubuntu_kernel
from cve_pipeline.domain.generators import kernel_qemu
from cve_pipeline.domain.spec import normalize
from cve_pipeline.kernel_repro import emit_kernel_scripts
from official_fixtures import official_bundle


NVD_SOURCE = {
    "name": "NVD", "url": "https://example.test/nvd", "description": "description",
    "cpe_matches": [{"criteria": "cpe:2.3:a:vendor:demo:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "2.0"}],
}


class SourceTests(unittest.TestCase):
    def test_ubuntu_kernel_rows_select_supported_lts_boundaries(self):
        new_rows = sources._ubuntu_kernel_rows(
            "linux 26.04 LTS resolute Not affected 24.04 LTS noble Fixed 6.8.0-117.117 "
            "22.04 LTS jammy Fixed 5.15.0-179.189 20.04 LTS focal Fixed 5.4.0-230.250 "
            "linux-hwe 26.04 LTS resolute Not in release"
        )
        old_rows = sources._ubuntu_kernel_rows(
            "linux 26.04 LTS resolute Not affected 24.04 LTS noble Not affected "
            "22.04 LTS jammy Not affected 20.04 LTS focal Fixed 5.4.0-105.119 "
            "linux-aws 26.04 LTS resolute Not affected"
        )
        self.assertEqual(new_rows[0]["version"], "24.04")
        self.assertEqual(new_rows[0]["fixed_version"], "6.8.0-117.117")
        self.assertEqual(old_rows[-1]["version"], "20.04")
        self.assertEqual(old_rows[-1]["fixed_version"], "5.4.0-105.119")

    def test_ubuntu_kernel_rows_support_old_table_and_impish(self):
        rows = sources._ubuntu_kernel_rows(
            "linux 24.04 LTS noble Not affected 22.04 LTS jammy Not affected "
            "21.10 impish Fixed 5.13.0-35.40 20.04 LTS focal Not affected "
            "linux-aws 24.04 LTS noble Not affected"
        )
        fixed = next(row for row in rows if row["status"] == "Fixed")
        self.assertEqual(fixed["suite"], "impish")
        self.assertEqual(fixed["fixed_version"], "5.13.0-35.40")

    def test_ubuntu_git_rows_parse_released_main_kernel(self):
        rows = sources._ubuntu_git_rows(
            "noble_linux: not-affected (6.5.0-9.9)\n"
            "focal_linux: released (5.4.0-74.83)\n"
            "impish_linux: not-affected (5.11.0-18.19+21.10.1)\n"
        )
        fixed = next(row for row in rows if row["status"] == "Fixed")
        self.assertEqual(fixed["suite"], "focal")
        self.assertEqual(fixed["fixed_version"], "5.4.0-74.83")

    def test_launchpad_resolves_meta_boundary_by_kernel_abi(self):
        page = (
            '<a href="/ubuntu/focal/amd64/linux-image-generic/5.4.0.104.108">old</a>'
            '<a href="/ubuntu/focal/amd64/linux-image-generic/5.4.0.105.109">fixed</a>'
        )
        api = {"entries": [{
            "binary_package_name": "linux-image-generic",
            "binary_package_version": "5.4.0.104.108",
            "status": "Published", "pocket": "Release",
        }]}
        with mock.patch("cve_pipeline.adapters.sources._get_text", return_value=page), \
             mock.patch("cve_pipeline.adapters.sources._get_json", return_value=api):
            version, _ = sources._launchpad_meta_fixed("focal", "5.4.0-105.119", 1)
        self.assertEqual(version, "5.4.0.105.109")

    def test_launchpad_selects_one_exact_earlier_kernel_publication(self):
        page = (
            '<a href="/ubuntu/noble/amd64/linux-image-generic/6.8.0-31.31">release</a>'
            '<a href="/ubuntu/noble/amd64/linux-image-generic/6.8.0-120.120">old</a>'
            '<a href="/ubuntu/noble/amd64/linux-image-generic/6.8.0-124.124">fixed</a>'
            '<a href="/ubuntu/noble/amd64/linux-image-generic/6.8.0-136.136">current</a>'
        )
        def active(url, _timeout):
            pocket = next(value for value in ("Release", "Updates", "Security") if f"pocket={value}" in url)
            versions = {
                "Release": ["6.8.0-31.31"],
                "Updates": ["6.8.0-120.120"],
                "Security": ["6.8.0-136.136"],
            }[pocket]
            return {"entries": [{
                "binary_package_name": "linux-image-generic",
                "binary_package_version": version,
                "status": "Published", "pocket": pocket,
            } for version in versions]}
        with mock.patch("cve_pipeline.adapters.sources._get_text", return_value=page), \
             mock.patch("cve_pipeline.adapters.sources._get_json", side_effect=active):
            fixed, candidate, _ = sources._launchpad_kernel_target(
                "noble", "6.8.0-124.124", 1
            )
        self.assertEqual(fixed, "6.8.0-124.124")
        self.assertEqual(candidate["meta_package_version"], "6.8.0-120.120")
        self.assertEqual(candidate["running_kernel_release"], "6.8.0-120-generic")
        self.assertEqual(candidate["concrete_package"], "linux-image-6.8.0-120-generic")

    def test_authoritative_kernel_reconciliation_repairs_nlp_output(self):
        bundle = {"sources": [{
            "name": "Ubuntu Security Tracker",
            "url": "https://ubuntu.test/cve",
            "selection_policy": "newest affected supported Ubuntu LTS cloud image",
            "selected_kernel": {
                "version": "20.04", "suite": "focal",
                "fixed_version": "5.4.0-105.119",
                "package": "linux-image-generic",
                "meta_fixed_version": "5.4.0.105.109",
                "meta_url": "https://launchpad.test/focal",
            },
        }]}
        truth = {"products": [{"part": "o", "product": "linux_kernel"}]}
        bad_nlp = normalize({
            "package": "linux", "os_family": "ubuntu", "os_version": "all",
            "version_constraint": "<5.10.254",
            "setup_commands": [{"command": "unsafe"}],
        }, "ubuntu")
        resolved, evidence = ubuntu_kernel.reconcile(bad_nlp, bundle, truth)
        self.assertEqual(resolved["package"], "linux-image-generic")
        self.assertEqual(resolved["os_version"], "20.04")
        self.assertEqual(resolved["version_constraint"], "<5.4.0.105.109")
        self.assertEqual(resolved["concrete_kernel_constraint"], "<5.4.0-105.119")
        self.assertEqual(resolved["setup_commands"], [])
        self.assertIn("Ubuntu 20.04 (focal)", resolved["notes"])
        self.assertEqual(evidence["suite"], "focal")

    def test_canonical_ubuntu_cpe_is_treated_as_kernel_with_tracker_rows(self):
        bundle = {"sources": [{
            "name": "Ubuntu Security Tracker",
            "url": "https://ubuntu.test/cve",
            "kernel_rows": [{"version": "20.04", "suite": "focal", "status": "Fixed",
                             "fixed_version": "5.4.0-72.80"}],
            "selected_kernel": {
                "version": "20.04", "suite": "focal",
                "fixed_version": "5.4.0-72.80",
                "package": "linux-image-generic",
                "meta_fixed_version": "5.4.0.72.75",
            },
        }]}
        truth = {"products": [{
            "part": "o", "vendor": "canonical", "product": "ubuntu_linux",
        }]}
        resolved, _ = ubuntu_kernel.reconcile(normalize({}, "ubuntu"), bundle, truth)
        self.assertEqual(resolved["version_constraint"], "<5.4.0.72.75")

    def test_arm64_64k_issue_is_rejected_by_x86_generator(self):
        bundle = {
            "description": "On ARM64 the 64KB base page size triggers the issue.",
            "sources": [{
                "name": "Ubuntu Security Tracker",
                "kernel_rows": [{"version": "24.04", "suite": "noble",
                                 "status": "Fixed", "fixed_version": "6.8.0-48.48"}],
                "selected_kernel": {
                    "version": "24.04", "suite": "noble",
                    "fixed_version": "6.8.0-48.48",
                    "package": "linux-image-generic",
                    "meta_fixed_version": "6.8.0-48.48",
                },
            }],
        }
        truth = {"products": [{"part": "o", "product": "linux_kernel"}]}
        with self.assertRaisesRegex(ValueError, "ARM64 with 64 KB"):
            ubuntu_kernel.reconcile(normalize({}, "ubuntu"), bundle, truth)

    def test_ubuntu_tracker_excerpt_starts_at_package_status(self):
        page = "navigation boilerplate " * 200 + (
            "Package Ubuntu Release Status linux 24.04 LTS noble Fixed 6.8.0-117.117"
        )
        with mock.patch("cve_pipeline.adapters.sources._get_text", return_value=page):
            source = sources._tracker_source(
                "Ubuntu Security Tracker", "https://example.test/ubuntu", 1
            )
        self.assertTrue(source["excerpt"].startswith("Package Ubuntu Release Status"))
        self.assertIn("6.8.0-117.117", source["excerpt"])

    def test_prompt_prioritizes_distro_trackers(self):
        bundle = {"sources": [
            {"name": "NVD", "url": "https://example.test/nvd", "description": "nvd"},
            {"name": "Ubuntu Security Tracker", "url": "https://example.test/ubuntu",
             "excerpt": "ubuntu status"},
        ]}
        evidence = sources.prompt_evidence(bundle)
        self.assertLess(evidence.index("Ubuntu Security Tracker"), evidence.index("NVD"))

    def test_configuration_prompt_preserves_reference_and_omits_machine_arrays(self):
        bundle = {
            "sources": [{
                "name": "NVD", "url": "https://example.test/nvd", "description": "description",
                "cpe_matches": [{"criteria": "cpe:2.3:o:example:large:" + "x" * 4000}],
            }],
            "reference_evidence": [{
                "url": "https://example.test/advisory",
                "excerpt": "CONFIG_DEMO must be enabled for the affected component.",
            }],
        }
        evidence = sources.prompt_evidence(bundle, max_chars=800)
        self.assertIn("CONFIG_DEMO must be enabled", evidence)
        self.assertNotIn("cpe:2.3", evidence)
        machine_evidence = sources.prompt_evidence(
            bundle, max_chars=6000, include_machine_data=True
        )
        self.assertIn("cpe:2.3", machine_evidence)

    def test_unexpected_source_failure_is_retained(self):
        with mock.patch("cve_pipeline.adapters.sources._nvd_source", side_effect=RuntimeError("bad schema")):
            bundle = sources.collect("CVE-2026-12345", mode="nvd")
        self.assertEqual(bundle["errors"][0]["source"], "NVD")

    def test_nvd_ground_truth_reuses_collected_evidence(self):
        truth = sources.nvd_ground_truth({"sources": [NVD_SOURCE]})
        self.assertEqual(truth["version_ranges"], ["<2.0"])
        self.assertEqual(truth["products"][0]["product"], "demo")

    def test_osv_record_rehydrates_ranges(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1"}]}]}]
        self.assertEqual(sources.osv_record({"sources": [{"name": "OSV", "affected": affected}]}),
                         {"affected": affected})

    def test_apt_range_is_exact_and_fail_closed(self):
        script = generators.build(normalize({"package": "demo", "package_manager": "apt",
                                             "version_constraint": ">=1.0,<2.0", "os_family": "ubuntu"}))
        self.assertIn("apt-cache madison demo", script)
        self.assertIn('demo="$_CVE_APT_VERSION"', script)
        self.assertIn("exit 42", script)
        self.assertNotIn("apt-get install -y -q demo\n", script)

    def test_sources_survive_model_failure(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.ollama.extract_configuration", side_effect=RuntimeError("offline")):
            cfg = Config(machines_dir=directory, register=False)
            with self.assertRaises(RuntimeError):
                pipeline.run_one(
                    "CVE-2026-12345", cfg,
                    source_bundle=official_bundle(description="manual advisory"),
                )
            self.assertTrue(os.path.isfile(os.path.join(directory, "CVE-2026-12345", "sources.json")))

    def test_saved_source_bundle_replays_without_live_collection(self):
        cve = "CVE-2026-12345"
        bundle = official_bundle(cve=cve, description="No extra configuration is required.")
        extracted = {
            "configuration_status": "not_required", "summary": "No extra configuration.",
            "kernel_modules": [], "kernel_config": [], "sysctls": [], "packages": [],
            "services": [], "file_settings": [], "manual_steps": [],
            "evidence": [{"claim": "No extra setting", "source": "Primary CVE description",
                          "excerpt": "No extra configuration is required."}],
        }
        with tempfile.TemporaryDirectory() as directory:
            bundle_dir = os.path.join(directory, "bundles", cve)
            os.makedirs(bundle_dir)
            bundle_path = os.path.join(bundle_dir, "sources.json")
            with open(bundle_path, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle)
            cfg = Config(
                machines_dir=os.path.join(directory, "output"),
                source_bundle_dir=os.path.join(directory, "bundles"), register=False,
            )
            with mock.patch("cve_pipeline.adapters.sources.collect") as collect, \
                 mock.patch("cve_pipeline.adapters.ollama.extract_configuration",
                            return_value=(extracted, json.dumps(extracted))):
                result = pipeline.run_one(cve, cfg)
        collect.assert_not_called()
        self.assertEqual(result["configuration"]["configuration_status"], "not_required")
        self.assertEqual(len(result["sources"]["replayed_from"]["sha256"]), 64)

    def test_saved_source_bundle_rejects_wrong_cve(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sources.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"cve": "CVE-2026-99999", "sources": []}, handle)
            with self.assertRaisesRegex(ValueError, "not CVE-2026-12345"):
                sources.load_bundle(path, "CVE-2026-12345")

    def test_kernel_candidate_cannot_predate_introduction(self):
        branch = kernel.branches_from_ranges([{"introduced": "6.18.22", "fixed": "6.18.22"}])[0]
        self.assertIsNone(branch["vulnerable_ref"])
        self.assertIn("predates introduction", branch["note"])

    def test_kernel_verifier_requires_poc(self):
        script = kernel_qemu.verify_script("v6.18.21")
        self.assertIn("FAIL=$((FAIL+1))", script)

    def test_poc_is_executed_at_guest_path(self):
        with tempfile.TemporaryDirectory() as directory:
            poc = os.path.join(directory, "host-poc")
            with open(poc, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\n")
            written = emit_kernel_scripts("CVE-2026-12345", "v6.18.21", directory,
                                          poc_path=poc, poc_success="true")
            with open(written["verify_kernel.sh"], encoding="utf-8") as handle:
                verify = handle.read()
            self.assertIn("/opt/cve/poc", verify)
            self.assertIn("runuser -u cvepoc", verify)
            self.assertNotIn(poc, verify)

    def test_kernel_pipeline_uses_one_bundle_and_writes_resolution(self):
        bundle = {"cve": "CVE-2026-12345", "mode": "enrich", "description": "kernel issue",
                  "errors": [], "sources": [NVD_SOURCE, {"name": "OSV", "url": "https://example.test/osv",
                  "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                      {"introduced": "6.18.1"}, {"fixed": "6.18.3"}]}]}]}]}
        extracted = {"subsystem": "demo", "introduced_version": "6.18.1",
                     "introduced_commit": None, "fixes": [{"version": "6.18.3", "commit": None}],
                     "notes": ""}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.sources.collect", return_value=bundle) as collect, \
             mock.patch("cve_pipeline.adapters.ollama._generate", return_value=json.dumps(extracted)):
            result = kernel_pipeline.resolve_kernel("CVE-2026-12345", Config(machines_dir=directory), "latest")
            self.assertEqual(result["vulnerable_ref"], "v6.18.2")
            self.assertEqual(collect.call_count, 1)
            self.assertTrue(os.path.isfile(result["sources_path"]))


    def test_reproduce_kernel_bundles_poc_and_emits_scripts(self):
        resolved = {"cve": "CVE-2026-12345", "vulnerable_ref": "v6.18.2",
                    "extracted": {"subsystem": "demo"}, "branches": [],
                    "chosen_branch": None, "chosen_reason": "test",
                    "sources_path": "sources.json", "resolution_path": "resolution.json"}
        with tempfile.TemporaryDirectory() as directory:
            poc = os.path.join(directory, "input-poc")
            with open(poc, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\ntouch /root/BUG_REACHED\n")
            cfg = Config(machines_dir=os.path.join(directory, "machines"))
            with mock.patch("cve_pipeline.kernel_pipeline.resolve_kernel", return_value=resolved):
                result = kernel_pipeline.reproduce_kernel(
                    "CVE-2026-12345", cfg, "latest", poc,
                    "test -f /root/BUG_REACHED", config_options=["CONFIG_DEMO"])
            self.assertFalse(result["executed"])
            self.assertTrue(os.path.isfile(result["poc_path"]))
            self.assertEqual(set(result["scripts"]), {"build_kernel.sh", "build_rootfs.sh",
                                                       "verify_kernel.sh", "run_qemu.sh"})
            with open(result["scripts"]["verify_kernel.sh"], encoding="utf-8") as handle:
                self.assertIn("/opt/cve/poc", handle.read())

    def test_model_generator_cannot_bypass_apt_range_safety(self):
        configuration = {"configuration_status": "not_required", "summary": "No extra configuration.",
                         "evidence": [{"claim": "No extra setting", "source": "Primary CVE description",
                                       "excerpt": "No extra configuration is required."}]}
        bundle = official_bundle(description="No extra configuration is required.")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.sources.collect", return_value=bundle), \
             mock.patch("cve_pipeline.adapters.ollama.extract_configuration", return_value=(configuration, "{}")), \
             mock.patch("cve_pipeline.adapters.ollama.generate_bash") as generate:
            result = pipeline.run_one("CVE-2026-12345", Config(machines_dir=directory, generator="model"))
            self.assertIn("deterministic", result["generator_used"])
            self.assertNotIn("apt-get install -y -q demo", result["script"])
            generate.assert_not_called()

    def test_official_source_policy_requires_two_recognized_https_hosts(self):
        one = {
            "sources": [{
                "name": "NVD",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-2026-12345",
                "description": "official evidence",
            }],
            "errors": [{"source": "Ubuntu Security Tracker", "error": "timeout"}],
        }
        coverage = sources.official_source_coverage(one)
        self.assertEqual(coverage["count"], 1)
        self.assertFalse(coverage["satisfied"])
        with self.assertRaisesRegex(ValueError, "at least 2 recognized official sources"):
            sources.require_multiple_official_sources(one)

    def test_official_source_policy_rejects_spoofed_name_and_accepts_real_bundle(self):
        spoofed = {
            "sources": [{"name": "NVD", "url": "https://example.test/nvd",
                         "description": "not official"}],
            "errors": [],
            "official_source_policy": {"count": 99, "satisfied": True},
        }
        self.assertEqual(sources.official_source_coverage(spoofed)["count"], 0)
        coverage = sources.require_multiple_official_sources(official_bundle())
        self.assertEqual(coverage["count"], 3)
        self.assertTrue(coverage["satisfied"])

    def test_manual_bundle_cannot_satisfy_generation_policy(self):
        bundle = sources.manual_bundle("CVE-2026-12345", "manual text")
        with self.assertRaisesRegex(ValueError, "Manual/offline descriptions"):
            sources.require_multiple_official_sources(bundle)

    def test_in_memory_bundle_must_match_requested_cve(self):
        bundle = official_bundle(cve="CVE-2026-12345")
        with self.assertRaisesRegex(ValueError, "not CVE-2026-54321"):
            sources.validate_bundle_identity(bundle, "CVE-2026-54321")

if __name__ == "__main__":
    unittest.main()

