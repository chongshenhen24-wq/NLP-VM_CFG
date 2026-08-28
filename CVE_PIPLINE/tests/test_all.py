import json
import os
import tempfile
import unittest
from unittest import mock

from cve_pipeline import pipeline
from cve_pipeline.adapters import ollama
from cve_pipeline.config import Config
from official_fixtures import official_bundle


CONFIGURATION = {
    "configuration_status": "required",
    "summary": "The affected crypto interface must be enabled.",
    "kernel_modules": [{"name": "algif_aead", "state": "loaded", "persistent": True,
                        "reason": "The vulnerable socket family is implemented by this module."}],
    "kernel_config": [{"symbol": "CONFIG_CRYPTO_USER_API_AEAD", "value": "m", "reason": "Required."}],
    "sysctls": [], "packages": [], "services": [], "file_settings": [], "manual_steps": [],
    "evidence": [{"claim": "AF_ALG AEAD is required", "source": "Primary CVE description",
                  "excerpt": "The algif_aead module must be loaded and "
                             "CONFIG_CRYPTO_USER_API_AEAD=m is required."}],
}


class EndToEndConfigurationTests(unittest.TestCase):
    def test_pipeline_separates_environment_and_configuration(self):
        cve = "CVE-2026-31431"
        bundle = {
            "cve": cve, "mode": "enrich",
            "description": "The algif_aead module must be loaded and "
                           "CONFIG_CRYPTO_USER_API_AEAD=m is required.", "errors": [],
            "sources": [
                {"name": "NVD", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-2026-31431",
                 "description": "The algif_aead module must be loaded and CONFIG_CRYPTO_USER_API_AEAD=m is required.",
                 "cpe_matches": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "6.8.0",
                }]},
                {"name": "Ubuntu Security Tracker", "url": "https://ubuntu.com/security/CVE-2026-31431",
                 "kernel_rows": [{"version": "24.04", "suite": "noble", "status": "Fixed",
                                  "fixed_version": "6.8.0-52.53"}],
                 "selected_kernel": {"version": "24.04", "suite": "noble",
                                     "status": "Fixed", "fixed_version": "6.8.0-52.53",
                                     "package": "linux-image-generic", "meta_fixed_version": "6.8.0-52.53",
                                     "vulnerable_candidate": {
                                         "meta_package": "linux-image-generic",
                                         "meta_package_version": "6.8.0-31.31",
                                         "concrete_package": "linux-image-6.8.0-31-generic",
                                         "running_kernel_release": "6.8.0-31-generic",
                                         "selection_policy": "explicit earlier official ABI",
                                         "publication_url": "https://launchpad.net/ubuntu/noble/amd64/linux-image-generic",
                                     }}},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            machine = os.path.join(directory, cve)
            os.makedirs(machine)
            with open(os.path.join(machine, "variables.pkrvars.hcl"), "w", encoding="utf-8") as handle:
                handle.write("scripts = [\n]\n")
            cfg = Config(machines_dir=directory, eval_log=os.path.join(directory, "eval.jsonl"))
            with mock.patch("cve_pipeline.adapters.sources.collect", return_value=bundle), \
                 mock.patch("cve_pipeline.adapters.ollama.extract_configuration",
                            return_value=(CONFIGURATION, json.dumps(CONFIGURATION))), \
                 mock.patch("cve_pipeline.adapters.ollama.extract") as old_extract, \
                 mock.patch("cve_pipeline.adapters.ollama.generate_bash") as model_generator:
                result = pipeline.run_one(cve, cfg)

            self.assertEqual(result["workflow"], "vulnerable-vm+guest-configuration")
            self.assertEqual(result["environment"]["selection_basis"], "ubuntu-security-tracker")
            self.assertEqual(result["configuration"]["configuration_status"], "required")
            self.assertTrue(result["registered"])
            self.assertTrue(os.path.isfile(result["environment_path"]))
            self.assertTrue(os.path.isfile(result["build_target_path"]))
            self.assertTrue(os.path.isfile(result["kernel_script_path"]))
            self.assertTrue(os.path.isfile(result["configuration_path"]))
            self.assertTrue(os.path.isfile(result["script_path"]))
            old_extract.assert_not_called()
            model_generator.assert_not_called()
            script = result["script"]
            self.assertIn("modprobe algif_aead", script)
            self.assertIn("verify_environment", script)
            self.assertNotIn("qemu-system", script)
            self.assertNotIn("grub-reboot", script)
            self.assertIn("EXPECTED_META_PACKAGE=linux-image-generic", script)
            self.assertNotIn("apt-get install", script)
            self.assertNotIn("grub-reboot", script)
            self.assertNotIn("POC_", script)
            self.assertIn("TARGET_META_VERSION='6.8.0-31.31'", result["kernel_script"])
            self.assertIn("TARGET_KERNEL_RELEASE='6.8.0-31-generic'", result["kernel_script"])

    def test_invalid_model_evidence_gets_one_bounded_repair(self):
        bad = {
            "configuration_status": "required",
            "services": [{"name": "invented", "state": "active", "enabled": False}],
            "evidence": [{"claim": "service", "source": "https://invented.invalid", "excerpt": "none"}],
        }
        good = {
            "configuration_status": "not_required",
            "summary": "No extra setting.",
            "evidence": [{"claim": "none", "source": "Primary CVE description",
                          "excerpt": "No extra configuration is required."}],
        }
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.ollama.extract_configuration",
                        side_effect=[(bad, json.dumps(bad)), (good, json.dumps(good))]) as extract:
            description = "No extra configuration is required."
            result = pipeline.run_one(
                "CVE-2026-12345",
                Config(machines_dir=directory, register=False),
                description="analyst note",
                source_bundle=official_bundle(description=description),
            )
        self.assertEqual(extract.call_count, 2)
        repair_context = extract.call_args_list[1].args[3]
        self.assertIn("no directly grounded prerequisite", repair_context)
        self.assertIn("https://invented.invalid", repair_context)
        self.assertIn("rejected JSON below is NOT source evidence", repair_context)
        self.assertEqual(len(result["extract_raw_paths"]), 2)
        self.assertEqual(len(result["extraction_validation_errors"]), 1)
        self.assertEqual(result["configuration"]["configuration_status"], "not_required")

    def test_two_invalid_attempts_write_a_fail_closed_unknown_artifact(self):
        bad = {
            "configuration_status": "unknown", "summary": "No requirements found.",
            "kernel_modules": [], "kernel_config": [], "kernel_config_alternatives": [],
            "sysctls": [], "packages": [], "services": [], "file_settings": [],
            "manual_steps": [], "evidence": [],
        }
        description = "Requirements: Kernel configuration: CONFIG_DEMO=y"
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.ollama.extract_configuration",
                        return_value=(bad, json.dumps(bad))) as extract:
            result = pipeline.run_one(
                "CVE-2026-12345", Config(machines_dir=directory, register=False),
                source_bundle=official_bundle(description=description),
            )
            self.assertEqual(extract.call_count, 2)
            self.assertTrue(result["configuration_fallback"])
            self.assertEqual(result["configuration"]["configuration_status"], "unknown")
            self.assertEqual(len(result["extraction_validation_errors"]), 2)
            self.assertTrue(os.path.isfile(result["configuration_path"]))
            self.assertTrue(os.path.isfile(result["script_path"]))
            self.assertIn("configuration evidence is insufficient", result["script"])

    def test_invalid_json_gets_the_same_bounded_repair(self):
        raw = '{"configuration_status":"unknown"}{"extra":true}'
        good = {
            "configuration_status": "unknown", "summary": "Insufficient evidence.",
            "kernel_modules": [], "kernel_config": [], "sysctls": [], "packages": [],
            "services": [], "file_settings": [], "manual_steps": [], "evidence": [],
        }
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.ollama.extract_configuration",
                        side_effect=[ollama.InvalidModelJSON("extra JSON data", raw),
                                     (good, json.dumps(good))]) as extract:
            result = pipeline.run_one(
                "CVE-2026-12345", Config(machines_dir=directory, register=False),
                source_bundle=official_bundle(
                    description="The available description has no configuration details."
                ),
            )
            with open(result["extract_raw_paths"][0], encoding="utf-8") as handle:
                retained_raw = handle.read()
        self.assertEqual(extract.call_count, 2)
        self.assertEqual(result["configuration"]["configuration_status"], "unknown")
        self.assertEqual(retained_raw, raw)
        self.assertIn(raw, extract.call_args_list[1].args[3])


if __name__ == "__main__":
    unittest.main()
