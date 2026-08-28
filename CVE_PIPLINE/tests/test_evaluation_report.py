import csv
import json
import os
import tempfile
import unittest
from unittest import mock

from cve_pipeline import pipeline
from cve_pipeline.config import Config
from cve_pipeline.evaluation import report
from official_fixtures import official_bundle


def _write_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle)


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


class EvaluationReportTests(unittest.TestCase):
    def _machine(self, root, cve, *, configuration="not_required", selected=True):
        directory = os.path.join(root, cve)
        os.makedirs(directory)
        _write_json(os.path.join(directory, "sources.json"), {
            "official_source_policy": {"count": 3, "minimum_required": 2},
            "errors": [],
        })
        _write_json(os.path.join(directory, "environment.json"), {
            "status": "selected" if selected else "needs-input",
            "os_family": "ubuntu", "os_version": "22.04", "suite": "jammy",
            "architecture": "amd64",
            "machine_readable_version_evidence": {
                "status": "nvd-cpe", "nvd_cpe_count": 1,
            },
        })
        if selected:
            _write_json(os.path.join(directory, "build-target.json"), {
                "status": "selected",
                "kernel": {
                    "meta_package": "linux-image-generic",
                    "meta_package_version": "5.15.0.25.27",
                    "running_kernel_release": "5.15.0-25-generic",
                    "concrete_package_constraint": "<5.15.0-100.110",
                },
            })
            open(os.path.join(directory, f"build_qemu_{cve}.sh"), "w").close()
            open(os.path.join(directory, f"check_configuration_{cve}.sh"), "w").close()
        _write_json(os.path.join(directory, "configuration.json"), {
            "configuration_status": configuration,
        })

    def test_report_keeps_denominators_and_false_ready_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            machines = os.path.join(directory, "machines")
            os.makedirs(machines)
            self._machine(machines, "CVE-2026-10001")
            self._machine(machines, "CVE-2026-10002")
            self._machine(machines, "CVE-2026-10003", selected=False)
            runtime_one = os.path.join(directory, "runtime-1.csv")
            runtime_two = os.path.join(directory, "runtime-2.csv")
            _write_csv(runtime_one, [
                {"cve": "CVE-2026-10001", "repetition": "1", "exact_kernel_vm": "1",
                 "environment_ready": "1", "result": "READY"},
                {"cve": "CVE-2026-10002", "repetition": "1", "exact_kernel_vm": "1",
                 "environment_ready": "1", "result": "READY"},
            ])
            _write_csv(runtime_two, [
                {"cve": "CVE-2026-10001", "repetition": "2", "exact_kernel_vm": "1",
                 "environment_ready": "1", "result": "READY"},
            ])
            truth = os.path.join(directory, "truth.csv")
            _write_csv(truth, [
                {"cve": "CVE-2026-10001", "actual_default_ready": "yes"},
                {"cve": "CVE-2026-10002", "actual_default_ready": "no"},
                {"cve": "CVE-2026-10003", "actual_default_ready": "unknown"},
            ])
            validation = os.path.join(directory, "validation.csv")
            _write_csv(validation, [
                {"cve": "CVE-2026-10001", "poc_attempted": "yes",
                 "poc_compatible": "yes", "poc_result": "confirmed"},
            ])
            rows, metrics = report.build_evaluation(
                machines,
                runtime_csv=[runtime_one, runtime_two],
                ground_truth_csv=truth,
                manual_validation_csv=validation,
            )

        self.assertEqual(len(rows), 4)
        self.assertEqual(metrics["dataset_cves"], 3)
        self.assertEqual(metrics["exact_targets_selected"], 2)
        self.assertEqual(metrics["vm_generation_success_rate_percent"], 100.0)
        self.assertEqual(metrics["end_to_end_success_rate_all_cves_percent"], 66.67)
        self.assertEqual(metrics["default_readiness_confusion_matrix"]["tp"], 1)
        self.assertEqual(metrics["default_readiness_confusion_matrix"]["fp"], 1)
        self.assertEqual(metrics["default_readiness_accuracy_percent"], 50.0)
        self.assertEqual(metrics["exploit_confirmation_rate_percent"], 100.0)
        self.assertEqual(metrics["outcome_repeatability_rate_percent"], 100.0)

    def test_batch_can_generate_split_qemu_evaluation_files(self):
        configuration = {
            "configuration_status": "not_required",
            "summary": "No extra configuration is required.",
            "evidence": [{
                "claim": "no extra configuration",
                "source": "Primary CVE description",
                "excerpt": "No extra configuration is required.",
            }],
        }
        cve = "CVE-2026-12345"
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.sources.collect",
                        return_value=official_bundle(cve=cve)), \
             mock.patch("cve_pipeline.adapters.ollama.extract_configuration",
                        return_value=(configuration, json.dumps(configuration))):
            results = pipeline.run_batch(
                [cve], Config(machines_dir=directory, register=False),
                qemu_check=True, qemu_memory_mb=2048,
            )

            self.assertNotIn("error", results[0])
            self.assertTrue(os.path.isfile(results[0]["qemu_script_path"]))
            self.assertTrue(os.path.isfile(results[0]["configuration_check_script_path"]))
            self.assertIn("-m 2048", results[0]["qemu_script"])

    def test_batch_logs_failures_instead_of_losing_them(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("cve_pipeline.adapters.sources.collect",
                        side_effect=RuntimeError("source timeout")):
            log = os.path.join(directory, "logs", "generation.jsonl")
            results = pipeline.run_batch(
                ["CVE-2026-12345"],
                Config(machines_dir=directory, register=False, eval_log=log),
            )
            with open(log, encoding="utf-8") as handle:
                retained = json.loads(handle.readline())
            generation = report.collect_generation(directory, log)

        self.assertEqual(results[0]["error"], "source timeout")
        self.assertEqual(retained["cve"], "CVE-2026-12345")
        self.assertEqual(len(generation), 1)
        self.assertEqual(generation[0]["generation_error"], "source timeout")


if __name__ == "__main__":
    unittest.main()
