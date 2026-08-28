"""Build dissertation-ready evaluation tables from generated and runtime data."""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from collections import defaultdict


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TRUE = {"1", "true", "yes", "y", "pass", "ready", "confirmed"}
_FALSE = {"0", "false", "no", "n", "fail", "failed", "not_ready"}


def _json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}


def _csv(path: str | list[str] | None) -> list[dict]:
    paths = path if isinstance(path, list) else [path]
    rows = []
    for item in paths:
        if not item or not os.path.isfile(item):
            continue
        with open(item, newline="", encoding="utf-8-sig") as handle:
            rows.extend(dict(row) for row in csv.DictReader(handle))
    return rows


def _bool(value) -> bool | None:
    text = str(value or "").strip().casefold()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def _rate(numerator: int, denominator: int) -> float | None:
    return round(100.0 * numerator / denominator, 2) if denominator else None


def _generation_errors(path: str | None) -> dict[str, str]:
    errors = {}
    if not path or not os.path.isfile(path):
        return errors
    with open(path, encoding="utf-8-sig") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and item.get("cve") and item.get("error"):
                errors[str(item["cve"]).upper()] = str(item["error"])
    return errors


def collect_generation(machines_dir: str, generation_log: str | None = None) -> list[dict]:
    """Read one stable generation record per CVE output directory."""
    errors = _generation_errors(generation_log)
    rows = []
    if not os.path.isdir(machines_dir) and not errors:
        return rows
    directories = {}
    if os.path.isdir(machines_dir):
        for name in os.listdir(machines_dir):
            cve = name.upper()
            directory = os.path.join(machines_dir, name)
            if _CVE.fullmatch(cve) and os.path.isdir(directory):
                directories[cve] = directory
    for cve in sorted(set(directories) | set(errors)):
        directory = directories.get(cve, os.path.join(machines_dir, cve))
        sources = _json(os.path.join(directory, "sources.json"))
        environment = _json(os.path.join(directory, "environment.json"))
        target = _json(os.path.join(directory, "build-target.json"))
        configuration = _json(os.path.join(directory, "configuration.json"))
        source_policy = sources.get("official_source_policy") or {}
        version_evidence = environment.get("machine_readable_version_evidence") or {}
        kernel = target.get("kernel") or {}
        config_items = sum(len(configuration.get(key) or []) for key in (
            "kernel_modules", "kernel_config", "kernel_config_alternatives", "sysctls",
            "packages", "services", "file_settings", "manual_steps",
        ))
        builder = os.path.join(directory, f"build_qemu_{cve}.sh")
        checker = os.path.join(directory, f"check_configuration_{cve}.sh")
        rows.append({
            "cve": cve,
            "generation_error": errors.get(cve, ""),
            "official_source_count": source_policy.get("count", ""),
            "official_source_minimum": source_policy.get("minimum_required", ""),
            "source_error_count": len(sources.get("errors") or []),
            "range_evidence_mode": version_evidence.get("status", ""),
            "nvd_cpe_count": version_evidence.get("nvd_cpe_count", ""),
            "environment_status": environment.get("status", ""),
            "os_family": environment.get("os_family", ""),
            "os_version": environment.get("os_version", ""),
            "suite": environment.get("suite", ""),
            "architecture": environment.get("architecture", ""),
            "target_status": target.get("status", ""),
            "target_reason": target.get("reason", ""),
            "meta_package": kernel.get("meta_package", ""),
            "meta_package_version": kernel.get("meta_package_version", ""),
            "running_kernel_release": kernel.get("running_kernel_release", ""),
            "kernel_constraint": kernel.get("concrete_package_constraint", ""),
            "configuration_status": configuration.get("configuration_status", ""),
            "configuration_item_count": config_items,
            "manual_step_count": len(configuration.get("manual_steps") or []),
            "qemu_builder_generated": int(os.path.isfile(builder)),
            "configuration_checker_generated": int(os.path.isfile(checker)),
        })
    return rows


def build_evaluation(
    machines_dir: str,
    *,
    runtime_csv: str | list[str] | None = None,
    ground_truth_csv: str | None = None,
    manual_validation_csv: str | None = None,
    generation_log: str | None = None,
) -> tuple[list[dict], dict]:
    """Merge records and calculate stage-specific, non-inflated rates."""
    generation = collect_generation(machines_dir, generation_log)
    runtime = _csv(runtime_csv)
    truth = {row.get("cve", "").upper(): row for row in _csv(ground_truth_csv)}
    validation = {
        row.get("cve", "").upper(): row for row in _csv(manual_validation_csv)
    }
    runtime_by_cve = defaultdict(list)
    for row in runtime:
        cve = row.get("cve", "").upper()
        if _CVE.fullmatch(cve):
            runtime_by_cve[cve].append(row)

    combined = []
    for generated in generation:
        cve = generated["cve"]
        attempts = runtime_by_cve.get(cve) or [{}]
        for runtime_row in attempts:
            row = dict(generated)
            row.update({f"runtime_{key}": value for key, value in runtime_row.items() if key != "cve"})
            row.update({f"truth_{key}": value for key, value in truth.get(cve, {}).items() if key != "cve"})
            row.update({
                f"validation_{key}": value
                for key, value in validation.get(cve, {}).items() if key != "cve"
            })
            combined.append(row)

    primary_runtime = {}
    for cve, attempts in runtime_by_cve.items():
        primary_runtime[cve] = next(
            (row for row in attempts if str(row.get("repetition", "")) == "1"),
            attempts[0],
        )
    selected = [row for row in generation if row["target_status"] == "selected"]
    attempted = [row for row in selected if row["cve"] in primary_runtime]
    exact = sum(
        _bool(primary_runtime[row["cve"]].get("exact_kernel_vm")) is True
        for row in attempted
    )
    ready = sum(
        _bool(primary_runtime[row["cve"]].get("environment_ready")) is True
        for row in attempted
    )

    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "excluded": 0}
    for row in generation:
        actual = _bool((truth.get(row["cve"]) or {}).get("actual_default_ready"))
        predicted = {
            "not_required": True,
            "required": False,
        }.get(row["configuration_status"])
        if actual is None or predicted is None:
            confusion["excluded"] += 1
        elif actual and predicted:
            confusion["tp"] += 1
        elif not actual and predicted:
            confusion["fp"] += 1
        elif actual and not predicted:
            confusion["fn"] += 1
        else:
            confusion["tn"] += 1
    classified = sum(confusion[key] for key in ("tp", "fp", "fn", "tn"))
    precision_den = confusion["tp"] + confusion["fp"]
    recall_den = confusion["tp"] + confusion["fn"]
    precision = confusion["tp"] / precision_den if precision_den else None
    recall = confusion["tp"] / recall_den if recall_den else None

    compatible_attempts = [
        row for row in validation.values()
        if _bool(row.get("poc_attempted")) is True
        and _bool(row.get("poc_compatible")) is True
    ]
    confirmed = sum(
        str(row.get("poc_result", "")).strip().casefold() == "confirmed"
        for row in compatible_attempts
    )
    repeated = [attempts for attempts in runtime_by_cve.values() if len(attempts) > 1]
    consistent = sum(
        len({str(_bool(row.get("environment_ready"))) for row in attempts}) == 1
        for attempts in repeated
    )
    metrics = {
        "dataset_cves": len(generation),
        "generation_errors": sum(bool(row["generation_error"]) for row in generation),
        "environment_selected": sum(row["environment_status"] == "selected" for row in generation),
        "exact_targets_selected": len(selected),
        "qemu_builders_generated": sum(row["qemu_builder_generated"] == 1 for row in generation),
        "primary_vm_attempts": len(attempted),
        "exact_kernel_vms_built": exact,
        "ready_environments": ready,
        "selected_target_evaluation_coverage_percent": _rate(len(attempted), len(selected)),
        "vm_generation_success_rate_percent": _rate(exact, len(attempted)),
        "configuration_readiness_rate_percent": _rate(ready, exact),
        "end_to_end_success_rate_attempted_targets_percent": _rate(ready, len(attempted)),
        "end_to_end_success_rate_all_cves_percent": (
            _rate(ready, len(generation)) if attempted else None
        ),
        "end_to_end_success_rate_selected_targets_percent": (
            _rate(ready, len(selected)) if attempted else None
        ),
        "default_readiness_confusion_matrix": confusion,
        "default_readiness_accuracy_percent": _rate(confusion["tp"] + confusion["tn"], classified),
        "default_readiness_precision_percent": round(100 * precision, 2) if precision is not None else None,
        "default_readiness_recall_percent": round(100 * recall, 2) if recall is not None else None,
        "false_ready_count": confusion["fp"],
        "compatible_poc_attempts": len(compatible_attempts),
        "exploit_confirmed": confirmed,
        "exploit_confirmation_rate_percent": _rate(confirmed, len(compatible_attempts)),
        "cves_repeated": len(repeated),
        "repeatable_outcomes": consistent,
        "outcome_repeatability_rate_percent": _rate(consistent, len(repeated)),
    }
    return combined, metrics


def _write_csv(path: str, rows: list[dict]) -> None:
    fields = ["cve"]
    fields.extend(sorted({key for row in rows for key in row if key != "cve"}))
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _markdown(metrics: dict, rows: list[dict]) -> str:
    def display(value):
        return "N/A" if value is None else str(value)

    lines = [
        "# CVE Reproduction Evaluation Report",
        "",
        "## Aggregate results",
        "",
        "| Metric | Result |",
        "|---|---:|",
    ]
    labels = (
        ("Dataset CVEs", "dataset_cves"),
        ("Exact targets selected", "exact_targets_selected"),
        ("Primary VM attempts", "primary_vm_attempts"),
        ("Exact-kernel VMs built", "exact_kernel_vms_built"),
        ("Ready environments", "ready_environments"),
        ("Selected-target evaluation coverage (%)", "selected_target_evaluation_coverage_percent"),
        ("VM generation success (%)", "vm_generation_success_rate_percent"),
        ("Configuration readiness (%)", "configuration_readiness_rate_percent"),
        ("End-to-end success, attempted targets (%)", "end_to_end_success_rate_attempted_targets_percent"),
        ("End-to-end success, all CVEs (%)", "end_to_end_success_rate_all_cves_percent"),
        ("False-ready classifications", "false_ready_count"),
        ("Compatible PoC attempts", "compatible_poc_attempts"),
        ("Exploit confirmations", "exploit_confirmed"),
        ("Exploit confirmation rate (%)", "exploit_confirmation_rate_percent"),
        ("Repeated CVEs", "cves_repeated"),
        ("Outcome repeatability (%)", "outcome_repeatability_rate_percent"),
    )
    lines.extend(f"| {label} | {display(metrics[key])} |" for label, key in labels)
    lines += [
        "",
        "## Per-CVE results",
        "",
        "| CVE | Evidence | Target | Kernel | Configuration | VM | READY |",
        "|---|---|---|---|---|---:|---:|",
    ]
    first = {}
    for row in rows:
        first.setdefault(row["cve"], row)
    for cve, row in sorted(first.items()):
        lines.append(
            f"| {cve} | {row.get('range_evidence_mode') or 'unavailable'} | "
            f"{row.get('target_status') or 'unresolved'} | "
            f"{row.get('running_kernel_release') or '-'} | "
            f"{row.get('configuration_status') or '-'} | "
            f"{row.get('runtime_exact_kernel_vm', '-')} | "
            f"{row.get('runtime_environment_ready', '-')} |"
        )
    lines += [
        "",
        "`READY` means exact target and configuration conformance. Exploit confirmation is reported separately.",
        "",
    ]
    return "\n".join(lines)


def write_report(
    machines_dir: str,
    output_dir: str,
    **inputs,
) -> dict:
    rows, metrics = build_evaluation(machines_dir, **inputs)
    os.makedirs(output_dir, exist_ok=True)
    _write_csv(os.path.join(output_dir, "combined-results.csv"), rows)
    with open(os.path.join(output_dir, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    with open(os.path.join(output_dir, "evaluation-report.md"), "w", encoding="utf-8") as handle:
        handle.write(_markdown(metrics, rows))
    return metrics


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Summarize generation, VM, and PoC evaluation data")
    parser.add_argument("--machines-dir", required=True)
    parser.add_argument(
        "--runtime-csv", action="append",
        help="runtime CSV from the Ubuntu runner; repeat for multiple repetitions",
    )
    parser.add_argument("--ground-truth")
    parser.add_argument("--manual-validation")
    parser.add_argument("--generation-log")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    metrics = write_report(
        args.machines_dir,
        args.output_dir,
        runtime_csv=args.runtime_csv,
        ground_truth_csv=args.ground_truth,
        manual_validation_csv=args.manual_validation,
        generation_log=args.generation_log,
    )
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
