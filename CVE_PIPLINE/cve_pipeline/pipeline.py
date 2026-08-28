"""CVE evidence -> exact vulnerable VM target -> guest configuration script.

The existing infrastructure owns VM/image construction, but receives an exact,
evidence-backed OS/kernel target and deterministic kernel provisioning script
from this project. NLP remains restricted to typed, evidence-linked extra
configuration prerequisites and cannot alter the selected target.
"""
from __future__ import annotations

import json
import os

from .config import Config
from .adapters import ollama, sources
from .domain import configuration as configuration_mod
from .domain import environment as environment_mod
from .domain import prompts
from .domain import vulnerable_target as vulnerable_target_mod
from .domain.generators import (
    configuration_check, distro_kernel, guest_configuration, packer_handoff, qemu_vm,
)
from . import registry


def _write_json(path: str, value: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)


def run_one(cve_id: str, cfg: Config, os_hint: str = "auto", description: str | None = None,
            auto_reboot: bool = False, kernel_target: str | None = None,
            os_version_hint: str | None = None, source_bundle: dict | None = None,
            qemu_check: bool = False, qemu_memory_mb: int = 4096,
            qemu_cpus: int = 2, qemu_disk_size: str = "20G",
            qemu_timeout_s: int = 1800) -> dict:
    """Generate an exact infrastructure target plus its configuration stage.

    ``auto_reboot`` and ``kernel_target`` remain accepted for API compatibility,
    but deliberately have no effect; target selection is evidence-driven.
    """
    del auto_reboot, kernel_target
    result = {"cve": cve_id, "workflow": "vulnerable-vm+guest-configuration"}

    if source_bundle is not None:
        bundle = source_bundle
    else:
        bundle_path = _bundle_path(cfg.source_bundle_dir, cve_id)
        bundle = (sources.load_bundle(bundle_path, cve_id) if bundle_path
                  else sources.collect(cve_id, cfg.nvd_api_key, cfg.source_mode, cfg.source_timeout))
    sources.validate_bundle_identity(bundle, cve_id)
    # Analyst text is retained for audit, but it never replaces or outranks the
    # descriptions collected from recognized official services.
    if description is not None:
        bundle["analyst_note"] = description
    coverage = sources.official_source_coverage(bundle)
    bundle["official_source_policy"] = coverage
    mdir = os.path.join(cfg.machines_dir, cve_id)
    os.makedirs(mdir, exist_ok=True)
    sources_path = os.path.join(mdir, "sources.json")
    _write_json(sources_path, bundle)
    result.update({"sources": bundle, "sources_path": sources_path,
                   "official_source_policy": coverage})

    # Fail before NLP and script generation. The retained sources.json explains
    # exactly which official collectors succeeded or failed.
    sources.require_multiple_official_sources(bundle)

    primary_description = bundle.get("description")
    if not primary_description:
        raise ValueError("No description was available from the collected official sources.")
    result["description"] = primary_description

    # Deterministic selection must happen before, and independently from, NLP.
    environment = environment_mod.select(bundle, os_hint, os_version_hint)
    build_target = vulnerable_target_mod.select(bundle, environment)
    environment["build_target"] = build_target
    environment_path = os.path.join(mdir, "environment.json")
    _write_json(environment_path, environment)
    build_target_path = os.path.join(mdir, "build-target.json")
    _write_json(build_target_path, build_target)
    result.update({
        "environment": environment,
        "environment_path": environment_path,
        "build_target": build_target,
        "build_target_path": build_target_path,
    })

    kernel_script = None
    kernel_name = None
    kernel_path = None
    kernel_constraints = environment.get("vulnerable_constraints") or {}
    if kernel_constraints.get("running_kernel_package_constraint"):
        if build_target.get("status") != "selected":
            raise ValueError(
                "A vulnerable Ubuntu kernel range was identified, but no exact "
                f"buildable kernel target was proven: {build_target.get('reason', 'unknown reason')}"
            )
        kernel = build_target["kernel"]
        kernel_spec = {
            "package": kernel["meta_package"],
            "version_constraint": kernel["meta_package_constraint"],
            "concrete_kernel_constraint": kernel["concrete_package_constraint"],
            "target_meta_version": kernel["meta_package_version"],
            "target_kernel_release": kernel["running_kernel_release"],
            "os_family": build_target["os_family"],
            "os_version": build_target["os_version"],
            "package_manager": "apt",
        }
        kernel_script = distro_kernel.build(kernel_spec)
        kernel_name = distro_kernel.filename(cve_id)
        kernel_path = os.path.join(mdir, kernel_name)
        with open(kernel_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(kernel_script)
        result.update({
            "kernel_script": kernel_script,
            "kernel_script_name": kernel_name,
            "kernel_script_path": kernel_path,
        })

    base_evidence = sources.prompt_evidence(bundle)
    validation_errors = []
    raw_paths = []
    configuration = None
    reconciliation_notes = []
    extraction_fallback = False
    extract_raw = ""
    for attempt in (1, 2):
        model_evidence = base_evidence
        if validation_errors:
            model_evidence = prompts.configuration_repair_evidence(
                base_evidence, validation_errors[-1], extract_raw
            )
        parse_error = None
        try:
            parsed, extract_raw = ollama.extract_configuration(
                primary_description, cfg.endpoint, cfg.extract_model, model_evidence
            )
        except ollama.InvalidModelJSON as exc:
            parsed, extract_raw, parse_error = None, exc.raw, str(exc)
        raw_path = os.path.join(mdir, f"extraction-attempt-{attempt}.txt")
        with open(raw_path, "w", encoding="utf-8") as handle:
            handle.write(extract_raw)
        raw_paths.append(raw_path)
        if parse_error:
            validation_errors.append(parse_error)
            continue
        try:
            candidate = configuration_mod.normalize(parsed)
            candidate, candidate_notes = configuration_mod.reconcile_and_ground(
                candidate, bundle, primary_description
            )
            configuration_mod.validate_evidence(candidate, bundle, primary_description)
            configuration = candidate
            reconciliation_notes = candidate_notes
            break
        except ValueError as exc:
            validation_errors.append(str(exc))
    if configuration is None:
        extraction_fallback = True
        configuration = configuration_mod.normalize({
            "configuration_status": "unknown",
            "summary": (
                "Configuration extraction could not be certified after two attempts. "
                "The generated script is fail-closed; inspect the retained model responses "
                "and validation errors before manual use."
            ),
        })
    configuration_path = os.path.join(mdir, "configuration.json")
    _write_json(configuration_path, configuration)
    result.update({
        "configuration": configuration,
        "configuration_path": configuration_path,
        "extract_raw": extract_raw,
        "extract_raw_paths": raw_paths,
        "extraction_validation_errors": validation_errors,
        "configuration_reconciliation_notes": reconciliation_notes,
        "configuration_fallback": extraction_fallback,
        "ground_truth": sources.nvd_ground_truth(bundle),
    })

    script = guest_configuration.build(environment, configuration, cve_id)
    script_name = guest_configuration.filename(cve_id)
    script_path = os.path.join(mdir, script_name)
    with open(script_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(script)
    result.update({
        "script": script,
        "script_name": script_name,
        "script_path": script_path,
        "generator_used": "exact kernel target plus deterministic typed guest configuration",
    })

    if kernel_name:
        handoff = packer_handoff.build(
            environment, cve_id, kernel_name, script_name
        )
        handoff_name = packer_handoff.filename(cve_id)
        handoff_path = os.path.join(mdir, handoff_name)
        with open(handoff_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(handoff)
        result.update({
            "packer_handoff": handoff,
            "packer_handoff_name": handoff_name,
            "packer_handoff_path": handoff_path,
        })

    if qemu_check:
        qemu_script = qemu_vm.build(
            environment, cve_id,
            memory_mb=qemu_memory_mb, cpus=qemu_cpus,
            disk_size=qemu_disk_size, timeout_s=qemu_timeout_s,
            kernel_script=kernel_script,
        )
        qemu_name = qemu_vm.filename(cve_id)
        qemu_path = os.path.join(mdir, qemu_name)
        with open(qemu_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(qemu_script)
        check_script = configuration_check.build(
            environment, configuration, cve_id, guest_script=script,
        )
        check_name = configuration_check.filename(cve_id)
        check_path = os.path.join(mdir, check_name)
        with open(check_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(check_script)
        result.update({
            "qemu_check": True,
            "qemu_script": qemu_script,
            "qemu_script_name": qemu_name,
            "qemu_script_path": qemu_path,
            "configuration_check_script": check_script,
            "configuration_check_script_name": check_name,
            "configuration_check_script_path": check_path,
            "workflow": "vulnerable-qemu-vm+guest-configuration-check",
        })

    hcl = os.path.join(mdir, "variables.pkrvars.hcl")
    # A flat scripts list cannot represent the mandatory reboot.  Register only
    # the post-build configuration payload there; the generated Packer handoff
    # contains the ordered kernel/reboot/verify/configuration stages.
    registration_names = [script_name]
    result["registered"] = (
        registry.register_many(hcl, cve_id, registration_names)
        if cfg.register and os.path.exists(hcl) else False
    )
    if cfg.eval_log:
        _append_eval(cfg.eval_log, result)
    return result


def run_batch(
    cve_ids,
    cfg: Config,
    os_hint: str = "auto",
    *,
    os_version_hint: str | None = None,
    qemu_check: bool = False,
    qemu_memory_mb: int = 4096,
    qemu_cpus: int = 2,
    qemu_disk_size: str = "20G",
    qemu_timeout_s: int = 1800,
):
    """Run independent CVEs sequentially and retain every failure as data."""
    results = []
    for cid in cve_ids:
        try:
            results.append(run_one(
                cid, cfg, os_hint,
                os_version_hint=os_version_hint,
                qemu_check=qemu_check,
                qemu_memory_mb=qemu_memory_mb,
                qemu_cpus=qemu_cpus,
                qemu_disk_size=qemu_disk_size,
                qemu_timeout_s=qemu_timeout_s,
            ))
        except Exception as exc:  # one incomplete record must not stop a batch
            failed = {"cve": cid, "error": str(exc)}
            results.append(failed)
            if cfg.eval_log:
                _append_eval(cfg.eval_log, failed)
    return results


def _bundle_path(directory: str | None, cve_id: str) -> str | None:
    """Resolve explicit replay layouts; a missing bundle uses live collection."""
    if not directory:
        return None
    candidates = (
        os.path.join(directory, cve_id, "sources.json"),
        os.path.join(directory, f"{cve_id}.json"),
    )
    return next((path for path in candidates if os.path.isfile(path)), None)


def _append_eval(path: str, result: dict) -> None:
    row = {key: result.get(key) for key in (
        "cve", "error", "workflow", "generator_used", "environment", "build_target",
        "configuration", "ground_truth", "sources"
    )}
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
