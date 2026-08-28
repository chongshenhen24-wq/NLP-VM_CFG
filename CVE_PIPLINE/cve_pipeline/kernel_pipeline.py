"""End-to-end kernel-CVE resolution and reproduction materialisation."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .adapters import ollama, osv, sources
from .domain import prompts
from .evaluation import kernel_resolve
from .kernel_repro import emit_kernel_scripts


def resolve_kernel(cve_id: str, cfg, branch: str = "latest", description: str | None = None) -> dict:
    """Resolve a vulnerable kernel ref using one shared multi-source bundle."""
    bundle = sources.collect(cve_id, cfg.nvd_api_key, cfg.source_mode, cfg.source_timeout)
    machine = os.path.join(cfg.machines_dir, sources.normalize_cve_id(cve_id))
    os.makedirs(machine, exist_ok=True)
    source_path = os.path.join(machine, "sources.json")
    with open(source_path, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)

    advisory = description or bundle.get("description")
    if not advisory:
        raise ValueError("No kernel advisory text is available; enable sources or supply --description.")
    osv_record = sources.osv_record(bundle)
    if not osv_record:
        raise ValueError("OSV supplied no structured kernel ranges; an automatic vulnerable ref cannot be proven.")
    osv_truth = osv.kernel_truth(osv_record)
    if not osv_truth.get("has_data"):
        raise ValueError("OSV supplied no introduced/fixed kernel range for this CVE.")

    system, user = prompts.kernel_extraction(advisory, sources.prompt_evidence(bundle))
    raw = ollama._generate(cfg.endpoint, cfg.extract_model, system, user, force_json=True)
    try:
        extracted = json.loads(prompts.strip_fences(raw))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Kernel extraction model did not return valid JSON: {exc}") from exc

    result = kernel_resolve.resolve(extracted, osv_truth, sources.nvd_ground_truth(bundle), branch)
    result.update({"cve": sources.normalize_cve_id(cve_id), "description": advisory,
                   "extracted": extracted, "extract_raw": raw, "sources": bundle,
                   "sources_path": source_path})
    resolution_path = os.path.join(machine, "kernel-resolution.json")
    with open(resolution_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    result["resolution_path"] = resolution_path
    return result


def reproduce_kernel(cve_id: str, cfg, branch: str, poc_path: str, poc_success: str,
                     config_options=None, subsystem=None, kallsyms_symbols=None,
                     modules=None, poc_args="", ubuntu_suite="jammy", execute=False) -> dict:
    """Resolve, bundle the PoC, emit scripts, and optionally build/boot/verify."""
    if not poc_path or not os.path.isfile(poc_path):
        raise ValueError("--poc must name an existing PoC executable or script")
    if not (poc_success or "").strip():
        raise ValueError("--poc-success is required so verification cannot report a false positive")
    result = resolve_kernel(cve_id, cfg, branch)
    vulnerable_ref = result.get("vulnerable_ref")
    if not vulnerable_ref:
        raise ValueError("No released vulnerable kernel ref was proven for the selected branch")

    subsystem = subsystem or (result.get("extracted") or {}).get("subsystem")
    machine = os.path.join(cfg.machines_dir, result["cve"])
    os.makedirs(machine, exist_ok=True)
    bundled_poc = os.path.join(machine, "poc")
    if os.path.abspath(poc_path) != os.path.abspath(bundled_poc):
        shutil.copy2(poc_path, bundled_poc)
    scripts = emit_kernel_scripts(result["cve"], vulnerable_ref, cfg.machines_dir,
                                  config_options=config_options, subsystem=subsystem,
                                  kallsyms_symbols=kallsyms_symbols, modules=modules,
                                  poc_success=poc_success, poc_path=bundled_poc,
                                  poc_args=poc_args, ubuntu_suite=ubuntu_suite)
    result["scripts"] = scripts
    result["poc_path"] = bundled_poc
    if execute:
        for name in ("build_kernel.sh", "build_rootfs.sh", "run_qemu.sh"):
            completed = subprocess.run(["bash", os.path.basename(scripts[name])], cwd=machine)
            if completed.returncode:
                raise RuntimeError(f"{name} failed with exit code {completed.returncode}")
        result["executed"] = True
    else:
        result["executed"] = False
    return result
