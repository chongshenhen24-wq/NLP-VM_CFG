"""Canonical identity shared by the split QEMU evaluation artefacts.

The VM builder, host-side checker, and guest payload are separate files.  A
stable digest prevents a file from one environment selection being combined
with files from another selection while retaining that separation of duties.
"""
from __future__ import annotations

import hashlib
import json


UBUNTU_SUITES = {
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
}


def canonical(environment: dict, cve_id: str) -> dict:
    """Return the runtime-relevant part of an environment selection."""
    if not isinstance(environment, dict):
        raise ValueError("Environment selection must be an object")
    constraints = environment.get("vulnerable_constraints") or {}
    if not isinstance(constraints, dict):
        raise ValueError("Environment vulnerable_constraints must be an object")
    build_target = environment.get("build_target") or {}
    kernel = build_target.get("kernel") or {}
    return {
        "schema": 2,
        "cve": str(cve_id or "").strip().upper(),
        "status": str(environment.get("status") or ""),
        "os_family": str(environment.get("os_family") or "").strip().lower(),
        "os_version": str(environment.get("os_version") or "").strip(),
        "suite": str(environment.get("suite") or "").strip().lower(),
        "architecture": str(environment.get("architecture") or "").strip().lower(),
        "vulnerable_constraints": constraints,
        "build_target": {
            "status": str(build_target.get("status") or ""),
            "os_family": str(build_target.get("os_family") or ""),
            "os_version": str(build_target.get("os_version") or ""),
            "suite": str(build_target.get("suite") or ""),
            "architecture": str(build_target.get("architecture") or ""),
            "kernel": {
                "meta_package": str(kernel.get("meta_package") or ""),
                "meta_package_version": str(kernel.get("meta_package_version") or ""),
                "concrete_package": str(kernel.get("concrete_package") or ""),
                "running_kernel_release": str(kernel.get("running_kernel_release") or ""),
            },
        },
    }


def fingerprint(environment: dict, cve_id: str) -> str:
    """Hash the canonical selection for embedding in all generated scripts."""
    encoded = json.dumps(
        canonical(environment, cve_id), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_selected_ubuntu(environment: dict) -> tuple[str, str]:
    """Validate and return a supported Ubuntu version/codename pair."""
    if environment.get("status") != "selected":
        raise ValueError("QEMU workflow requires a selected base environment")
    if (environment.get("os_family") or "").strip().lower() != "ubuntu":
        raise ValueError("The QEMU workflow currently supports Ubuntu only")
    version = (environment.get("os_version") or "").strip()
    expected_suite = UBUNTU_SUITES.get(version)
    if not expected_suite:
        supported = ", ".join(sorted(UBUNTU_SUITES))
        raise ValueError(
            f"Unsupported Ubuntu cloud-image version {version!r}; choose one of: {supported}"
        )
    selected_suite = (environment.get("suite") or expected_suite).strip().lower()
    if selected_suite != expected_suite:
        raise ValueError(
            "Selected Ubuntu version and suite disagree: "
            f"{version} requires {expected_suite}, not {selected_suite}"
        )
    return version, expected_suite


def validate_selected_kernel_target(environment: dict) -> dict:
    """Return the exact selected kernel target required by a vulnerable VM build."""
    target = environment.get("build_target") or {}
    kernel = target.get("kernel") or {}
    required = (
        "meta_package", "meta_package_version", "concrete_package",
        "running_kernel_release",
    )
    if target.get("status") != "selected" or any(not kernel.get(key) for key in required):
        raise ValueError(
            "Vulnerable VM construction requires an exact evidence-backed kernel target"
        )
    if (
        target.get("os_family") != environment.get("os_family")
        or target.get("os_version") != environment.get("os_version")
        or target.get("suite") != environment.get("suite")
        or target.get("architecture") != environment.get("architecture")
    ):
        raise ValueError("The exact kernel target does not match the selected Ubuntu image")
    return kernel
