"""Deterministic Ubuntu kernel reconciliation from authoritative source evidence."""
from __future__ import annotations

import re


def _ubuntu_source(bundle: dict) -> dict | None:
    for source in bundle.get("sources") or []:
        if source.get("name") == "Ubuntu Security Tracker":
            return source
    return None


def _is_linux_kernel(ground_truth: dict | None, source: dict | None) -> bool:
    products = (ground_truth or {}).get("products") or []
    upstream = any(
        product.get("part") == "o"
        and product.get("product") in {"linux_kernel", "linux"}
        for product in products
    )
    ubuntu_kernel = any(
        product.get("part") == "o"
        and product.get("vendor") == "canonical"
        and product.get("product") == "ubuntu_linux"
        for product in products
    )
    return upstream or ubuntu_kernel or bool((source or {}).get("kernel_rows"))


def _requires_arm64_64k(bundle: dict) -> bool:
    text = " ".join(
        str(value)
        for value in (
            bundle.get("description"),
            *((source.get("description") or source.get("details") or "")
              for source in bundle.get("sources") or []),
        )
    ).lower()
    return (
        ("arm64" in text or "aarch64" in text)
        and bool(re.search(r"\b64\s*k(?:b|ib)\b", text))
        and "page" in text
    )


def reconcile(spec: dict, bundle: dict, ground_truth: dict | None) -> tuple[dict, dict | None]:
    """Replace ambiguous NLP distro fields with reviewed Ubuntu package evidence."""
    source = _ubuntu_source(bundle)
    if not _is_linux_kernel(ground_truth, source):
        return spec, None
    if _requires_arm64_64k(bundle):
        raise ValueError(
            "This CVE requires ARM64 with 64 KB base pages; the current "
            "x86_64 Ubuntu QEMU generator cannot reproduce it safely"
        )
    if not source:
        raise ValueError(
            "Ubuntu kernel evidence is unavailable; refusing to guess an OS release"
        )
    selected = source.get("selected_kernel")
    if not selected:
        raise ValueError(
            "Ubuntu tracker has no fixed affected release supported by the QEMU generator"
        )
    required = ("version", "suite", "fixed_version", "package", "meta_fixed_version")
    missing = [field for field in required if not selected.get(field)]
    if missing:
        detail = selected.get("meta_error") or ", ".join(missing)
        raise ValueError(f"Ubuntu kernel evidence is incomplete: {detail}")
    resolved = dict(spec)
    resolved.update({
        "package": selected["package"],
        "package_manager": "apt",
        "version_constraint": f"<{selected['meta_fixed_version']}",
        "concrete_kernel_constraint": f"<{selected['fixed_version']}",
        "os_family": "ubuntu",
        "os_version": selected["version"],
        "service_name": "",
        "start_command": "",
        "config_file": "",
        "config_directives": [],
        "setup_commands": [],
        "notes": (
            f"Resolved automatically from Ubuntu Security Tracker and Launchpad: "
            f"Ubuntu {selected['version']} ({selected['suite']}), "
            f"{selected['package']} fixed at {selected['meta_fixed_version']}, "
            f"concrete kernel fixed at {selected['fixed_version']}."
        ),
    })
    evidence = {
        "policy": source.get("selection_policy"),
        "release": selected["version"],
        "suite": selected["suite"],
        "package": selected["package"],
        "meta_fixed_version": selected["meta_fixed_version"],
        "concrete_fixed_version": selected["fixed_version"],
        "ubuntu_url": source.get("url"),
        "meta_url": selected.get("meta_url"),
    }
    return resolved, evidence