"""Deterministic vulnerable-platform selection from machine-readable evidence.

The NLP model is deliberately absent from this module. NVD CPE data identifies
the affected product/platform when it is available. A newly published record
may not have an NVD CPE yet, so official CNA/OSV affected-version arrays are an
explicitly labelled fallback. Canonical's structured tracker rows then resolve
Ubuntu's downstream kernel boundary. The fallback is never described as CPE.
"""
from __future__ import annotations

import re
from urllib.parse import unquote


def _source(bundle: dict, name: str) -> dict | None:
    return next((item for item in bundle.get("sources") or [] if item.get("name") == name), None)


def _cpe_matches(bundle: dict) -> list[dict]:
    nvd = _source(bundle, "NVD") or {}
    return list(nvd.get("cpe_matches") or [])


def machine_version_evidence(bundle: dict) -> dict:
    """Describe the machine-readable range evidence without relabelling it.

    NVD CPE is preferred. If it is absent, a non-empty official CNA or OSV
    affected-version structure is accepted as a documented fallback. Free-form
    prose and distribution tracker rows do not satisfy this gate by themselves.
    """
    nvd = _source(bundle, "NVD") or {}
    cpes = list(nvd.get("cpe_matches") or [])
    if cpes:
        return {
            "status": "nvd-cpe",
            "nvd_cpe_status": "available",
            "nvd_cpe_count": len(cpes),
            "fallback_used": False,
            "source_names": ["NVD"],
            "evidence_urls": [nvd.get("url")] if nvd.get("url") else [],
            "explanation": (
                "NVD supplied machine-readable CPE match data for deterministic "
                "affected-product/range selection."
            ),
        }

    structured_sources = []
    structured_urls = []
    cna = _source(bundle, "CVE.org / CNA record") or {}
    if any(
        isinstance(item, dict) and item.get("versions")
        for item in cna.get("affected") or []
    ):
        structured_sources.append("CVE.org / CNA record")
        if cna.get("url"):
            structured_urls.append(cna["url"])
    osv = _source(bundle, "OSV") or {}
    if any(
        isinstance(item, dict) and (item.get("ranges") or item.get("versions"))
        for item in osv.get("affected") or []
    ):
        structured_sources.append("OSV")
        if osv.get("url"):
            structured_urls.append(osv["url"])
    if structured_sources:
        return {
            "status": "structured-version-fallback",
            "nvd_cpe_status": "unavailable",
            "nvd_cpe_count": 0,
            "fallback_used": True,
            "source_names": structured_sources,
            "evidence_urls": structured_urls,
            "explanation": (
                "NVD supplied no CPE match. Official CNA/OSV machine-readable "
                "affected-version data is used as a clearly labelled fallback; "
                "it is not CPE data."
            ),
        }
    return {
        "status": "unavailable",
        "nvd_cpe_status": "unavailable",
        "nvd_cpe_count": 0,
        "fallback_used": False,
        "source_names": [],
        "evidence_urls": [],
        "explanation": (
            "Neither NVD CPE matches nor official CNA/OSV structured affected-"
            "version data was available. Prose alone cannot select a target."
        ),
    }


def _parse_cpe(criteria: str) -> dict | None:
    bits = (criteria or "").split(":")
    if len(bits) < 6 or bits[:2] != ["cpe", "2.3"]:
        return None
    return {
        "part": unquote(bits[2]),
        "vendor": unquote(bits[3]),
        "product": unquote(bits[4]),
        "version": unquote(bits[5]),
    }


def _range(match: dict, version: str) -> str:
    terms = []
    for field, operator in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        if match.get(field):
            terms.append(operator + str(match[field]))
    if not terms and version not in {"", "*", "-"}:
        terms.append("==" + version)
    return ",".join(terms)


def _kernel_environment(bundle: dict, cpes: list[dict], version_evidence: dict) -> dict | None:
    ubuntu = _source(bundle, "Ubuntu Security Tracker") or {}
    selected = ubuntu.get("selected_kernel") or {}
    if not selected:
        return None
    required = ("version", "suite", "fixed_version")
    if any(not selected.get(field) for field in required):
        return None
    package = selected.get("package") or "linux-image-generic"
    meta_fixed = selected.get("meta_fixed_version")
    constraints = {
        "package": package,
        "meta_package_constraint": f"<{meta_fixed}" if meta_fixed else None,
        "running_kernel_package_constraint": f"<{selected['fixed_version']}",
    }
    return {
        "status": "selected",
        "os_family": "ubuntu",
        "os_version": selected["version"],
        "suite": selected["suite"],
        "architecture": "amd64",
        "selection_basis": "ubuntu-security-tracker",
        "selection_explanation": (
            "Machine-readable upstream version evidence was mapped to Canonical's "
            "structured Ubuntu kernel row; no NLP output participated in this choice."
        ),
        "vulnerable_constraints": constraints,
        "cpe_matches": cpes,
        "machine_readable_version_evidence": version_evidence,
        "evidence_urls": list(dict.fromkeys(url for url in (
            *version_evidence.get("evidence_urls", []), ubuntu.get("url"),
            selected.get("meta_url"), ubuntu.get("fallback_url")
        ) if url)),
    }


def select(bundle: dict, os_hint: str = "auto", os_version_hint: str | None = None) -> dict:
    """Return a reviewable base-environment decision without model inference."""
    matches = _cpe_matches(bundle)
    version_evidence = machine_version_evidence(bundle)
    parsed = []
    for match in matches:
        cpe = _parse_cpe(match.get("criteria") or match.get("cpe23Uri") or "")
        if cpe:
            parsed.append((cpe, match))

    is_kernel = any(
        cpe["part"] == "o"
        and ((cpe["vendor"] == "linux" and cpe["product"] == "linux_kernel")
             or (cpe["vendor"] == "canonical" and cpe["product"] == "ubuntu_linux"))
        and match.get("vulnerable", True)
        for cpe, match in parsed
    ) or bool((_source(bundle, "Ubuntu Security Tracker") or {}).get("kernel_rows"))
    if is_kernel:
        selected = _kernel_environment(bundle, matches, version_evidence)
        if selected:
            return selected

    ubuntu_candidates = []
    for cpe, match in parsed:
        if cpe["part"] == "o" and cpe["vendor"] == "canonical" and cpe["product"] == "ubuntu_linux":
            version = cpe["version"]
            if re.fullmatch(r"\d{2}\.\d{2}", version or ""):
                ubuntu_candidates.append((version, match, cpe))
    if ubuntu_candidates:
        version, match, cpe = sorted(ubuntu_candidates, reverse=True)[0]
        suite = {"24.04": "noble", "22.04": "jammy", "20.04": "focal"}.get(version)
        is_vulnerable_match = match.get("vulnerable", True)
        return {
            "status": "selected",
            "os_family": "ubuntu",
            "os_version": version,
            "suite": suite,
            "architecture": "amd64",
            "selection_basis": "nvd-cpe",
            "selection_explanation": (
                "The Ubuntu release is explicit in an NVD operating-system CPE "
                f"used as {'the vulnerable product' if is_vulnerable_match else 'a platform condition'}."
            ),
            "platform_constraint": _range(match, cpe["version"]),
            "vulnerable_constraints": ({"operating_system": _range(match, cpe["version"])}
                                       if is_vulnerable_match else {}),
            "cpe_matches": matches,
            "machine_readable_version_evidence": version_evidence,
            "evidence_urls": [(_source(bundle, "NVD") or {}).get("url")],
        }

    product_names = sorted({
        f"{cpe['vendor']}:{cpe['product']}" for cpe, _ in parsed if cpe["part"] in {"a", "o"}
    })
    hint = (os_hint or "auto").lower()
    version_hint = (os_version_hint or "").strip()
    if hint != "auto" and version_hint:
        suite = ({"24.04": "noble", "22.04": "jammy", "20.04": "focal"}.get(version_hint)
                 if hint == "ubuntu" else None)
        return {
            "status": "selected",
            "os_family": hint,
            "os_version": version_hint,
            "suite": suite,
            "architecture": "amd64",
            "selection_basis": "user-supplied-platform",
            "selection_explanation": (
                "CPE evidence did not identify a complete image; the OS family and version were "
                "supplied explicitly by the researcher, never inferred by NLP."
            ),
            "affected_products": product_names,
            "cpe_matches": matches,
            "machine_readable_version_evidence": version_evidence,
            "evidence_urls": [url for url in [(_source(bundle, "NVD") or {}).get("url")] if url],
        }
    return {
        "status": "needs-input",
        "os_family": None if hint == "auto" else hint,
        "os_version": None,
        "suite": None,
        "architecture": "amd64",
        "selection_basis": "unresolved-cpe",
        "selection_explanation": (
            "The evidence identifies an affected product but not a complete base OS image. "
            "Choose the image in the existing VM infrastructure; the NLP model is not allowed to guess it."
        ),
        "affected_products": product_names,
        "cpe_matches": matches,
        "machine_readable_version_evidence": version_evidence,
        "evidence_urls": [url for url in [(_source(bundle, "NVD") or {}).get("url")] if url],
    }
