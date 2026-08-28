"""Choose one concrete VM build target without using NLP.

The environment selector identifies an affected Ubuntu release and vulnerable
package boundaries.  This module turns that range into one reviewable kernel
release that the existing VM infrastructure can build.  It accepts only the
candidate attached to Canonical/Launchpad source evidence; it never guesses a
kernel from the prose description.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .environment import machine_version_evidence


def _source(bundle: dict, name: str) -> dict | None:
    return next(
        (item for item in bundle.get("sources") or [] if item.get("name") == name),
        None,
    )


def _kernel_release_parts(value: str) -> tuple[str, int] | None:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)-(\d+)-generic", value or "")
    return (match.group(1), int(match.group(2))) if match else None


def _package_abi(value: str) -> tuple[str, int] | None:
    match = re.match(r"^(\d+\.\d+\.\d+)[.-](\d+)[.-]", value or "")
    return (match.group(1), int(match.group(2))) if match else None


def _semver(value: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"v?(\d+(?:\.\d+){1,3})", (value or "").strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def _introduced_floors(bundle: dict) -> list[tuple[int, ...]]:
    floors = []
    nvd = _source(bundle, "NVD") or {}
    for match in nvd.get("cpe_matches") or []:
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        if ":linux:linux_kernel:" not in criteria or not match.get("vulnerable", True):
            continue
        for field in ("versionStartIncluding", "versionStartExcluding"):
            parsed = _semver(str(match.get(field) or ""))
            if parsed:
                floors.append(parsed)
    cna = _source(bundle, "CVE.org / CNA record") or {}
    for product in cna.get("affected") or []:
        label = " ".join(str(product.get(key) or "") for key in ("vendor", "product", "packageName"))
        if "linux" not in label.casefold():
            continue
        for version in product.get("versions") or []:
            if version.get("status") != "affected":
                continue
            parsed = _semver(str(version.get("version") or ""))
            if parsed:
                floors.append(parsed)
    osv = _source(bundle, "OSV") or {}
    for affected in osv.get("affected") or []:
        if "linux" not in str(affected.get("package") or "").casefold():
            continue
        for item in affected.get("ranges") or []:
            for event in item.get("events") or []:
                parsed = _semver(str(event.get("introduced") or ""))
                if parsed and any(parsed):
                    floors.append(parsed)
    return floors


def _version_at_least(candidate: tuple[int, ...], floor: tuple[int, ...]) -> bool:
    width = max(len(candidate), len(floor))
    return candidate + (0,) * (width - len(candidate)) >= floor + (0,) * (width - len(floor))


def select(bundle: dict, environment: dict) -> dict:
    """Return an exact build target, or a fail-closed unresolved decision."""
    base = {
        "status": "needs-input",
        "os_family": environment.get("os_family"),
        "os_version": environment.get("os_version"),
        "suite": environment.get("suite"),
        "architecture": environment.get("architecture"),
    }
    if environment.get("status") != "selected":
        return {
            **base,
            "reason": "The base operating-system selection is unresolved.",
        }
    constraints = environment.get("vulnerable_constraints") or {}
    meta_constraint = constraints.get("meta_package_constraint")
    concrete_constraint = constraints.get("running_kernel_package_constraint")
    if not meta_constraint and not concrete_constraint:
        return {
            **base,
            "status": "not-applicable",
            "reason": (
                "The selected record does not describe an Ubuntu kernel package; "
                "no concrete kernel target can be selected."
            ),
        }
    if not meta_constraint or not concrete_constraint:
        return {
            **base,
            "reason": (
                "Official Ubuntu package evidence did not resolve both the meta-package "
                "and concrete running-kernel boundaries."
            ),
            "vulnerable_constraints": constraints,
        }

    version_evidence = (
        environment.get("machine_readable_version_evidence")
        or machine_version_evidence(bundle)
    )
    if version_evidence.get("status") not in {
        "nvd-cpe", "structured-version-fallback",
    }:
        return {
            **base,
            "reason": (
                "Neither NVD CPE data nor official CNA/OSV structured affected-"
                "version data can establish a machine-readable vulnerable range."
            ),
            "machine_readable_version_evidence": version_evidence,
            "vulnerable_constraints": constraints,
        }

    ubuntu = _source(bundle, "Ubuntu Security Tracker") or {}
    selected = ubuntu.get("selected_kernel") or {}
    candidate = selected.get("vulnerable_candidate") or {}
    required = (
        "meta_package", "meta_package_version", "concrete_package",
        "running_kernel_release", "publication_url",
    )
    missing = [field for field in required if not candidate.get(field)]
    if missing:
        return {
            **base,
            "reason": (
                "Official package evidence did not provide a concrete vulnerable "
                "kernel publication; missing: " + ", ".join(missing)
            ),
            "vulnerable_constraints": constraints,
        }

    release_parts = _kernel_release_parts(candidate["running_kernel_release"])
    fixed_parts = _package_abi(selected.get("fixed_version") or "")
    meta_parts = _package_abi(candidate["meta_package_version"])
    expected_package = "linux-image-" + candidate["running_kernel_release"]
    publication = urlsplit(candidate.get("publication_url") or "")
    publication_host = (publication.hostname or "").casefold()
    if (
        release_parts is None
        or fixed_parts is None
        or meta_parts is None
        or release_parts != meta_parts
        or release_parts[0] != fixed_parts[0]
        or release_parts[1] >= fixed_parts[1]
        or candidate["concrete_package"] != expected_package
        or publication.scheme != "https"
        or not (
            publication_host == "launchpad.net"
            or publication_host.endswith(".launchpad.net")
        )
    ):
        return {
            **base,
            "reason": (
                "The official package candidate is internally inconsistent or is "
                "not strictly earlier than Canonical's fixed kernel ABI."
            ),
            "vulnerable_constraints": constraints,
        }
    candidate_upstream = _semver(release_parts[0])
    floors = _introduced_floors(bundle)
    if candidate_upstream and floors and not any(
        _version_at_least(candidate_upstream, floor) for floor in floors
    ):
        return {
            **base,
            "reason": (
                f"The selected kernel series {release_parts[0]} predates every "
                "machine-readable vulnerability introduction boundary."
            ),
            "vulnerable_constraints": constraints,
        }
    if (
        selected.get("version") != environment.get("os_version")
        or selected.get("suite") != environment.get("suite")
    ):
        return {
            **base,
            "reason": "The package candidate and selected Ubuntu image do not match.",
            "vulnerable_constraints": constraints,
        }

    return {
        **base,
        "status": "selected",
        "selection_basis": "canonical-tracker-and-launchpad-publication",
        "selection_explanation": (
            "Canonical supplies the fixed downstream boundary and Launchpad supplies "
            "the exact earlier meta-package publication. NLP did not participate."
        ),
        "kernel": {
            "meta_package": candidate["meta_package"],
            "meta_package_version": candidate["meta_package_version"],
            "concrete_package": candidate["concrete_package"],
            "running_kernel_release": candidate["running_kernel_release"],
            "meta_package_constraint": meta_constraint,
            "concrete_package_constraint": concrete_constraint,
        },
        "evidence_urls": list(dict.fromkeys(url for url in (
            ubuntu.get("url"), ubuntu.get("fallback_url"),
            candidate.get("publication_url"),
        ) if url)),
        "selection_policy": candidate.get("selection_policy"),
        "machine_readable_version_evidence": version_evidence,
        "availability_rule": (
            "The infrastructure must prove the exact meta-package is available before "
            "installation; absence is an unresolved build, never a READY environment."
        ),
    }
