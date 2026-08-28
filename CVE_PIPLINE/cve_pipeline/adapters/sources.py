"""Authoritative CVE evidence collection for reproducible Linux environments.

Machine-readable source fields feed deterministic environment selection. Textual
descriptions and bounded reference excerpts feed only configuration extraction.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds="
CVE_ORG_API = "https://cveawg.mitre.org/api/cve/"
OSV_API = "https://api.osv.dev/v1/vulns/"
DEBIAN_TRACKER = "https://security-tracker.debian.org/tracker/"
UBUNTU_TRACKER = "https://ubuntu.com/security/"
UBUNTU_TRACKER_GIT = (
    "https://git.launchpad.net/ubuntu-cve-tracker/plain/{bucket}/{cve}"
)
LAUNCHPAD_BINARY = "https://launchpad.net/ubuntu/{suite}/amd64/linux-image-generic"
LAUNCHPAD_PRIMARY_ARCHIVE = "https://api.launchpad.net/1.0/ubuntu/+archive/primary"
USER_AGENT = "cve-reproduction-pipeline/3.0 evidence collector"

# Only these first-party/government vulnerability services satisfy the
# generation provenance policy. Advisory links discovered inside a record are
# useful evidence, but they do not count toward the minimum because they may be
# arbitrary third-party URLs.
OFFICIAL_SOURCE_HOSTS = {
    "NVD": ("services.nvd.nist.gov",),
    "CVE.org / CNA record": ("cveawg.mitre.org",),
    "OSV": ("api.osv.dev",),
    "Debian Security Tracker": ("security-tracker.debian.org",),
    "Ubuntu Security Tracker": ("ubuntu.com", "git.launchpad.net"),
}
MINIMUM_OFFICIAL_SOURCES = 2
_EVIDENCE_FIELDS = (
    "description", "summary", "details", "excerpt", "affected",
    "cpe_matches", "kernel_rows", "selected_kernel",
)

_UBUNTU_LTS = (
    ("24.04", "noble"),
    ("22.04", "jammy"),
    ("20.04", "focal"),
)
_UBUNTU_TARGETS = _UBUNTU_LTS + (
    ("21.10", "impish"),
)


def normalize_cve_id(cve_id: str) -> str:
    cid = (cve_id or "").strip().upper()
    if not cid.startswith("CVE-"):
        cid = "CVE-" + cid
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
        raise ValueError(f"Invalid CVE id: {cve_id!r}")
    return cid


def manual_bundle(cve_id: str, description: str) -> dict:
    """Create evidence for explicitly supplied text without making network calls."""
    cid = normalize_cve_id(cve_id)
    bundle = {"cve": cid, "mode": "offline", "description": description or "",
              "sources": [], "errors": []}
    return annotate_official_source_policy(bundle)


def load_bundle(path: str, cve_id: str) -> dict:
    """Load an explicitly supplied saved evidence bundle with provenance."""
    cid = normalize_cve_id(cve_id)
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        bundle = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid source bundle JSON: {path}: {exc}") from exc
    if not isinstance(bundle, dict):
        raise ValueError("Source bundle must be a JSON object")
    bundle_cve = normalize_cve_id(bundle.get("cve") or "")
    if bundle_cve != cid:
        raise ValueError(f"Source bundle is for {bundle_cve}, not {cid}")
    if not isinstance(bundle.get("sources"), list):
        raise ValueError("Source bundle sources must be a list")
    replay = dict(bundle)
    replay["replayed_from"] = {
        "path": os.path.abspath(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return annotate_official_source_policy(replay)


def _official_url(name: str, url: str) -> bool:
    """Return true only for the allow-listed HTTPS endpoint for ``name``."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return False
    return parsed.scheme == "https" and any(
        host == allowed or host.endswith("." + allowed)
        for allowed in OFFICIAL_SOURCE_HOSTS.get(name, ())
    )


def _has_source_evidence(source: dict) -> bool:
    return any(source.get(field) for field in _EVIDENCE_FIELDS)


def validate_bundle_identity(bundle: dict, cve_id: str) -> str:
    """Require an in-memory/replayed bundle to identify the requested CVE."""
    if not isinstance(bundle, dict):
        raise ValueError("Source bundle must be a JSON object")
    requested = normalize_cve_id(cve_id)
    bundled = normalize_cve_id(bundle.get("cve") or "")
    if bundled != requested:
        raise ValueError(f"Source bundle is for {bundled}, not {requested}")
    return requested


def official_source_coverage(bundle: dict, minimum: int = MINIMUM_OFFICIAL_SOURCES) -> dict:
    """Recalculate, rather than trust, the official-source provenance summary."""
    accepted, rejected = [], []
    seen = set()
    bundled_cve = bundle.get("cve")
    try:
        bundled_cve = normalize_cve_id(bundled_cve) if bundled_cve else None
    except ValueError:
        bundled_cve = None
    for source in bundle.get("sources") or []:
        if not isinstance(source, dict):
            continue
        name = source.get("name", "")
        url = (source.get("fallback_url") if name == "Ubuntu Security Tracker"
               and source.get("fallback_url") else source.get("url", ""))
        if name not in OFFICIAL_SOURCE_HOSTS:
            continue
        targets_cve = (
            not bundled_cve
            or bundled_cve.casefold() in urllib.parse.unquote(str(url)).casefold()
        )
        if not _official_url(name, url) or not _has_source_evidence(source) or not targets_cve:
            rejected.append({"name": name, "url": url,
                             "reason": "wrong CVE, unrecognized official URL, or empty evidence"})
            continue
        if name not in seen:
            accepted.append({"name": name, "url": url})
            seen.add(name)
    attempted = list(dict.fromkeys(
        [item["name"] for item in accepted]
        + [item["name"] for item in rejected]
        + [error.get("source") for error in bundle.get("errors") or []
           if isinstance(error, dict) and error.get("source") in OFFICIAL_SOURCE_HOSTS]
    ))
    return {
        "policy": "multiple-recognized-official-sources",
        "minimum_required": minimum,
        "count": len(accepted),
        "satisfied": len(accepted) >= minimum,
        "accepted": accepted,
        "rejected": rejected,
        "attempted": attempted,
    }


def annotate_official_source_policy(bundle: dict,
                                    minimum: int = MINIMUM_OFFICIAL_SOURCES) -> dict:
    bundle["official_source_policy"] = official_source_coverage(bundle, minimum)
    return bundle


def require_multiple_official_sources(bundle: dict,
                                      minimum: int = MINIMUM_OFFICIAL_SOURCES) -> dict:
    """Fail closed unless multiple recognized official endpoints supplied evidence."""
    coverage = official_source_coverage(bundle, minimum)
    bundle["official_source_policy"] = coverage
    if coverage["satisfied"]:
        return coverage
    accepted = ", ".join(item["name"] for item in coverage["accepted"]) or "none"
    failed = ", ".join(
        error.get("source", "unknown") for error in bundle.get("errors") or []
        if isinstance(error, dict)
    ) or "none recorded"
    raise ValueError(
        f"Generation requires evidence from at least {minimum} recognized official sources; "
        f"received {coverage['count']} ({accepted}). Source failures: {failed}. "
        "Use --sources enrich with network access. Manual/offline descriptions do not "
        "satisfy the provenance policy."
    )


def _get_json(url: str, timeout: int, headers=None):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def _get_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode(errors="replace")


def _safe_reference_url(url: str) -> bool:
    """Reject local/file targets before following advisory reference URLs."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        hostname = parsed.hostname.lower().rstrip(".")
        if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
            return False
        try:
            address = ipaddress.ip_address(hostname)
            return not (address.is_private or address.is_loopback or address.is_link_local
                        or address.is_reserved or address.is_multicast)
        except ValueError:
            return True
    except (TypeError, ValueError):
        return False


def _reference_excerpt(url: str, timeout: int, byte_limit=262144) -> dict:
    if not _safe_reference_url(url):
        raise ValueError("reference URL is not a public HTTP(S) target")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=min(timeout, 8)) as response:
        content_type = (response.headers.get("Content-Type") or "").lower()
        if not any(kind in content_type for kind in ("text/", "json", "xml")):
            raise ValueError(f"unsupported reference content type: {content_type or 'unknown'}")
        raw = response.read(byte_limit + 1)
        if len(raw) > byte_limit:
            raw = raw[:byte_limit]
        text = raw.decode(errors="replace")
    excerpt = _html_excerpt(text, limit=5000)
    if not excerpt:
        raise ValueError("reference contained no extractable text")
    return {"url": url, "excerpt": excerpt, "content_type": content_type}


def _collect_reference_evidence(source_items: list[dict], timeout: int, maximum=3) -> tuple[list[dict], list[dict]]:
    candidates = _dedupe_urls(
        reference
        for source in source_items
        for reference in (source.get("references") or [])
    )
    evidence, errors = [], []
    for url in candidates:
        if len(evidence) >= maximum:
            break
        try:
            evidence.append(_reference_excerpt(url, timeout))
        except Exception as exc:
            errors.append({"source": "Advisory reference", "url": url, "error": str(exc)[:240]})
    return evidence, errors[:10]


def _get_text_retry(url: str, timeout: int, attempts=3) -> str:
    """Retry transient tracker failures, but never retry a permanent 4xx."""
    last_error = None
    for attempt in range(attempts):
        try:
            return _get_text(url, timeout)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if isinstance(exc, urllib.error.HTTPError) and 400 <= exc.code < 500:
                break
            if attempt + 1 < attempts:
                time.sleep(min(2 ** attempt, 2))
    raise last_error


def _english_description(descriptions) -> str:
    for item in descriptions or []:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    return (descriptions or [{}])[0].get("value", "")


def _dedupe_urls(values) -> list[str]:
    urls, seen = [], set()
    for value in values or []:
        url = value.get("url") if isinstance(value, dict) else value
        if url and url not in seen:
            urls.append(url)
            seen.add(url)
    return urls[:50]


def _cpe_matches(nodes) -> list[dict]:
    matches = []
    for node in nodes or []:
        for item in node.get("cpeMatch") or []:
            normalized = {key: item[key] for key in (
                "criteria", "cpe23Uri", "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding",
            ) if item.get(key)}
            normalized["vulnerable"] = bool(item.get("vulnerable"))
            if normalized.get("criteria") or normalized.get("cpe23Uri"):
                matches.append(normalized)
        matches.extend(_cpe_matches(node.get("nodes")))
    return matches[:100]


def _html_excerpt(raw: str, limit=1200) -> str:
    text = re.sub(r"(?is)<(?:script|style).*?>.*?</(?:script|style)>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()[:limit]


def _nvd_source(cve_id: str, api_key: str | None, timeout: int) -> dict:
    headers = {"apiKey": api_key} if api_key else None
    data = _get_json(NVD_API + urllib.parse.quote(cve_id), timeout, headers)
    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        raise ValueError(f"No NVD record found for {cve_id}")
    cve = vulnerabilities[0].get("cve") or {}
    return {
        "name": "NVD", "url": NVD_API + urllib.parse.quote(cve_id),
        "description": _english_description(cve.get("descriptions")),
        "references": _dedupe_urls(cve.get("references")),
        "cpe_matches": _cpe_matches(cve.get("configurations")),
        "published": cve.get("published"), "last_modified": cve.get("lastModified"),
    }


def _cve_org_source(cve_id: str, timeout: int) -> dict:
    record = _get_json(CVE_ORG_API + urllib.parse.quote(cve_id), timeout)
    cna = (record.get("containers") or {}).get("cna") or {}
    affected = [{key: item[key] for key in ("vendor", "product", "packageName", "collectionURL", "versions")
                 if item.get(key)} for item in cna.get("affected") or []]
    return {
        "name": "CVE.org / CNA record", "url": CVE_ORG_API + urllib.parse.quote(cve_id),
        "description": _english_description(cna.get("descriptions")),
        "references": _dedupe_urls(cna.get("references")), "affected": affected[:50],
    }


def _osv_source(cve_id: str, timeout: int) -> dict:
    record = _get_json(OSV_API + urllib.parse.quote(cve_id), timeout)
    affected = []
    for item in record.get("affected") or []:
        package = item.get("package") or {}
        affected.append({"package": package.get("name"), "ecosystem": package.get("ecosystem"),
                         "ranges": item.get("ranges") or [], "versions": item.get("versions") or []})
    return {
        "name": "OSV", "url": OSV_API + urllib.parse.quote(cve_id),
        "summary": record.get("summary", ""), "details": (record.get("details") or "")[:2000],
        "references": _dedupe_urls(record.get("references")), "affected": affected[:50],
    }


def _tracker_source(name: str, url: str, timeout: int) -> dict:
    text = _html_excerpt(_get_text(url, timeout), limit=12000)
    if name == "Ubuntu Security Tracker":
        # Canonical's page has substantial navigation/notification boilerplate
        # before the package status table. Preserve the table because it carries
        # the distro release and exact fixed kernel revisions needed by extraction.
        marker = "Package Ubuntu Release Status"
        start = text.find(marker)
        excerpt = text[start:start + 2600] if start >= 0 else text[:1200]
    else:
        excerpt = text[:1200]
    return {"name": name, "url": url, "excerpt": excerpt}


def _ubuntu_kernel_rows(text: str) -> list[dict]:
    """Parse Canonical's main ``linux`` rows without assuming its first release."""
    match = re.search(
        r"(?:^|\s)linux\s+(?=\d{2}\.\d{2}(?:\s+LTS)?\s+[a-z]+\s+)",
        text,
    )
    if not match:
        return []
    block = text[match.start():]
    next_package = re.search(r"\s+linux-[a-z0-9]", block[1:])
    if next_package:
        block = block[:next_package.start() + 1]
    rows = []
    for version, suite in _UBUNTU_TARGETS:
        release = re.search(
            rf"\b{re.escape(version)}(?:\s+LTS)?\s+{suite}\s+",
            block,
        )
        if not release:
            continue
        tail = block[release.end():]
        fixed = re.match(r"Fixed\s+(\S+)", tail)
        if fixed:
            rows.append({"version": version, "suite": suite, "status": "Fixed",
                         "fixed_version": fixed.group(1)})
        elif tail.startswith("Not affected"):
            rows.append({"version": version, "suite": suite, "status": "Not affected"})
        elif tail.startswith("Vulnerable"):
            rows.append({"version": version, "suite": suite, "status": "Vulnerable"})
    return rows


def _ubuntu_git_rows(raw: str) -> list[dict]:
    """Parse main-kernel rows from Canonical's authoritative tracker Git file."""
    rows = []
    for version, suite in _UBUNTU_TARGETS:
        match = re.search(rf"(?m)^{re.escape(suite)}_linux:\s+([^\r\n]+)", raw)
        if not match:
            continue
        value = match.group(1).strip()
        released = re.match(r"released\s+\(([^)]+)\)", value)
        if released:
            rows.append({
                "version": version,
                "suite": suite,
                "status": "Fixed",
                "fixed_version": released.group(1),
            })
        elif value.startswith("not-affected"):
            rows.append({"version": version, "suite": suite, "status": "Not affected"})
        elif value.startswith(("needed", "needs-triage", "pending", "deferred")):
            rows.append({"version": version, "suite": suite, "status": "Vulnerable"})
    return rows


def _ubuntu_git_source(cve_id: str, timeout: int) -> tuple[list[dict], str]:
    errors = []
    for bucket in ("active", "retired"):
        url = UBUNTU_TRACKER_GIT.format(bucket=bucket, cve=cve_id)
        try:
            rows = _ubuntu_git_rows(_get_text_retry(url, timeout, attempts=2))
            if rows:
                return rows, url
            errors.append(f"{bucket}: main linux rows were absent")
        except Exception as exc:
            errors.append(f"{bucket}: {exc}")
    raise ValueError("Ubuntu tracker Git fallback failed: " + "; ".join(errors))


def _version_abi(version: str) -> tuple[str, int] | None:
    match = re.match(r"^(\d+\.\d+\.\d+)[.-](\d+)[.-]", version or "")
    return (match.group(1), int(match.group(2))) if match else None


def _natural_version_key(value: str):
    return tuple(int(part) if part.isdigit() else part
                 for part in re.split(r"(\d+)", value))


def _launchpad_versions(suite: str, timeout: int) -> tuple[set[str], str]:
    url = LAUNCHPAD_BINARY.format(suite=suite)
    raw = _get_text_retry(url, timeout)
    versions = {
        urllib.parse.unquote(value)
        for value in re.findall(
            rf"/ubuntu/{re.escape(suite)}/amd64/linux-image-generic/([^\"?#<]+)", raw
        )
    }
    if not versions:
        raise ValueError(f"Launchpad listed no linux-image-generic publications for {suite}")
    return versions, url


def _launchpad_active_versions(suite: str, timeout: int) -> tuple[set[str], str]:
    """Return exact meta-package versions still published in normal APT pockets."""
    versions = set()
    for pocket in ("Release", "Updates", "Security"):
        query = urllib.parse.urlencode({
            "ws.op": "getPublishedBinaries",
            "binary_name": "linux-image-generic",
            "distro_arch_series": f"https://api.launchpad.net/1.0/ubuntu/{suite}/amd64",
            "exact_match": "true",
            "status": "Published",
            "pocket": pocket,
        })
        data = _get_json(f"{LAUNCHPAD_PRIMARY_ARCHIVE}?{query}", timeout)
        for entry in data.get("entries") or []:
            if (
                entry.get("binary_package_name") == "linux-image-generic"
                and entry.get("status") == "Published"
                and entry.get("pocket") == pocket
                and entry.get("binary_package_version")
            ):
                versions.add(entry["binary_package_version"])
    if not versions:
        raise ValueError(
            f"Launchpad API listed no active linux-image-generic publication for {suite}"
        )
    return versions, LAUNCHPAD_PRIMARY_ARCHIVE


def _launchpad_kernel_target(
    suite: str, concrete_fixed: str, timeout: int
) -> tuple[str, dict, str]:
    """Resolve the fixed meta boundary and one exact earlier kernel target.

    Canonical's CVE tracker gives the fixed concrete kernel package version.
    Launchpad's binary-publication page supplies the corresponding fixed
    meta-package version. Its machine-readable API supplies versions whose
    status is still Published in Release, Updates, or Security. We choose the
    newest active ABI strictly before the fixed ABI, which avoids a candidate
    predating the affected interval while remaining available to normal APT.
    """
    versions, url = _launchpad_versions(suite, timeout)
    concrete_abi = _version_abi(concrete_fixed)
    if concrete_abi is None:
        raise ValueError(f"Canonical fixed kernel version is not understood: {concrete_fixed}")
    matches = [version for version in versions if _version_abi(version) == concrete_abi]
    if not matches:
        raise ValueError(
            f"Launchpad has no linux-image-generic publication matching {concrete_fixed}"
        )
    meta_fixed = min(matches, key=_natural_version_key)
    base, fixed_abi = concrete_abi
    active_versions, api_url = _launchpad_active_versions(suite, timeout)
    vulnerable = [
        version for version in active_versions
        if (parsed := _version_abi(version)) is not None
        and parsed[0] == base
        and parsed[1] < fixed_abi
    ]
    if not vulnerable:
        raise ValueError(
            "Launchpad has no earlier linux-image-generic ABI from which to choose "
            f"a concrete vulnerable target before {concrete_fixed}"
        )
    meta_version = max(vulnerable, key=_natural_version_key)
    _, abi = _version_abi(meta_version)
    kernel_release = f"{base}-{abi}-generic"
    candidate = {
        "meta_package": "linux-image-generic",
        "meta_package_version": meta_version,
        "concrete_package": f"linux-image-{kernel_release}",
        "running_kernel_release": kernel_release,
        "selection_policy": (
            "newest Launchpad API publication with status Published in a normal "
            "APT pocket that is strictly before Canonical's fixed ABI"
        ),
        "publication_url": api_url,
    }
    return meta_fixed, candidate, url


def _launchpad_meta_fixed(suite: str, concrete_fixed: str, timeout: int) -> tuple[str, str]:
    """Compatibility helper retained for callers that need only the boundary."""
    meta_fixed, _candidate, url = _launchpad_kernel_target(
        suite, concrete_fixed, timeout
    )
    return meta_fixed, url


def _ubuntu_source(cve_id: str, timeout: int) -> dict:
    url = UBUNTU_TRACKER + cve_id
    table = ""
    rows = []
    web_error = ""
    fallback_url = ""
    try:
        text = _html_excerpt(_get_text_retry(url, timeout), limit=20000)
        marker = "Package Ubuntu Release Status"
        start = text.find(marker)
        table = text[start:] if start >= 0 else text
        rows = _ubuntu_kernel_rows(table)
    except Exception as exc:
        web_error = str(exc)[:240]
    if not rows:
        rows, fallback_url = _ubuntu_git_source(cve_id, timeout)
    source = {
        "name": "Ubuntu Security Tracker",
        "url": url,
        "excerpt": table[:4000],
        "kernel_rows": rows,
    }
    if fallback_url:
        source["fallback_url"] = fallback_url
    if web_error:
        source["web_error"] = web_error
    selected = next((row for row in rows if row.get("status") == "Fixed"), None)
    if selected:
        selected = dict(selected)
        try:
            meta_fixed, vulnerable_candidate, meta_url = _launchpad_kernel_target(
                selected["suite"], selected["fixed_version"], timeout
            )
            selected.update({
                "package": "linux-image-generic",
                "meta_fixed_version": meta_fixed,
                "meta_url": meta_url,
                "vulnerable_candidate": vulnerable_candidate,
            })
        except Exception as exc:
            selected["meta_error"] = str(exc)[:240]
        source["selected_kernel"] = selected
        source["selection_policy"] = (
            "newest affected supported Ubuntu LTS, then an exact earlier "
            "Launchpad kernel publication"
        )
    return source

def collect(cve_id: str, nvd_api_key: str | None = None, mode="enrich", timeout=15) -> dict:
    """Collect evidence. Modes: enrich, nvd, or offline (no network)."""
    cid = normalize_cve_id(cve_id)
    if mode not in {"enrich", "nvd", "offline"}:
        raise ValueError("source mode must be enrich, nvd, or offline")
    bundle = {"cve": cid, "mode": mode, "description": "", "sources": [], "errors": []}
    if mode == "offline":
        return annotate_official_source_policy(bundle)
    fetchers = [("NVD", lambda: _nvd_source(cid, nvd_api_key, timeout))]
    if mode == "enrich":
        fetchers += [
            ("CVE.org / CNA record", lambda: _cve_org_source(cid, timeout)),
            ("OSV", lambda: _osv_source(cid, timeout)),
            ("Debian Security Tracker", lambda: _tracker_source("Debian Security Tracker", DEBIAN_TRACKER + cid, timeout)),
            ("Ubuntu Security Tracker", lambda: _ubuntu_source(cid, timeout)),
        ]
    for name, fetch in fetchers:
        try:
            source = fetch()
            bundle["sources"].append(source)
            if not bundle["description"]:
                bundle["description"] = next((
                    source.get(field) for field in ("description", "summary", "details", "excerpt")
                    if isinstance(source.get(field), str) and source.get(field).strip()
                ), "")
        except Exception as exc:  # every source is optional; retain the failure for review
            bundle["errors"].append({"source": name, "error": str(exc)[:240]})
    if mode == "enrich":
        reference_evidence, reference_errors = _collect_reference_evidence(bundle["sources"], timeout)
        bundle["reference_evidence"] = reference_evidence
        bundle["errors"].extend(reference_errors)
    return annotate_official_source_policy(bundle)


def prompt_evidence(bundle: dict, max_chars=7000, *, include_machine_data=False) -> str:
    """Create bounded, source-labelled evidence for an extraction model.

    CPE and affected-version arrays drive deterministic selection and are not
    configuration evidence.  Excluding them by default leaves room for the
    descriptive and advisory-reference text the configuration model needs.
    """
    lines = ["Authoritative source evidence (use only when explicit; do not guess or merge conflicting versions):"]
    priority = {
        "Ubuntu Security Tracker": 0,
        "Debian Security Tracker": 1,
        "NVD": 2,
        "CVE.org / CNA record": 3,
        "OSV": 4,
    }
    # Technical advisory excerpts are collected specifically because short CVE
    # records often omit reachability/configuration prerequisites. Put them
    # first so the global character bound cannot trim them after large tracker
    # tables or reference URL lists.
    for reference in bundle.get("reference_evidence") or []:
        lines.append(f"- Citation source (copy exactly): {reference['url']}")
        lines.append("  advisory reference excerpt: " + reference.get("excerpt", "")[:1600])
    ordered = sorted(bundle.get("sources") or [],
                     key=lambda source: priority.get(source.get("name"), 99))
    for source in ordered:
        lines.append(f"- Citation source (copy exactly): {source['name']}")
        lines.append(f"  URL (also accepted as citation source): {source['url']}")
        keys = ["description", "summary", "details", "excerpt"]
        if include_machine_data:
            keys.extend(("cpe_matches", "affected"))
        for key in keys:
            value = source.get(key)
            if value:
                rendered = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
                lines.append(f"  {key}: {rendered[:1200]}")
        if source.get("references"):
            lines.append("  reference URLs (not evidence unless excerpted below): "
                         + ", ".join(source["references"][:6]))
    return "\n".join(lines)[:max_chars]


def _source(bundle: dict, name: str) -> dict | None:
    for item in bundle.get("sources") or []:
        if item.get("name") == name:
            return item
    return None


def _range_from_cpe(match: dict, version: str) -> str:
    lo_i, lo_e = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    hi_i, hi_e = match.get("versionEndIncluding"), match.get("versionEndExcluding")
    if not any((lo_i, lo_e, hi_i, hi_e)):
        return f"=={version}" if version and version != "*" else ""
    parts = []
    if lo_i: parts.append(f">={lo_i}")
    if lo_e: parts.append(f">{lo_e}")
    if hi_i: parts.append(f"<={hi_i}")
    if hi_e: parts.append(f"<{hi_e}")
    return ",".join(parts)


def nvd_ground_truth(bundle: dict) -> dict | None:
    """Derive comparison data from the NVD evidence already fetched once."""
    source = _source(bundle, "NVD")
    if not source:
        return None
    products, ranges = [], []
    for match in source.get("cpe_matches") or []:
        if match.get("vulnerable") is False:
            continue
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        bits = criteria.split(":")
        if len(bits) < 6:
            continue
        product = {"part": bits[2], "vendor": bits[3], "product": bits[4]}
        products.append(product)
        value = _range_from_cpe(match, bits[5])
        if value:
            ranges.append(value)
    seen, unique = set(), []
    for product in products:
        key = (product["part"], product["vendor"], product["product"])
        if key not in seen:
            seen.add(key)
            unique.append(product)
    return {"products": unique, "version_ranges": list(dict.fromkeys(ranges)),
            "parts": sorted({p["part"] for p in unique}), "cpe_count": len(products)}


def osv_record(bundle: dict) -> dict | None:
    """Rehydrate the normalized OSV evidence for the kernel truth parser."""
    source = _source(bundle, "OSV")
    return {"affected": source.get("affected") or []} if source else None


def reproduction_hints(spec: dict) -> list[dict]:
    """Return review links for real distro package revisions; never pin a version."""
    package = (spec.get("package") or "").strip()
    if not package or (spec.get("package_manager") or "apt") != "apt":
        return []
    family, quoted = (spec.get("os_family") or "").lower(), urllib.parse.quote(package, safe="+.-")
    if family == "debian":
        return [{"name": "Debian Snapshot package history", "url": f"https://snapshot.debian.org/package/{quoted}/"}]
    if family == "ubuntu":
        return [
            {"name": "Ubuntu source package history", "url": f"https://launchpad.net/ubuntu/+source/{quoted}"},
            {"name": "Ubuntu old releases archive", "url": "https://old-releases.ubuntu.com/ubuntu/"},
        ]
    return []


