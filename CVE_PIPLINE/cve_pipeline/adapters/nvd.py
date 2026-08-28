"""NVD 2.0 API adapter: fetch a record, pull the description, derive CPE ground truth."""
import json
import re
import urllib.request

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def _cid(cve_id: str) -> str:
    c = cve_id.strip().upper()
    return c if c.startswith("CVE-") else "CVE-" + c


def fetch_record(cve_id: str, api_key: str | None = None, timeout: int = 30) -> dict:
    req = urllib.request.Request(_API + _cid(cve_id), headers={"User-Agent": "cve-pipeline"})
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def description(record: dict) -> str:
    vulns = record.get("vulnerabilities") or []
    if not vulns:
        raise ValueError("No NVD record / vulnerabilities in response")
    for d in vulns[0]["cve"]["descriptions"]:
        if d.get("lang") == "en":
            return d["value"]
    return vulns[0]["cve"]["descriptions"][0]["value"]


def _range_from_match(m: dict, version: str) -> str:
    lo_i, lo_e = m.get("versionStartIncluding"), m.get("versionStartExcluding")
    hi_i, hi_e = m.get("versionEndIncluding"), m.get("versionEndExcluding")
    if not any([lo_i, lo_e, hi_i, hi_e]):
        return f"=={version}" if version and version != "*" else ""
    parts = []
    if lo_i: parts.append(f">={lo_i}")
    if lo_e: parts.append(f">{lo_e}")
    if hi_i: parts.append(f"<={hi_i}")
    if hi_e: parts.append(f"<{hi_e}")
    return ",".join(parts)


def ground_truth(record: dict) -> dict:
    cve = (record.get("vulnerabilities") or [{}])[0].get("cve", {})
    products, ranges = [], []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                bits = m.get("criteria", "").split(":")
                if len(bits) < 6:
                    continue
                products.append({"part": bits[2], "vendor": bits[3], "product": bits[4]})
                r = _range_from_match(m, bits[5])
                if r:
                    ranges.append(r)
    seen, uniq_p = set(), []
    for p in products:
        k = (p["part"], p["vendor"], p["product"])
        if k not in seen:
            seen.add(k); uniq_p.append(p)
    return {
        "products": uniq_p,
        "version_ranges": list(dict.fromkeys(ranges)),
        "parts": sorted({p["part"] for p in uniq_p}),
        "cpe_count": len(products),
    }
