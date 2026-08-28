"""OSV.dev adapter: structured introduced/fixed data for kernel CVEs.

OSV records carry two representations we use as ground truth:
  - GIT events:       introduced commit + fixed commit(s)  (mainline + stable)
  - ECOSYSTEM events: introduced/fixed VERSION ranges, one pair per stable branch
The ECOSYSTEM ranges are exactly the per-branch input the resolver needs.
"""
import json
import urllib.request

_API = "https://api.osv.dev/v1/vulns/"


def _cid(cve_id: str) -> str:
    c = cve_id.strip().upper()
    return c if c.startswith("CVE-") else "CVE-" + c


def fetch(cve_id: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(_API + _cid(cve_id), headers={"User-Agent": "cve-pipeline"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def kernel_truth(record: dict) -> dict:
    """Pull GIT commits and ECOSYSTEM version ranges from an OSV record."""
    git_introduced, git_fixed = [], []
    version_ranges = []          # list of {'introduced','fixed'}
    for aff in record.get("affected", []):
        for rng in aff.get("ranges", []):
            rtype = rng.get("type")
            introduced = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                    if rtype == "GIT" and ev["introduced"] not in ("0", ""):
                        git_introduced.append(ev["introduced"])
                fixed = ev.get("fixed")
                if fixed:
                    if rtype == "GIT":
                        git_fixed.append(fixed)
                    elif rtype == "ECOSYSTEM":
                        version_ranges.append({"introduced": introduced, "fixed": fixed})
    return {
        "git_introduced": list(dict.fromkeys(git_introduced)),
        "git_fixed": list(dict.fromkeys(git_fixed)),
        "version_ranges": version_ranges,
        "has_data": bool(version_ranges or git_fixed),
    }
