"""Kernel version + vulnerable-ref logic. PURE (no I/O).

The core research distinction for kernel CVEs: an advisory gives an *introducing*
commit/version and one-or-more *fixing* commits/versions (one per stable branch).
The thing we must BUILD is a ref that is after the bug and before the fix — a
*vulnerable* ref. That ref is COMPUTED here from extracted/ground-truth data,
never hallucinated by the model.

A "branch" is one (introduced, fixed) pair, e.g. (6.16, 6.18.22). The vulnerable
build target for that branch is the last tag strictly below the fix, i.e.
v<fixed with its last component decremented> (6.18.22 -> v6.18.21).
"""
import re


def parse_version(v: str):
    """'6.18.22' -> (6,18,22); '6.1' -> (6,1); tolerant of a leading 'v' and
    of -rcN / trailing suffixes (suffix captured separately)."""
    s = (v or "").strip().lstrip("vV")
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", s)
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    return nums


def _branch_key(introduced: str, fixed: str) -> str:
    """A human label for a branch, e.g. '6.18.x' from fixed=6.18.22."""
    fp = parse_version(fixed)
    if fp and len(fp) >= 2:
        return f"{fp[0]}.{fp[1]}.x"
    ip = parse_version(introduced)
    if ip and len(ip) >= 2:
        return f"{ip[0]}.{ip[1]}.x"
    return "unknown"


def previous_tag(fixed_version: str):
    """The last vulnerable tag below a fix version.
    '6.18.22' -> 'v6.18.21'; '6.1.74' -> 'v6.1.73'; '5.4.229' -> 'v5.4.228'.
    If the fix is a .0 / x.y (branch base), stepping below it crosses branches,
    which is not a valid same-branch vulnerable tag -> return None (caller skips).
    Also None for -rc fixes (handled by caller)."""
    p = parse_version(fixed_version)
    if not p:
        return None
    # Only a full stable release x.y.z has a same-branch predecessor. A two-part
    # version (x.y) is a branch base (x.y == x.y.0); stepping it crosses branches
    # (6.8 -> 6.7), so there is no valid same-branch vulnerable tag below it.
    if len(p) < 3:
        return None
    last = p[-1]
    if last <= 0:
        return None
    stepped = p[:-1] + (last - 1,)
    return "v" + ".".join(str(n) for n in stepped)


def branches_from_ranges(ranges):
    """ranges: list of {'introduced':..,'fixed':..} (OSV ECOSYSTEM-style).
    Returns branch dicts with a computed vulnerable_ref (or a reason it's absent)."""
    out = []
    for r in ranges:
        introduced = r.get("introduced") or ""
        fixed = r.get("fixed") or ""
        b = {
            "branch": _branch_key(introduced, fixed),
            "introduced": introduced,
            "fixed": fixed,
            "vulnerable_ref": None,
            "note": "",
        }
        if not fixed:
            b["note"] = "no fixed version in this range"
        elif "rc" in fixed.lower():
            b["note"] = f"fix landed in a pre-release ({fixed}); pick a tag manually"
        else:
            tag = previous_tag(fixed)
            tag_version, introduced_version = parse_version(tag), parse_version(introduced)
            if tag and introduced_version and tag_version < introduced_version:
                b["note"] = (f"candidate {tag} predates introduction {introduced}; "
                             "no released vulnerable tag in this range")
            elif tag:
                b["vulnerable_ref"] = tag
            else:
                b["note"] = f"fix {fixed} is a branch base; no same-branch vulnerable tag below it"
        out.append(b)
    # de-dupe by (introduced, fixed)
    seen, uniq = set(), []
    for b in out:
        k = (b["introduced"], b["fixed"])
        if k not in seen:
            seen.add(k)
            uniq.append(b)
    return uniq


def choose_branch(branches, prefer: str = "latest"):
    """Pick one branch. prefer: 'latest' (highest fixed version), 'oldest',
    or an explicit branch label like '6.18.x'. Returns (branch|None, reason)."""
    usable = [b for b in branches if b.get("vulnerable_ref")]
    if not usable:
        return None, "no branch yielded a computable vulnerable ref"
    if prefer not in ("latest", "oldest"):
        for b in usable:
            if b["branch"] == prefer or b["fixed"].startswith(prefer.rstrip("x").rstrip(".")):
                return b, f"selected branch {b['branch']}"
        return None, f"requested branch {prefer!r} not among {[b['branch'] for b in usable]}"
    keyed = sorted(usable, key=lambda b: parse_version(b["fixed"]) or ())
    chosen = keyed[-1] if prefer == "latest" else keyed[0]
    return chosen, f"selected {prefer} branch {chosen['branch']}"
