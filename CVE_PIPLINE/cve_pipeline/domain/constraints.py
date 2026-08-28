"""Version-constraint parsing shared by the generators and the evaluator.

A constraint string looks like "==2.3.4", "<6.0.0", or ">=4.14,<6.18.22".
"""
import re

_TOKEN = re.compile(r"(==|>=|<=|>|<)?\s*([A-Za-z0-9][\w.\-+~]*)$")


def classify(constraint: str) -> dict:
    """Coarse classification used by installers: exact / range / none."""
    s = (constraint or "").strip()
    if not s:
        return {"kind": "none"}
    m = re.match(r"^(?:==|=)?\s*([A-Za-z0-9][\w.\-]*)$", s)
    if m:
        return {"kind": "exact", "version": m.group(1)}
    return {"kind": "range"}


def bounds(constraint: str) -> dict:
    """Decompose a constraint into named bounds (string equality, no ordering)."""
    b = {"min_inc": None, "min_exc": None, "max_inc": None, "max_exc": None, "exact": None}
    for tok in re.split(r"\s*,\s*", (constraint or "").strip()):
        tok = tok.strip()
        if not tok:
            continue
        m = _TOKEN.match(tok)
        if not m:
            continue
        op, ver = m.group(1), m.group(2)
        if op in (None, "=="):
            b["exact"] = ver
        elif op == ">=":
            b["min_inc"] = ver
        elif op == ">":
            b["min_exc"] = ver
        elif op == "<=":
            b["max_inc"] = ver
        elif op == "<":
            b["max_exc"] = ver
    return b


def upper_bound(constraint: str):
    """The fix boundary — the version that separates vulnerable from patched."""
    b = bounds(constraint)
    return b["max_exc"] or b["max_inc"] or b["exact"]
