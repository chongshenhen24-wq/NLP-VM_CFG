"""Compare a model spec to NVD/CPE ground truth. Pure (no I/O)."""
import re
from ..domain.constraints import upper_bound


def _tokens(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def compare(spec: dict, gt: dict) -> dict:
    ext = spec.get("version_constraint", "") or ""
    ext_upper = upper_bound(ext)
    truth_ranges = gt.get("version_ranges", [])
    truth_uppers = [u for u in (upper_bound(r) for r in truth_ranges) if u]

    ext_pkg = (spec.get("package") or "").lower()
    truth_products = sorted({p["product"].lower() for p in gt.get("products", [])})
    truth_terms = truth_products + sorted({p["vendor"].lower() for p in gt.get("products", [])})
    overlap = any(t in ext_pkg or ext_pkg in t or (_tokens(ext_pkg) & _tokens(t)) for t in truth_terms)

    parts = gt.get("parts", [])
    return {
        "version_constraint": {
            "extracted": ext, "truth_ranges": truth_ranges,
            "extracted_upper_bound": ext_upper, "truth_upper_bounds": truth_uppers,
            "upper_bound_match": bool(ext_upper) and ext_upper in truth_uppers,
            "exact_match": ext in truth_ranges,
        },
        "product": {"extracted_package": spec.get("package"), "truth_products": truth_products, "overlap": overlap},
        "cpe_parts": parts,
        "fits_pipeline": (("a" in parts) and ("o" not in parts)) if parts else None,
    }
