"""Kernel CVE resolution: extract fix metadata, cross-check against ground truth,
and COMPUTE the vulnerable build ref per branch.

Division of labour (same principle as the deterministic template):
  - the MODEL extracts introduced/fixed commits+versions from the advisory prose
  - OSV (primary) + NVD (cross-check) provide structured ground truth
  - the vulnerable ref is COMPUTED by domain.kernel, never guessed
Scoring compares the model's extraction to OSV ground truth.
"""
from ..domain import kernel


def _norm_commit(c: str) -> str:
    return (c or "").strip().lower()


def _short(c: str) -> str:
    c = _norm_commit(c)
    return c[:12] if len(c) >= 12 else c


def resolve(extracted: dict, osv_truth: dict, nvd_gt: dict | None, prefer_branch: str = "latest") -> dict:
    """Return the resolved kernel target + a comparison of model vs ground truth.

    extracted: model output for KERNEL_SCHEMA (introduced/fixes).
    osv_truth: adapters.osv.kernel_truth(...) output (primary ground truth).
    nvd_gt:    adapters.nvd.ground_truth(...) output (cross-check; may be None).
    """
    # --- branches + vulnerable refs computed from OSV version ranges (primary) ---
    branches = kernel.branches_from_ranges(osv_truth.get("version_ranges", []))
    chosen, reason = kernel.choose_branch(branches, prefer_branch)

    # --- score the MODEL's extraction against OSV ground truth ---
    truth_fixed_commits = {_short(c) for c in osv_truth.get("git_fixed", [])}
    truth_introduced = {_short(c) for c in osv_truth.get("git_introduced", [])}
    model_fixed_commits = {_short(f.get("commit")) for f in extracted.get("fixes", []) if f.get("commit")}
    model_introduced = _short(extracted.get("introduced_commit"))

    truth_fixed_versions = {b["fixed"] for b in branches if b.get("fixed")}
    model_fixed_versions = {(f.get("version") or "").strip() for f in extracted.get("fixes", []) if f.get("version")}

    # cross-check: does NVD's part/product agree it's a kernel (part 'o', product linux_kernel)?
    nvd_is_kernel = None
    if nvd_gt is not None:
        parts = nvd_gt.get("parts", [])
        prods = {p.get("product", "") for p in nvd_gt.get("products", [])}
        nvd_is_kernel = ("o" in parts) or ("linux_kernel" in prods)

    comparison = {
        "introduced_commit": {
            "extracted": model_introduced or None,
            "in_ground_truth": bool(model_introduced) and model_introduced in truth_introduced,
            "truth": sorted(truth_introduced),
        },
        "fixed_commits": {
            "extracted": sorted(model_fixed_commits),
            "truth": sorted(truth_fixed_commits),
            "matched": sorted(model_fixed_commits & truth_fixed_commits),
            "recall": (len(model_fixed_commits & truth_fixed_commits) / len(truth_fixed_commits)) if truth_fixed_commits else None,
        },
        "fixed_versions": {
            "extracted": sorted(model_fixed_versions),
            "truth": sorted(truth_fixed_versions),
            "matched": sorted(model_fixed_versions & truth_fixed_versions),
        },
        "nvd_crosscheck": {"is_kernel": nvd_is_kernel},
    }

    return {
        "branches": branches,
        "chosen_branch": chosen,
        "chosen_reason": reason,
        "vulnerable_ref": chosen["vulnerable_ref"] if chosen else None,
        "comparison": comparison,
        "ground_truth_source": "osv" + ("+nvd" if nvd_gt is not None else ""),
    }
