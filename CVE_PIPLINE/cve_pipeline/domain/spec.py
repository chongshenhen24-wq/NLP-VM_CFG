"""The Spec: a plain dict with a fixed shape (defined in schema.FIELDS).

Kept as a dict (not a dataclass) so it round-trips through JSON, the model, the
web form, and the log with zero friction. `normalize()` guarantees every field
is present and correctly typed, so no downstream code null-checks.
"""
import re

from .schema import FIELDS


def blank(os_fallback: str = "debian") -> dict:
    return {
        "package": "",
        "package_manager": "apt",
        "version_constraint": "",
        "concrete_kernel_constraint": "",
        "service_name": "",
        "start_command": "",
        "config_file": "",
        "os_family": os_fallback or "debian",
        "os_version": "",
        "config_directives": [],
        "setup_commands": [],
        "notes": "",
    }


def normalize(parsed: dict, os_fallback: str = "debian") -> dict:
    """Coerce raw model output into a complete, well-typed spec."""
    parsed = parsed or {}
    base = blank(os_fallback)
    out = {}
    for f in FIELDS:
        if f in ("config_directives", "setup_commands"):
            v = parsed.get(f)
            out[f] = v if isinstance(v, list) else []
        else:
            out[f] = parsed.get(f) or base[f]

    if (out.get("os_family") or "").strip().lower() == "ubuntu":
        value = str(out.get("os_version") or "").strip().lower()
        aliases = {
            "impish": "21.10",
            "focal": "20.04",
            "jammy": "22.04",
            "noble": "24.04",
        }
        match = re.search(r"(?<!\d)(20\.04|21\.10|22\.04|24\.04)(?!\d)", value)
        if match:
            out["os_version"] = match.group(1)
        else:
            for alias, version in aliases.items():
                if re.search(rf"\b{alias}\b", value):
                    out["os_version"] = version
                    break
    return out


def is_windows(spec: dict) -> bool:
    return (spec.get("os_family") or "").lower() == "windows"
