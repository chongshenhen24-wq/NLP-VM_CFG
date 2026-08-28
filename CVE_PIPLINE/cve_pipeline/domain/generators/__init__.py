"""Generators: spec -> provisioning script. Dispatch by OS family."""
from ..spec import is_windows
from . import bash, powershell


def build(spec: dict) -> str:
    return powershell.build(spec) if is_windows(spec) else bash.build(spec)


def filename(spec: dict, cve_id: str) -> str:
    import re
    base = re.sub(r"[^a-zA-Z0-9._-]", "_", cve_id or spec.get("package") or "setup")
    ext = "ps1" if is_windows(spec) else "sh"
    return f"setup_{base}.{ext}"
