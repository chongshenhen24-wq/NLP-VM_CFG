"""Register a generated script into a machine's variables.pkrvars.hcl scripts list."""
import os
import re
import shutil


def register(hcl_path: str, cve_id: str, script_name: str) -> bool:
    """Compatibility wrapper for registering one generated script."""
    return register_many(hcl_path, cve_id, [script_name])


def register_many(hcl_path: str, cve_id: str, script_names: list[str]) -> bool:
    """Atomically register scripts in the supplied execution order.

    Kernel provisioning must precede extra configuration.  A single backup and
    rewrite avoids leaving only half of that pair registered.
    """
    with open(hcl_path, "r") as f:
        lines = f.read().splitlines()
    pending = [
        name for name in script_names
        if name and not any(f"machines/{cve_id}/{name}" in line for line in lines)
    ]
    if not pending:
        return False
    idx = -1
    for i, ln in enumerate(lines):
        if re.search(rf"machines/{re.escape(cve_id)}/", ln):
            idx = i
    if idx < 0:
        for i, ln in enumerate(lines):
            if re.search(r"scripts\s*=\s*\[", ln):
                idx = i
                break
    if idx < 0:
        raise ValueError(f"No 'scripts = [' block in {hcl_path}")
    shutil.copyfile(hcl_path, hcl_path + ".bak")
    for offset, script_name in enumerate(pending, start=1):
        lines.insert(idx + offset, f'"machines/{cve_id}/{script_name}",')
    with open(hcl_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return True
