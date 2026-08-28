"""spec -> bash. Pure."""
import base64
import re
from ..constraints import bounds, classify
from ..sanitize import clean_setup_commands

LINEINFILE_HELPER = base64.b64decode(
    "ZnVuY3Rpb24gbGluZWluZmlsZSgpIHsgbGluZT0kezIvL1wvL1xcL30gOyBzZWQgLWkgLWUgJy8nIiR7MS8vXC8vXFwvfSInL3tzLy4qLyciJHtsaW5lfSInLzs6YTtuO2JhO3F9OyRhJyIke2xpbmV9IiAiJDMiIDsgfQ=="
).decode()


def _apt_range_install(pkg: str, constraint: str) -> list[str]:
    """Select an exact available Debian version inside a vulnerable range."""
    b = bounds(constraint)
    checks = []
    for key, op in (("min_inc", "ge"), ("min_exc", "gt"),
                    ("max_inc", "le"), ("max_exc", "lt")):
        if b.get(key):
            checks.append(f'dpkg --compare-versions "$_cve_v" {op} {b[key]!r}')
    if not checks:
        return [f'echo "ERROR: unsupported APT version constraint: {constraint}" >&2', "exit 42"]
    condition = " && ".join(checks)
    return [
        'apt-get update -q',
        f'echo "Resolve an exact vulnerable version of {pkg} ({constraint})"',
        f'mapfile -t _cve_versions < <(apt-cache madison {pkg} | awk \'{{print $3}}\' | awk \'!seen[$0]++\')',
        '_CVE_APT_VERSION=""',
        'for _cve_v in "${_cve_versions[@]}"; do',
        f'  if {condition}; then _CVE_APT_VERSION="$_cve_v"; break; fi',
        'done',
        'if [ -z "$_CVE_APT_VERSION" ]; then',
        f'  echo "ERROR: no configured APT repository contains {pkg} in vulnerable range {constraint}" >&2',
        '  echo "Add the matching Ubuntu archive or Debian Snapshot repository, then rerun." >&2',
        '  exit 42',
        'fi',
        f'apt-get install -y -q {pkg}="$_CVE_APT_VERSION"',
        f'dpkg-query -W -f=\'${{Version}}\\n\' {pkg} | grep -Fx "$_CVE_APT_VERSION"',
    ]


def _install(spec):
    pkg = spec["package"]
    pm = spec["package_manager"] or "apt"
    c = (spec["version_constraint"] or "").strip()
    k = classify(c)
    if pm == "pip":
        spec_str = (c if re.match(r"^[<>=!~]", c) else "==" + c) if c else ""
        target = f'"{pkg}{spec_str}"' if spec_str else pkg
        return [f"python3 -m venv /opt/venv", "source /opt/venv/bin/activate", f"pip install {target}"]
    if pm == "dnf":
        if k["kind"] == "exact":
            return [f"dnf install -y {pkg}-{k['version']}"]
        if k["kind"] == "range":
            return [f"dnf install -y {pkg}", f"# vulnerable range {c}; dnf can't express it - pin below the fix."]
        return [f"dnf install -y {pkg}"]
    if k["kind"] == "exact":
        return ["apt-get update -q", f"apt-get install -y -q {pkg}={k['version']}", f"# verify: 'apt-cache madison {pkg}'."]
    if k["kind"] == "range":
        return _apt_range_install(pkg, c)
    return ["apt-get update -q", f"apt-get install -y -q {pkg}"]


def build(spec: dict) -> str:
    echo = lambda s: f'echo "{s}"'
    comment = lambda s: f"# {s}"
    L = ["#!/bin/bash -eux", echo("Install dependencies")]
    L += _install(spec)
    L += ["", LINEINFILE_HELPER]

    setup = clean_setup_commands(spec["setup_commands"], echo, comment)
    if setup:
        L.append("")
        L += setup

    if spec["service_name"]:
        L += ["", echo(f"stop {spec['service_name']}"), f"service {spec['service_name']} stop"]

    if spec["config_directives"] and spec["config_file"]:
        L.append("")
        for d in spec["config_directives"]:
            if not d.get("key"):
                continue
            L.append(echo(f"set {d['key']}"))
            L.append(f"lineinfile '{d['key']}' '{d['key']}={d.get('value','')}' {spec['config_file']}")
    elif spec["config_directives"] and not spec["config_file"]:
        L += ["", comment("WARNING: directives extracted but no config_file set - fill it in and regenerate.")]

    if spec["service_name"]:
        L += ["", echo(f"start {spec['service_name']}"), f"service {spec['service_name']} start"]

    if spec["start_command"]:
        L += ["", echo("start service"),
              comment("NOTE: run as a background/systemd service in a real build; inline would block the provisioner."),
              f"nohup {spec['start_command']} >/var/log/cve-service.log 2>&1 &"]
    return "\n".join(L) + "\n"
