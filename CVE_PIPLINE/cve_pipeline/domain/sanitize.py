"""Sanitizer: strip install/venv/service lines and unfilled placeholders that a
model wrongly places in setup_commands, so a misbehaving extraction can't inject
a duplicate or broken install into the generated script.
"""
import re

_INSTALL = re.compile(
    r"(?:^|[\s;&|(])(?:pip3?\s+install|python3?(?:\.exe)?\s+-m\s+pip\s+install|"
    r"apt(?:-get)?\s+install|(?:dnf|yum)\s+install|choco\s+install|winget\s+install)\b", re.I)
_VENV = re.compile(r"python3?(?:\.exe)?\s+-m\s+venv\b", re.I)
_ACTIVATE = re.compile(r"(?:^|[\s;&|])(?:source|\.)\s+\S*/(?:bin/)?activate\b|Activate\.ps1\b", re.I)
_SERVICE = re.compile(r"\b(?:service\s+\S+\s+(?:start|stop|restart)|systemctl\s+(?:start|stop|restart|enable))\b", re.I)
_PLACEHOLDER = re.compile(r"\$\(version\)|\$\{version\}|<\s*version\s*>", re.I)


def is_handled_elsewhere(cmd: str) -> bool:
    c = cmd or ""
    return bool(_INSTALL.search(c) or _VENV.search(c) or _ACTIVATE.search(c) or _SERVICE.search(c))


def has_placeholder(cmd: str) -> bool:
    return bool(_PLACEHOLDER.search(cmd or ""))


def clean_setup_commands(setup_commands, echo, comment):
    """Yield rendered lines for the setup commands. `echo` and `comment` are the
    per-shell line builders (bash vs powershell), so this stays shell-agnostic."""
    lines = []
    for cmd in setup_commands or []:
        raw = (cmd.get("command") or "")
        desc = (cmd.get("description") or "")
        if not raw and not desc:
            continue
        if is_handled_elsewhere(raw):
            lines.append(comment(f"skipped (install handled above): {desc or raw}"))
            continue
        if has_placeholder(raw):
            lines.append(comment("WARNING: setup step had an unfilled placeholder and was disabled:"))
            lines.append(comment(f"  {raw}"))
            continue
        if desc:
            lines.append(echo(desc))
        if raw:
            lines.append(raw)
    return lines
