"""spec -> PowerShell (.ps1) for Windows targets. Pure."""
import re
from ..constraints import classify
from ..sanitize import clean_setup_commands

PS_VENV = "C:\\cve-venv"

_HELPER = [
    "function Set-ConfigLine {",
    "    param([string]$Key, [string]$Value, [string]$Path)",
    '    $line = "$Key=$Value"',
    "    if (Test-Path $Path) {",
    "        $content = Get-Content $Path",
    "        $pattern = '^\\s*' + [regex]::Escape($Key) + '\\b.*'",
    "        if ($content -match $pattern) {",
    "            ($content -replace $pattern, $line) | Set-Content -Path $Path",
    "        } else { Add-Content -Path $Path -Value $line }",
    "    } else { Set-Content -Path $Path -Value $line }",
    "}",
]


def _install(spec):
    pkg = spec["package"]
    pm = spec["package_manager"] or "pip"
    c = (spec["version_constraint"] or "").strip()
    k = classify(c)
    if pm == "pip":
        spec_str = (c if re.match(r"^[<>=!~]", c) else "==" + c) if c else ""
        target = f'"{pkg}{spec_str}"' if spec_str else pkg
        return [f"python.exe -m venv {PS_VENV}", f"& {PS_VENV}\\Scripts\\Activate.ps1",
                f"python.exe -m pip install {target}"]
    if pm == "choco":
        ver = f" --version {k['version']}" if k["kind"] == "exact" else ""
        return [f"choco install {pkg} -y{ver}"]
    if pm == "winget":
        ver = f" --version {k['version']}" if k["kind"] == "exact" else ""
        return [f"winget install --id {pkg} -e{ver} --accept-package-agreements --accept-source-agreements"]
    return [f'# WARNING: package_manager "{pm}" is not a Windows installer. Install {pkg} manually.']


def build(spec: dict) -> str:
    echo = lambda s: f'Write-Host "{s}"'
    comment = lambda s: f"# {s}"
    L = ["#Requires -Version 5.0", "# Run with: powershell -ExecutionPolicy Bypass -File <this>.ps1",
         '$ErrorActionPreference = "Stop"']
    if spec["os_version"]:
        L.append(f"# Target: Windows {spec['os_version']}")
    L += ["", echo("Install dependencies")]
    L += _install(spec)
    L += [""] + _HELPER

    setup = clean_setup_commands(spec["setup_commands"], echo, comment)
    if setup:
        L += setup

    if spec["service_name"]:
        L += ["", echo(f"stop {spec['service_name']}"),
              f'Stop-Service -Name "{spec["service_name"]}" -ErrorAction SilentlyContinue']

    if spec["config_directives"] and spec["config_file"]:
        L.append("")
        for d in spec["config_directives"]:
            if not d.get("key"):
                continue
            L.append(echo(f"set {d['key']}"))
            L.append(f'Set-ConfigLine -Key "{d["key"]}" -Value "{d.get("value","")}" -Path "{spec["config_file"]}"')

    if spec["service_name"]:
        L += ["", echo(f"start {spec['service_name']}"), f'Start-Service -Name "{spec["service_name"]}"']

    if spec["start_command"]:
        L += ["", echo("start service"),
              comment("NOTE: register as a Windows service / scheduled task in a real build; this just launches it."),
              f'Start-Process -FilePath "powershell" -ArgumentList "-NoProfile","-Command","{spec["start_command"]}" -WindowStyle Hidden']
    return "\r\n".join(L) + "\r\n"
