"""Generate the post-reboot verification script for a kernel reproduction.

This runs INSIDE the guest AFTER the kernel swap + reboot (a second Packer
provisioner). It asserts, in layers, that the built kernel is not just a pile of
files but a *running, vulnerable* kernel — and finally runs a user-supplied PoC
and reports its result.

Boundary: this script RUNS a PoC that the user provides (a path/command); it does
NOT contain or generate exploit code. The exploit is an input, not output.

Layers (each `check` prints PASS/FAIL and feeds the final exit code):
  1. version        uname -r == the vulnerable ref that was built
  2. clean boot     systemctl not failed; no oops/BUG/panic in dmesg; stayed up
  3. subsystem      the vulnerable code path is compiled in (config/kallsyms/module)
  4. poc            the supplied PoC ran and its success marker fired
"""

_VERIFY_HELPERS = r"""
PASS=0; FAIL=0
check() {  # check "<label>" "<command>"
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $label"; PASS=$((PASS+1));
  else echo "FAIL  $label"; FAIL=$((FAIL+1)); fi
}
note() { echo "----  $*"; }
"""


def _expected_release(vulnerable_ref: str) -> str:
    """v6.18.21 -> 6.18.21 (uname -r prefix to match; local builds append suffixes)."""
    return (vulnerable_ref or "").lstrip("vV")


def build_verify(
    vulnerable_ref: str,
    subsystem: str | None = None,
    config_options=None,        # e.g. ["CONFIG_CRYPTO_USER_API_AEAD"]
    kallsyms_symbols=None,       # e.g. ["algif_aead"]
    modules=None,                # e.g. ["algif_aead"]
    poc_cmd: str | None = None,  # user-supplied: how to run their PoC
    poc_success: str | None = None,  # shell test that is TRUE iff the PoC succeeded
) -> str:
    rel = _expected_release(vulnerable_ref)
    config_options = config_options or []
    kallsyms_symbols = kallsyms_symbols or []
    modules = modules or []

    L = ["#!/bin/bash", "# Post-reboot kernel verification (runs in-guest after the kernel swap).",
         "# Generated — do not hand-edit; regenerate from the pipeline.", "set -u", _VERIFY_HELPERS]

    # --- Level 1: version ---
    L += [
        'note "Level 1: kernel version"',
        f'RUNNING="$(uname -r)"; EXPECT="{rel}"',
        'echo "    running: $RUNNING   expected-prefix: $EXPECT"',
        'check "uname -r matches the built vulnerable ref" bash -c \'[[ "$(uname -r)" == "'
        + rel + '"* ]]\'',
    ]

    # --- Level 2: clean boot ---
    L += [
        'note "Level 2: clean boot"',
        'check "system not in failed state" bash -c \'[[ "$(systemctl is-system-running 2>/dev/null)" != "failed" ]]\'',
        r'''check "no oops/BUG/panic in dmesg" bash -c '! dmesg 2>/dev/null | grep -Eiq "kernel BUG|Oops|call trace|kernel panic|general protection fault"' ''',
        'check "uptime is sane (booted, not looping)" bash -c \'[[ "$(cut -d. -f1 /proc/uptime)" -ge 5 ]]\'',
    ]

    # --- Level 3: vulnerable subsystem present ---
    L += ['note ' + _sq("Level 3: vulnerable subsystem present" + (f" ({subsystem})" if subsystem else ""))]
    if not (config_options or kallsyms_symbols or modules):
        L.append('echo "    (no subsystem markers provided — skipping; supply config/kallsyms/modules for a real check)"')
    for opt in config_options:
        # config may be at /proc/config.gz or /boot/config-$(uname -r)
        L.append(
            f'check "config {opt} enabled" bash -c \''
            f'(zcat /proc/config.gz 2>/dev/null; cat /boot/config-$(uname -r) 2>/dev/null) | grep -Eq "^{opt}=(y|m)"\'')
    for sym in kallsyms_symbols:
        L.append(f'check "symbol {sym} present in kallsyms" bash -c \'grep -qi "{sym}" /proc/kallsyms\'')
    for mod in modules:
        # present either as a loadable module available OR already built-in (kallsyms covers built-in)
        L.append(
            f'check "module {mod} available or built-in" bash -c \''
            f'modinfo {mod} >/dev/null 2>&1 || grep -qi "{mod}" /proc/kallsyms\'')

    # --- Level 4: PoC result (user-supplied) ---
    L += ['note "Level 4: PoC result (user-supplied exploit; run + read result only)"']
    if not poc_cmd:
        L.append('echo "    (no --poc-cmd provided — skipping exploit check)"')
    else:
        L += [
            'note ' + _sq('running PoC: ' + poc_cmd),
            f'{poc_cmd} || true    # PoC exit code is not trusted; success is judged by the marker below',
        ]
        success_test = poc_success or 'test "$(id -u)" -eq 0'
        L.append(f'check "PoC success condition" bash -c {_sq(success_test)}')

    # --- summary + exit code ---
    L += [
        'note "summary"',
        'echo "    PASS=$PASS  FAIL=$FAIL"',
        'if [[ $FAIL -eq 0 ]]; then echo "RESULT: kernel reproduction VERIFIED"; exit 0; '
        'else echo "RESULT: verification FAILED ($FAIL check(s))"; exit 1; fi',
    ]
    return "\n".join(L) + "\n"


def _sq(s: str) -> str:
    """Safely single-quote a string for embedding in bash."""
    return "'" + s.replace("'", "'\\''") + "'"
