"""Generate a two-stage Ubuntu/Debian kernel-package reproduction script."""
from __future__ import annotations

import re

from ..constraints import bounds, classify

_KERNEL_PACKAGE = re.compile(
    r"^(?:linux$|linux(?:-image|-signed-image|-generic|-virtual|-lowlatency|-aws|-azure|-gcp)|kernel)",
    re.IGNORECASE,
)

_CONCRETE_IMAGE_PACKAGE = re.compile(r"^linux-(?:signed-)?image-[0-9]", re.IGNORECASE)


def filename(cve_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id or "CVE")
    return f"provision_kernel_{safe}.sh"


def is_kernel_spec(spec: dict, ground_truth: dict | None = None) -> bool:
    package = (spec.get("package") or "").strip()
    if _KERNEL_PACKAGE.match(package):
        return True
    return any(p.get("part") == "o" and p.get("product") in {"linux_kernel", "linux"}
               for p in (ground_truth or {}).get("products") or [])


def _sq(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def _validate_constraint(constraint: str) -> None:
    info = classify(constraint)
    if info["kind"] == "exact":
        return
    if info["kind"] != "range":
        raise ValueError("A kernel reproduction requires an exact version or a bounded vulnerable range")
    parsed = bounds(constraint)
    if not any(parsed.get(key) for key in ("min_inc", "min_exc", "max_inc", "max_exc")):
        raise ValueError("The kernel version constraint has no usable Debian package boundary")


def build(spec: dict, auto_reboot: bool = False) -> str:
    package = (spec.get("package") or "").strip()
    constraint = (spec.get("version_constraint") or "").strip()
    concrete_constraint = (spec.get("concrete_kernel_constraint") or "").strip()
    os_family = (spec.get("os_family") or "").lower()
    os_version = (spec.get("os_version") or "").strip()
    target_meta_version = (spec.get("target_meta_version") or "").strip()
    target_kernel_release = (spec.get("target_kernel_release") or "").strip()
    if os_family not in {"ubuntu", "debian"}:
        raise ValueError("Distro-kernel reproduction currently supports Ubuntu and Debian only")
    if not os_version:
        raise ValueError("Distro-kernel reproduction requires an exact OS version")
    if (spec.get("package_manager") or "apt") != "apt":
        raise ValueError("Distro-kernel reproduction requires an APT kernel package")
    if package.lower() in {"linux", "kernel"} or not package or not _KERNEL_PACKAGE.match(package):
        raise ValueError("Provide an installable Ubuntu/Debian kernel package (for example linux-image-generic), not the source package")
    _validate_constraint(constraint)
    if _CONCRETE_IMAGE_PACKAGE.match(package):
        concrete_constraint = concrete_constraint or constraint
    elif not concrete_constraint:
        raise ValueError(
            "A kernel meta-package reproduction requires concrete_kernel_constraint "
            "for the resolved linux-image-N package"
        )
    _validate_constraint(concrete_constraint)
    if bool(target_meta_version) != bool(target_kernel_release):
        raise ValueError(
            "An exact kernel target requires both target_meta_version and "
            "target_kernel_release"
        )
    if target_kernel_release and not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-(?:generic|virtual|lowlatency)",
        target_kernel_release,
    ):
        raise ValueError("target_kernel_release is not a supported Ubuntu kernel release")
    default_reboot = "1" if auto_reboot else "0"
    return f'''#!/bin/bash
# Kernel-aware CVE reproduction for an isolated Ubuntu/Debian VM.
# Usage: sudo ./setup.sh prepare | verify | status
set -Eeuo pipefail

PACKAGE={_sq(package)}
CONSTRAINT={_sq(constraint)}
CONCRETE_CONSTRAINT={_sq(concrete_constraint)}
TARGET_META_VERSION={_sq(target_meta_version)}
TARGET_KERNEL_RELEASE={_sq(target_kernel_release)}
EXPECTED_OS_FAMILY={_sq(os_family)}
EXPECTED_OS_VERSION={_sq(os_version)}
STATE_DIR=/var/lib/cve-reproduction
CVE_AUTO_REBOOT="${{CVE_AUTO_REBOOT:-{default_reboot}}}"

status() {{
  if [ -f "$STATE_DIR/status" ]; then cat "$STATE_DIR/status"; else echo "INCONCLUSIVE no workflow status exists"; fi
}}

version_matches_constraint() {{
  local version="$1" constraint="${{2:-$CONSTRAINT}}" term op boundary
  local normalized="${{constraint//,/ }}"
  local terms=()
  read -r -a terms <<< "$normalized"
  [ "${{#terms[@]}}" -gt 0 ] || return 2
  for term in "${{terms[@]}}"; do
    case "$term" in
      '<='*) op=le; boundary="${{term#<=}}" ;;
      '>='*) op=ge; boundary="${{term#>=}}" ;;
      '<'*)  op=lt; boundary="${{term#<}}" ;;
      '>'*)  op=gt; boundary="${{term#>}}" ;;
      '=='*) op=eq; boundary="${{term#==}}" ;;
      '='*)  op=eq; boundary="${{term#=}}" ;;
      *)     op=eq; boundary="$term" ;;
    esac
    [ -n "$boundary" ] || return 2
    dpkg --compare-versions "$version" "$op" "$boundary" || return 1
  done
}}

preflight() {{
  [ "$(id -u)" -eq 0 ] || {{ echo "ERROR: run prepare as root" >&2; return 2; }}
  [ -r /etc/os-release ] || {{ echo "ERROR: /etc/os-release is unavailable" >&2; return 2; }}
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${{ID:-}}" != "$EXPECTED_OS_FAMILY" ] || [ "${{VERSION_ID:-}}" != "$EXPECTED_OS_VERSION" ]; then
    printf 'ERROR: this recipe requires %s %s; detected %s %s\\n' "$EXPECTED_OS_FAMILY" "$EXPECTED_OS_VERSION" "${{ID:-unknown}}" "${{VERSION_ID:-unknown}}" >&2
    return 2
  fi
  command -v apt-get >/dev/null || {{ echo "ERROR: apt-get is unavailable" >&2; return 2; }}
  command -v systemctl >/dev/null || {{ echo "ERROR: systemd is required" >&2; return 2; }}
  command -v update-grub >/dev/null || {{ echo "ERROR: update-grub is required" >&2; return 2; }}
  command -v grub-reboot >/dev/null || {{ echo "ERROR: grub-reboot is required" >&2; return 2; }}
  [ -d /boot ] || {{ echo "ERROR: /boot is unavailable" >&2; return 2; }}
}}

verify() {{
  install -d -m 0755 "$STATE_DIR"
  if [ ! -r "$STATE_DIR/expected-kernel" ]; then
    echo "FAILED expected kernel state is missing" | tee "$STATE_DIR/status"
    echo "##CVE-ENV-RESULT## FAILED missing_expected_kernel"; return 1
  fi
  local expected actual concrete concrete_version concrete_constraint installed_concrete_version state_file
  expected="$(cat "$STATE_DIR/expected-kernel")"; actual="$(uname -r)"
  if [ "$actual" != "$expected" ]; then
    printf 'FAILED expected_kernel=%s actual_kernel=%s\\n' "$expected" "$actual" | tee "$STATE_DIR/status"
    echo "##CVE-ENV-RESULT## FAILED kernel_mismatch"; return 1
  fi
  for state_file in concrete-package concrete-package-version concrete-constraint; do
    if [ ! -s "$STATE_DIR/$state_file" ]; then
      echo "FAILED concrete kernel state is incomplete" | tee "$STATE_DIR/status"
      echo "##CVE-ENV-RESULT## FAILED missing_concrete_state"; return 1
    fi
  done
  concrete="$(cat "$STATE_DIR/concrete-package")"
  concrete_version="$(cat "$STATE_DIR/concrete-package-version")"
  concrete_constraint="$(cat "$STATE_DIR/concrete-constraint")"
  installed_concrete_version="$(dpkg-query -W -f='${{Version}}' "$concrete" 2>/dev/null || true)"
  if [ "$installed_concrete_version" != "$concrete_version" ] || ! version_matches_constraint "$installed_concrete_version" "$concrete_constraint"; then
    printf 'FAILED concrete_package=%s expected_version=%s actual_version=%s constraint=%s\\n' "$concrete" "$concrete_version" "$installed_concrete_version" "$concrete_constraint" | tee "$STATE_DIR/status"
    echo "##CVE-ENV-RESULT## FAILED concrete_kernel_constraint"; return 1
  fi
  printf 'READY kernel=%s concrete_package_version=%s environment_ready=true manual_validation=true\\n' "$actual" "$installed_concrete_version" | tee "$STATE_DIR/status"
  echo "##CVE-ENV-RESULT## READY"; return 0
}}

prepare() {{
  preflight || return $?
  export DEBIAN_FRONTEND=noninteractive
  if ! apt-get update -q; then
    echo "ERROR: APT repository update failed; provide a valid guest sources list with CVE_APT_SOURCES_FILE when creating the VM" >&2
    return 41
  fi
  if [ -n "$TARGET_META_VERSION" ]; then
    echo "Select the evidence-backed exact $PACKAGE version $TARGET_META_VERSION ($CONSTRAINT)"
  else
    echo "Select the newest available vulnerable $PACKAGE version ($CONSTRAINT)"
  fi
  mapfile -t versions < <(apt-cache madison "$PACKAGE" | awk '{{print $3}}' | awk '!seen[$0]++')
  selected=""
  for _cve_v in "${{versions[@]}}"; do
    if [ -n "$TARGET_META_VERSION" ] && [ "$_cve_v" != "$TARGET_META_VERSION" ]; then continue; fi
    if version_matches_constraint "$_cve_v" "$CONSTRAINT"; then
      if [ -z "$selected" ] || dpkg --compare-versions "$_cve_v" gt "$selected"; then selected="$_cve_v"; fi
    fi
  done
  if [ -z "$selected" ]; then
    echo "ERROR: no configured APT repository contains the selected $PACKAGE target ${{TARGET_META_VERSION:-in vulnerable range $CONSTRAINT}}" >&2
    echo "Add the matching Ubuntu archive or Debian Snapshot repository, then rerun." >&2; return 42
  fi
  if [ -n "$TARGET_META_VERSION" ] && [ "$selected" != "$TARGET_META_VERSION" ]; then
    echo "ERROR: package resolver did not preserve exact target $TARGET_META_VERSION" >&2; return 48
  fi
  version_matches_constraint "$selected" "$CONSTRAINT" || {{ echo "ERROR: selected package escaped $CONSTRAINT" >&2; return 47; }}
  if ! apt-get install -s --allow-downgrades --no-remove "$PACKAGE=$selected" grub-common >/dev/null; then
    echo "ERROR: APT cannot install the selected kernel without removing packages" >&2; return 46
  fi
  apt-get install -y -q --allow-downgrades --no-remove "$PACKAGE=$selected" grub-common
  test "$(dpkg-query -W -f='${{Version}}' "$PACKAGE")" = "$selected"

  concrete="$PACKAGE"
  case "$concrete" in
    linux-image-[0-9]*) ;;
    *) concrete="$(dpkg-query -W -f='${{Depends}}\\n' "$PACKAGE" | grep -oE 'linux-image-[0-9][^ ,|()]+' | head -n1)" ;;
  esac
  if [ -z "$concrete" ]; then echo "ERROR: could not resolve the concrete kernel image dependency" >&2; return 43; fi
  expected="${{concrete#linux-image-}}"
  if [ -n "$TARGET_KERNEL_RELEASE" ] && [ "$expected" != "$TARGET_KERNEL_RELEASE" ]; then
    printf 'ERROR: exact target requires kernel %s but package dependency resolved %s\\n' "$TARGET_KERNEL_RELEASE" "$expected" >&2
    return 48
  fi
  dpkg-query -W -f='${{Status}}\\n' "$concrete" | grep -Fx 'install ok installed'
  concrete_version="$(dpkg-query -W -f='${{Version}}' "$concrete")"
  if ! version_matches_constraint "$concrete_version" "$CONCRETE_CONSTRAINT"; then
    printf 'ERROR: concrete package %s version %s is outside vulnerable range %s\\n' "$concrete" "$concrete_version" "$CONCRETE_CONSTRAINT" >&2
    return 49
  fi
  test -r "/boot/vmlinuz-$expected"; test -d "/lib/modules/$expected"
  header="linux-headers-$expected"
  if ! apt-cache show "$header" >/dev/null 2>&1; then
    echo "ERROR: matching headers package $header is unavailable" >&2; return 45
  fi
  apt-get install -y -q --no-remove "$header"
  dpkg-query -W -f='${{Status}}\n' "$header" | grep -Fx 'install ok installed'

  install -d -m 0755 "$STATE_DIR"
  printf '%s\\n' "$expected" > "$STATE_DIR/expected-kernel"
  printf '%s\\n' "$selected" > "$STATE_DIR/selected-package-version"
  printf '%s\\n' "$concrete" > "$STATE_DIR/concrete-package"
  printf '%s\\n' "$concrete_version" > "$STATE_DIR/concrete-package-version"
  printf '%s\\n' "$CONCRETE_CONSTRAINT" > "$STATE_DIR/concrete-constraint"
  script_target=/usr/local/sbin/cve-kernel-reproduction
  if [ ! -e "$script_target" ] || ! [ "$0" -ef "$script_target" ]; then
    install -m 0755 "$0" "$script_target"
  fi
  cat > /etc/systemd/system/cve-kernel-verify.service <<'CVE_UNIT'
[Unit]
Description=Verify CVE reproduction kernel after reboot
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cve-kernel-reproduction verify
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
CVE_UNIT
  systemctl daemon-reload; systemctl enable cve-kernel-verify.service
  if [ "$(uname -r)" = "$expected" ]; then
    verify; return $?
  fi
  update-grub
  grub_target="$(awk -v image="/boot/vmlinuz-$expected" '
    BEGIN {{ quote=sprintf("%c", 39); submenu_id=""; menu_id="" }}
    function last_quoted(line, count, fields) {{
      count=split(line, fields, quote)
      return count >= 3 ? fields[count - 1] : ""
    }}
    /^[[:space:]]*submenu[[:space:]]/ {{ submenu_id=last_quoted($0); next }}
    /^[[:space:]]*menuentry[[:space:]]/ {{ menu_id=last_quoted($0); next }}
    /^[[:space:]]*linux(efi)?[[:space:]]/ && ($2 == image || $2 == substr(image, 6)) {{
      if (submenu_id != "") print submenu_id ">" menu_id; else print menu_id
      exit
    }}' /boot/grub/grub.cfg)"
  if [ -z "$grub_target" ]; then
    echo "ERROR: exact GRUB entry for $expected was not found" >&2; return 44
  fi
  grub-reboot "$grub_target"
  printf 'PREPARED kernel=%s package_version=%s reboot_required=true verification=pending\\n' "$expected" "$selected" | tee "$STATE_DIR/status"
  if [ "$CVE_AUTO_REBOOT" = "1" ]; then systemctl reboot; fi
}}

case "${{1:-prepare}}" in
  prepare) prepare ;;
  verify) verify ;;
  status) status ;;
  *) echo "Usage: $0 prepare|verify|status" >&2; exit 2 ;;
esac
'''





