"""Deterministic Bash generator for configuring an already-created Linux guest."""
from __future__ import annotations

import re
import shlex

from . import environment_identity


def filename(cve_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id or "CVE")
    return f"configure_{safe}.sh"


def _q(value) -> str:
    return shlex.quote("" if value is None else str(value))


def _kernel_config_test(item: dict) -> str:
    if item["value"] == "enabled":
        return f"grep -Eq {_q('^' + item['symbol'] + '=(y|m)$')} \"$kernel_config\""
    return f"grep -qxF {_q(item['symbol'] + '=' + item['value'])} \"$kernel_config\""


def _report_lines(configuration: dict) -> list[str]:
    """Generate a non-mutating report that never stops at the first mismatch."""
    lines = [
        "report_reset() { REPORT_TOTAL=0; REPORT_PASSED=0; REPORT_FAILED=0; }",
        "report_pass() {",
        '  REPORT_TOTAL=$((REPORT_TOTAL + 1)); REPORT_PASSED=$((REPORT_PASSED + 1))',
        '  printf "CHECK PASS name=%s expected=%s actual=%s\\n" "$1" "$2" "$3"',
        "}",
        "report_fail() {",
        '  REPORT_TOTAL=$((REPORT_TOTAL + 1)); REPORT_FAILED=$((REPORT_FAILED + 1))',
        '  printf "CHECK FAIL name=%s expected=%s actual=%s\\n" "$1" "$2" "$3"',
        "}",
        "report_configuration() {",
        "  local os_id=missing os_version=missing os_suite=missing actual_arch=missing package_version=missing kernel_config actual",
        "  report_reset",
        '  if [ "$ENVIRONMENT_STATUS" = selected ]; then report_pass environment-selection selected "$ENVIRONMENT_STATUS"; else report_fail environment-selection selected "$ENVIRONMENT_STATUS"; fi',
        "  if [ -r /etc/os-release ]; then",
        "    . /etc/os-release",
        '    os_id="${ID:-missing}"; os_version="${VERSION_ID:-missing}"; os_suite="${VERSION_CODENAME:-missing}"',
        "  fi",
        '  if [ -z "$EXPECTED_OS" ] || [ "$os_id" = "$EXPECTED_OS" ]; then report_pass os-family "${EXPECTED_OS:-any}" "$os_id"; else report_fail os-family "$EXPECTED_OS" "$os_id"; fi',
        '  if [ -z "$EXPECTED_OS_VERSION" ] || [ "$os_version" = "$EXPECTED_OS_VERSION" ]; then report_pass os-version "${EXPECTED_OS_VERSION:-any}" "$os_version"; else report_fail os-version "$EXPECTED_OS_VERSION" "$os_version"; fi',
        '  if [ -z "$EXPECTED_OS_SUITE" ] || [ "$os_suite" = "$EXPECTED_OS_SUITE" ]; then report_pass os-suite "${EXPECTED_OS_SUITE:-any}" "$os_suite"; else report_fail os-suite "$EXPECTED_OS_SUITE" "$os_suite"; fi',
        '  if command -v dpkg >/dev/null 2>&1; then actual_arch="$(dpkg --print-architecture 2>/dev/null || true)"; fi',
        '  if [ -z "$EXPECTED_ARCHITECTURE" ] || [ "$actual_arch" = "$EXPECTED_ARCHITECTURE" ]; then report_pass architecture "${EXPECTED_ARCHITECTURE:-any}" "$actual_arch"; else report_fail architecture "$EXPECTED_ARCHITECTURE" "$actual_arch"; fi',
        '  if [ -z "$KERNEL_PACKAGE_CONSTRAINT" ]; then',
        '    report_pass kernel-package-version any "$(uname -r)"',
        '  else',
        '    if [ "$BUILD_TARGET_STATUS" = selected ]; then report_pass build-target selected "$BUILD_TARGET_STATUS"; else report_fail build-target selected "$BUILD_TARGET_STATUS"; fi',
        '    if [ "$(uname -r)" = "$EXPECTED_KERNEL_RELEASE" ]; then report_pass running-kernel "$EXPECTED_KERNEL_RELEASE" "$(uname -r)"; else report_fail running-kernel "$EXPECTED_KERNEL_RELEASE" "$(uname -r)"; fi',
        '    if command -v dpkg-query >/dev/null 2>&1; then actual="$(dpkg-query -W -f=\'${Version}\' "$EXPECTED_META_PACKAGE" 2>/dev/null || true)"; else actual=missing; fi',
        '    [ -n "$actual" ] || actual=missing',
        '    if [ "$actual" = "$EXPECTED_META_PACKAGE_VERSION" ]; then report_pass kernel-meta-package "$EXPECTED_META_PACKAGE_VERSION" "$actual"; else report_fail kernel-meta-package "$EXPECTED_META_PACKAGE_VERSION" "$actual"; fi',
        '    if command -v dpkg-query >/dev/null 2>&1; then package_version="$(dpkg-query -W -f=\'${Version}\' "linux-image-$(uname -r)" 2>/dev/null || true)"; fi',
        '    [ -n "$package_version" ] || package_version=missing',
        '    if [ "$package_version" != missing ] && version_matches "$package_version" "$KERNEL_PACKAGE_CONSTRAINT"; then report_pass kernel-package-version "$KERNEL_PACKAGE_CONSTRAINT" "$package_version"; else report_fail kernel-package-version "$KERNEL_PACKAGE_CONSTRAINT" "$package_version"; fi',
        "  fi",
        '  if [ "$CONFIGURATION_STATUS" = unknown ]; then report_fail configuration-decision certified unknown; else report_pass configuration-decision certified "$CONFIGURATION_STATUS"; fi',
    ]
    for package in configuration.get("packages") or []:
        name = package["name"]
        lines.append(
            f"  if dpkg-query -W -f='${{Status}}' {_q(name)} 2>/dev/null | grep -qxF 'install ok installed'; "
            f"then report_pass {_q('package:' + name)} installed installed; "
            f"else report_fail {_q('package:' + name)} installed missing; fi"
        )
    for module in configuration.get("kernel_modules") or []:
        name = module["name"]
        lines.append(
            f"  if grep -qw {_q(name)} /proc/modules; then report_pass {_q('module:' + name)} "
            f"loaded loaded; else report_fail {_q('module:' + name)} loaded not-loaded; fi"
        )
    kernel_config = configuration.get("kernel_config") or []
    kernel_config_alternatives = configuration.get("kernel_config_alternatives") or []
    if kernel_config or kernel_config_alternatives:
        lines += [
            '  kernel_config="/boot/config-$(uname -r)"',
            '  if [ -r "$kernel_config" ]; then report_pass kernel-config-file readable "$kernel_config"; else report_fail kernel-config-file readable missing; fi',
        ]
    for item in kernel_config:
        pattern = (
            "^" + item["symbol"] + "=(y|m)$" if item["value"] == "enabled"
            else "^" + item["symbol"] + "=" + re.escape(item["value"]) + "$"
        )
        expected = "enabled" if item["value"] == "enabled" else item["value"]
        lines += [
            f"  actual=\"$(grep -E {_q(pattern)} \"$kernel_config\" 2>/dev/null | head -n 1 || true)\"",
            f"  if [ -n \"$actual\" ]; then report_pass {_q('kernel-config:' + item['symbol'])} {_q(expected)} \"${{actual#*=}}\"; "
            f"else report_fail {_q('kernel-config:' + item['symbol'])} {_q(expected)} missing; fi",
        ]
    for index, group in enumerate(kernel_config_alternatives, start=1):
        tests = " || ".join(_kernel_config_test(item) for item in group["one_of"])
        expected = " or ".join(
            item["symbol"] + (" enabled" if item["value"] == "enabled" else "=" + item["value"])
            for item in group["one_of"]
        )
        lines.append(
            f"  if [ -r \"$kernel_config\" ] && ( {tests} ); then report_pass {_q('kernel-config-alternative:' + str(index))} {_q(expected)} satisfied; "
            f"else report_fail {_q('kernel-config-alternative:' + str(index))} {_q(expected)} missing; fi"
        )
    for item in configuration.get("sysctls") or []:
        lines += [
            f"  actual=\"$(sysctl -n {_q(item['key'])} 2>/dev/null || true)\"",
            f"  if [ \"$actual\" = {_q(item['value'])} ]; then report_pass {_q('sysctl:' + item['key'])} {_q(item['value'])} \"$actual\"; "
            f"else report_fail {_q('sysctl:' + item['key'])} {_q(item['value'])} \"${{actual:-missing}}\"; fi",
        ]
    for item in configuration.get("file_settings") or []:
        expected = item["key"] + item["separator"] + item["value"]
        label = "file-setting:" + item["path"] + ":" + item["key"]
        lines.append(
            f"  if grep -qxF {_q(expected)} {_q(item['path'])} 2>/dev/null; then report_pass {_q(label)} {_q(expected)} present; "
            f"else report_fail {_q(label)} {_q(expected)} missing; fi"
        )
    for service in configuration.get("services") or []:
        name = service["name"]
        lines.append(
            f"  if systemctl is-active --quiet {_q(name)} 2>/dev/null; then report_pass {_q('service:' + name)} active active; "
            f"else report_fail {_q('service:' + name)} active inactive; fi"
        )
    if configuration.get("manual_steps"):
        lines.append(
            "  report_fail manual-prerequisites completed 'manual_steps are present and cannot be automatically certified'"
        )
    lines += [
        '  printf "CHECK SUMMARY total=%s passed=%s failed=%s\\n" "$REPORT_TOTAL" "$REPORT_PASSED" "$REPORT_FAILED"',
        '  [ "$REPORT_FAILED" -eq 0 ]',
        "}",
        "",
    ]
    return lines


def build(environment: dict, configuration: dict, cve_id: str) -> str:
    family = environment.get("os_family") or ""
    version = environment.get("os_version") or ""
    suite = environment.get("suite") or ""
    architecture = environment.get("architecture") or ""
    environment_id = environment_identity.fingerprint(environment, cve_id)
    status = configuration["configuration_status"]
    environment_status = environment.get("status") or "needs-input"
    constraints = environment.get("vulnerable_constraints") or {}
    kernel_constraint = constraints.get("running_kernel_package_constraint") or ""
    build_target = environment.get("build_target") or {}
    target_kernel = build_target.get("kernel") or {}
    lines = [
        "#!/bin/bash",
        "set -Eeuo pipefail",
        "",
        f"CVE_ID={_q(cve_id)}",
        f"ENVIRONMENT_ID={_q(environment_id)}",
        f"EXPECTED_OS={_q(family)}",
        f"EXPECTED_OS_VERSION={_q(version)}",
        f"EXPECTED_OS_SUITE={_q(suite)}",
        f"EXPECTED_ARCHITECTURE={_q(architecture)}",
        f"KERNEL_PACKAGE_CONSTRAINT={_q(kernel_constraint)}",
        f"BUILD_TARGET_STATUS={_q(build_target.get('status') or 'needs-input')}",
        f"EXPECTED_KERNEL_RELEASE={_q(target_kernel.get('running_kernel_release') or '')}",
        f"EXPECTED_META_PACKAGE={_q(target_kernel.get('meta_package') or '')}",
        f"EXPECTED_META_PACKAGE_VERSION={_q(target_kernel.get('meta_package_version') or '')}",
        f"CONFIGURATION_STATUS={_q(status)}",
        f"ENVIRONMENT_STATUS={_q(environment_status)}",
        'ACTION="${1:-apply}"',
        'STATE_DIR="/var/lib/cve-configuration/${CVE_ID}"',
        'STATUS_FILE="${STATE_DIR}/status"',
        "",
        "log() { printf '%s\\n' \"$*\"; }",
        "fail() { printf 'ERROR: %s\\n' \"$*\" >&2; exit 1; }",
        "require_root() { [ \"$(id -u)\" -eq 0 ] || fail 'apply must run as root'; }",
        "",
        "version_matches() {",
        '  local candidate="$1" constraint="$2" term operator boundary',
        '  [ -z "$constraint" ] && return 0',
        "  IFS=',' read -r -a terms <<< \"$constraint\"",
        '  for term in "${terms[@]}"; do',
        '    term="${term//[[:space:]]/}"',
        r'    if [[ "$term" =~ ^(==|=|\<\=|\>\=|\<|\>)(.+)$ ]]; then',
        '      operator="${BASH_REMATCH[1]}"; boundary="${BASH_REMATCH[2]}"',
        "    else fail \"invalid constraint term: $term\"; fi",
        '    case "$operator" in',
        '      ==|=) dpkg --compare-versions "$candidate" eq "$boundary" || return 1 ;;',
        r'      \<) dpkg --compare-versions "$candidate" lt "$boundary" || return 1 ;;',
        r'      \<\=) dpkg --compare-versions "$candidate" le "$boundary" || return 1 ;;',
        r'      \>) dpkg --compare-versions "$candidate" gt "$boundary" || return 1 ;;',
        r'      \>\=) dpkg --compare-versions "$candidate" ge "$boundary" || return 1 ;;',
        "    esac",
        "  done",
        "}",
        "",
        "verify_environment() {",
        '  [ "$ENVIRONMENT_STATUS" = selected ] || fail "base environment is unresolved; complete the deterministic platform selection before applying configuration"',
        "  [ -r /etc/os-release ] || fail '/etc/os-release is unavailable'",
        "  . /etc/os-release",
        '  if [ -n "$EXPECTED_OS" ]; then',
        '    case "$EXPECTED_OS" in ubuntu|debian) [ "${ID:-}" = "$EXPECTED_OS" ] || fail "expected $EXPECTED_OS, found ${ID:-unknown}" ;; esac',
        "  fi",
        '  [ -z "$EXPECTED_OS_VERSION" ] || [ "${VERSION_ID:-}" = "$EXPECTED_OS_VERSION" ] || fail "expected OS $EXPECTED_OS_VERSION, found ${VERSION_ID:-unknown}"',
        '  [ -z "$EXPECTED_OS_SUITE" ] || [ "${VERSION_CODENAME:-}" = "$EXPECTED_OS_SUITE" ] || fail "expected OS suite $EXPECTED_OS_SUITE, found ${VERSION_CODENAME:-unknown}"',
        '  if [ -n "$EXPECTED_ARCHITECTURE" ]; then',
        '    command -v dpkg >/dev/null || fail "dpkg is required to verify the selected Ubuntu architecture"',
        '    [ "$(dpkg --print-architecture)" = "$EXPECTED_ARCHITECTURE" ] || fail "expected architecture $EXPECTED_ARCHITECTURE, found $(dpkg --print-architecture)"',
        '  fi',
        '  if [ -n "$KERNEL_PACKAGE_CONSTRAINT" ]; then',
        '    [ "$BUILD_TARGET_STATUS" = selected ] || fail "exact vulnerable kernel build target is unresolved"',
        '    [ -n "$EXPECTED_KERNEL_RELEASE" ] || fail "exact running kernel release is missing from the build target"',
        '    [ "$(uname -r)" = "$EXPECTED_KERNEL_RELEASE" ] || fail "expected exact vulnerable kernel $EXPECTED_KERNEL_RELEASE, found $(uname -r)"',
        '    command -v dpkg-query >/dev/null || fail "dpkg-query is required for the selected Ubuntu environment"',
        '    [ -n "$EXPECTED_META_PACKAGE" ] && [ -n "$EXPECTED_META_PACKAGE_VERSION" ] || fail "exact kernel meta-package target is incomplete"',
        '    local meta_version',
        '    meta_version="$(dpkg-query -W -f=\'${Version}\' "$EXPECTED_META_PACKAGE" 2>/dev/null || true)"',
        '    [ "$meta_version" = "$EXPECTED_META_PACKAGE_VERSION" ] || fail "expected $EXPECTED_META_PACKAGE=$EXPECTED_META_PACKAGE_VERSION, found ${meta_version:-missing}"',
        '    local package_version',
        '    package_version="$(dpkg-query -W -f=\'${Version}\' "linux-image-$(uname -r)" 2>/dev/null || true)"',
        '    [ -n "$package_version" ] || fail "cannot resolve the running kernel package version"',
        '    version_matches "$package_version" "$KERNEL_PACKAGE_CONSTRAINT" || fail "running kernel package $package_version does not satisfy $KERNEL_PACKAGE_CONSTRAINT"',
        "  fi",
        "}",
        "",
        "set_file_value() {",
        '  local path="$1" key="$2" value="$3" separator="$4" tmp',
        '  mkdir -p "$(dirname "$path")"; touch "$path"; tmp="$(mktemp)"',
        '  awk -v k="$key" -v v="$value" -v s="$separator" \''
        'BEGIN {done=0} $0 ~ "^[[:space:]]*" k "[[:space:]=]" {if (!done) print k s v; done=1; next} {print} END {if (!done) print k s v}\''
        ' "$path" > "$tmp"',
        '  cat "$tmp" > "$path"; rm -f "$tmp"',
        "}",
        "",
        "apply_configuration() {",
        "  require_root",
        "  verify_environment",
        '  mkdir -p "$STATE_DIR"',
        '  if [ "$CONFIGURATION_STATUS" = unknown ]; then fail "configuration evidence is insufficient; refusing to treat unknown as no configuration"; fi',
    ]
    if status == "not_required":
        lines.append("  log 'No additional guest configuration is required by the available evidence.'")
    for package in configuration.get("packages") or []:
        name = package["name"]
        lines += [
            f"  log {_q('Installing enablement package: ' + name)}",
            "  command -v apt-get >/dev/null || fail 'Only apt-based guest package enablement is currently supported'",
            "  apt-get update -q",
            f"  DEBIAN_FRONTEND=noninteractive apt-get install -y -q {_q(name)}",
        ]
    persistent_modules = []
    for module in configuration.get("kernel_modules") or []:
        name = module["name"]
        lines += [f"  log {_q('Loading required kernel module: ' + name)}", f"  modprobe {_q(name)}"]
        if module.get("persistent"):
            persistent_modules.append(name)
    if persistent_modules:
        lines += [
            f"  printf '%s\\n' {' '.join(_q(name) for name in persistent_modules)} > /etc/modules-load.d/{re.sub('[^A-Za-z0-9_.-]', '_', cve_id)}.conf"
        ]
    if configuration.get("sysctls"):
        sysctl_path = f"/etc/sysctl.d/90-{re.sub('[^A-Za-z0-9_.-]', '_', cve_id)}.conf"
        lines.append(f"  : > {_q(sysctl_path)}")
        for item in configuration["sysctls"]:
            lines += [
                f"  printf '%s\\n' {_q(item['key'] + '=' + item['value'])} >> {_q(sysctl_path)}",
                f"  sysctl -w {_q(item['key'] + '=' + item['value'])} >/dev/null",
            ]
    for item in configuration.get("file_settings") or []:
        lines.append(f"  set_file_value {_q(item['path'])} {_q(item['key'])} {_q(item['value'])} {_q(item['separator'])}")
    for service in configuration.get("services") or []:
        if service.get("enabled"):
            lines.append(f"  systemctl enable {_q(service['name'])}")
        lines.append(f"  systemctl start {_q(service['name'])}")
    if configuration.get("manual_steps"):
        lines.append("  log 'Manual configuration steps remain; review configuration.json before validation.'")
    lines += [
        '  printf "APPLIED cve=%s environment_id=%s\\n" "$CVE_ID" "$ENVIRONMENT_ID" > "$STATUS_FILE"',
        "  verify_configuration",
        "}",
        "",
        "verify_configuration() {",
        "  verify_environment",
        '  [ "$CONFIGURATION_STATUS" != unknown ] || fail "configuration evidence remains unknown"',
    ]
    for module in configuration.get("kernel_modules") or []:
        lines.append(f"  grep -qw {_q(module['name'])} /proc/modules || fail {_q('required module is not loaded: ' + module['name'])}")
    kernel_config = configuration.get("kernel_config") or []
    kernel_config_alternatives = configuration.get("kernel_config_alternatives") or []
    if kernel_config or kernel_config_alternatives:
        lines += [
            '  kernel_config="/boot/config-$(uname -r)"',
            '  [ -r "$kernel_config" ] || fail "running kernel config is unavailable"',
        ]
    for item in kernel_config:
        if item["value"] == "enabled":
            lines.append(
                f"  {_kernel_config_test(item)} || fail "
                f"{_q('kernel config requirement is not enabled: ' + item['symbol'])}"
            )
        else:
            expected = f"{item['symbol']}={item['value']}"
            lines.append(
                f"  {_kernel_config_test(item)} || fail "
                f"{_q('kernel config requirement is absent: ' + expected)}"
            )
    for group in kernel_config_alternatives:
        tests = " || ".join(_kernel_config_test(item) for item in group["one_of"])
        expected = " or ".join(
            item["symbol"] + (" enabled" if item["value"] == "enabled" else "=" + item["value"])
            for item in group["one_of"]
        )
        lines.append(
            f"  if ! ( {tests} ); then fail {_q('no kernel config alternative is satisfied: ' + expected)}; fi"
        )
    for item in configuration.get("sysctls") or []:
        lines.append(f"  [ \"$(sysctl -n {_q(item['key'])})\" = {_q(item['value'])} ] || fail {_q('sysctl mismatch: ' + item['key'])}")
    for item in configuration.get("file_settings") or []:
        expected = item["key"] + item["separator"] + item["value"]
        lines.append(f"  grep -qxF {_q(expected)} {_q(item['path'])} || fail {_q('file setting missing: ' + expected)}")
    for service in configuration.get("services") or []:
        lines.append(f"  systemctl is-active --quiet {_q(service['name'])} || fail {_q('service is not active: ' + service['name'])}")
    if configuration.get("manual_steps"):
        lines.append("  fail 'manual_steps are present and cannot be automatically certified'")
    lines += [
        '  log "CONFIGURED cve=$CVE_ID environment_id=$ENVIRONMENT_ID configuration_status=$CONFIGURATION_STATUS environment_ready=true"',
        "}",
        "",
    ]
    lines += _report_lines(configuration)
    lines += [
        'case "$ACTION" in',
        "  apply) apply_configuration ;;",
        "  verify) verify_configuration ;;",
        "  report) report_configuration ;;",
        '  status) [ -r "$STATUS_FILE" ] && cat "$STATUS_FILE" || printf "NOT_APPLIED cve=%s\\n" "$CVE_ID" ;;',
        "  *) fail 'usage: configure script [apply|verify|report|status]' ;;",
        "esac",
        "",
    ]
    return "\n".join(lines)
