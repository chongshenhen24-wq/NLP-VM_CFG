"""Generate a host-side checker for an already-running QEMU evaluation VM."""
from __future__ import annotations

import base64
import re

from . import guest_configuration
from . import environment_identity


SENTINEL = "##CVE-CONFIG-RESULT##"


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value or "CVE")


def _sq(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def filename(cve_id: str) -> str:
    return f"check_configuration_{_safe_id(cve_id)}.sh"


def build(
    environment: dict,
    configuration: dict,
    cve_id: str,
    *,
    guest_script: str | None = None,
) -> str:
    """Build a separate checker that transfers and runs the guest payload."""
    try:
        os_version, suite = environment_identity.validate_selected_ubuntu(environment)
    except ValueError as exc:
        message = str(exc).replace("QEMU workflow", "Configuration checking")
        raise ValueError(message) from exc
    cve = _safe_id(cve_id)
    environment_id = environment_identity.fingerprint(environment, cve_id)
    kernel_constraint = str(
        (environment.get("vulnerable_constraints") or {}).get(
            "running_kernel_package_constraint"
        ) or ""
    )
    guest_name = guest_configuration.filename(cve)
    guest = guest_script if guest_script is not None else guest_configuration.build(
        environment, configuration, cve_id
    )
    if not guest.startswith("#!/bin/bash") or "\x00" in guest:
        raise ValueError("The guest configuration script is invalid")
    if not re.search(
        rf"^ENVIRONMENT_ID={re.escape(environment_id)}$", guest, flags=re.MULTILINE
    ):
        raise ValueError(
            "Guest configuration payload environment identity does not match "
            "the selected QEMU environment"
        )
    payload = base64.b64encode(guest.encode("utf-8")).decode("ascii")
    status = configuration.get("configuration_status") or "unknown"
    manual_required = "1" if configuration.get("manual_steps") else "0"

    return rf'''#!/bin/bash
# Host-side configuration checker for the VM created by build_qemu_{cve}.sh.
# This script contains no QEMU lifecycle commands and never runs a PoC.
set -Eeuo pipefail

SENTINEL={_sq(SENTINEL)}
ENVIRONMENT_ID={_sq(environment_id)}
EXPECTED_OS_VERSION={_sq(os_version)}
EXPECTED_OS_SUITE={_sq(suite)}
KERNEL_PACKAGE_CONSTRAINT={_sq(kernel_constraint)}
CONFIGURATION_STATUS={_sq(status)}
MANUAL_REQUIRED={manual_required}
USER_HOME="${{HOME:?ERROR: HOME is required to locate QEMU state}}"
STATE_ROOT="${{XDG_STATE_HOME:-$USER_HOME/.local/state}}/cve-configuration-qemu"
WORK_DIR="${{CVE_QEMU_WORK_DIR:-$STATE_ROOT/qemu-build-{cve}}}"
PID_FILE="$WORK_DIR/qemu.pid"
ENVIRONMENT_FILE="$WORK_DIR/environment.identity"
SSH_KEY="$WORK_DIR/id_ed25519"
SSH_PORT="${{CVE_SSH_PORT:-2222}}"
SSH_WAIT="${{CVE_SSH_WAIT:-300}}"
CHECK_LOG="$WORK_DIR/configuration-check.log"
PAYLOAD_B64={_sq(payload)}
REMOTE_SCRIPT="/tmp/{guest_name}"

if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "ERROR: CVE_SSH_PORT must be an unprivileged TCP port from 1024 to 65535" >&2; exit 20
fi
if ! [[ "$SSH_WAIT" =~ ^[0-9]+$ ]] || [ "$SSH_WAIT" -lt 1 ]; then
  echo "ERROR: CVE_SSH_WAIT must be a positive integer" >&2; exit 20
fi
for tool in ssh base64 tee; do
  command -v "$tool" >/dev/null 2>&1 || {{ echo "ERROR: missing host tool: $tool" >&2; exit 20; }}
done
[ -r "$ENVIRONMENT_FILE" ] || {{
  echo "$SENTINEL MISMATCH reason=missing_builder_environment_identity" >&2
  echo "ERROR: VM environment identity is missing; recreate it with build_qemu_{cve}.sh" >&2
  exit 22
}}
VM_ENVIRONMENT_ID=''
IFS= read -r VM_ENVIRONMENT_ID < "$ENVIRONMENT_FILE" || true
if [ "$VM_ENVIRONMENT_ID" != "$ENVIRONMENT_ID" ]; then
  echo "$SENTINEL MISMATCH expected_environment_id=$ENVIRONMENT_ID actual_environment_id=${{VM_ENVIRONMENT_ID:-missing}}" >&2
  echo "ERROR: QEMU builder and configuration checker came from different environment selections" >&2
  echo "Expected Ubuntu $EXPECTED_OS_VERSION ($EXPECTED_OS_SUITE), kernel constraint $KERNEL_PACKAGE_CONSTRAINT" >&2
  exit 22
fi
[ -r "$PID_FILE" ] || {{ echo "ERROR: VM PID file is missing; run build_qemu_{cve}.sh first" >&2; exit 21; }}
vm_pid="$(cat "$PID_FILE")"
kill -0 "$vm_pid" 2>/dev/null || {{ echo "ERROR: the QEMU VM is not running" >&2; exit 21; }}
[ -r "$SSH_KEY" ] || {{ echo "ERROR: VM SSH key is missing: $SSH_KEY" >&2; exit 21; }}

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=5
  -i "$SSH_KEY"
  -p "$SSH_PORT"
)
TARGET=cve@127.0.0.1

echo "Waiting for the separate QEMU VM SSH service"
deadline=$((SECONDS + SSH_WAIT))
until ssh "${{SSH_OPTS[@]}}" "$TARGET" true >/dev/null 2>&1; do
  if ! kill -0 "$vm_pid" 2>/dev/null; then
    echo "RESULT: INCONCLUSIVE (VM exited before SSH became available)" >&2; exit 2
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "RESULT: INCONCLUSIVE (SSH timeout)" >&2; exit 2
  fi
  sleep 2
done

echo "Transferring the deterministic configuration checker"
if ! printf '%s' "$PAYLOAD_B64" | base64 --decode | \
  ssh "${{SSH_OPTS[@]}}" "$TARGET" "cat > '$REMOTE_SCRIPT' && chmod 700 '$REMOTE_SCRIPT'"; then
  echo "RESULT: INCONCLUSIVE (checker transfer failed)" >&2; exit 2
fi

: > "$CHECK_LOG"
set +e
echo "Applying the certified configuration plan"
ssh "${{SSH_OPTS[@]}}" "$TARGET" "sudo '$REMOTE_SCRIPT' apply" 2>&1 | tee -a "$CHECK_LOG"
apply_rc="${{PIPESTATUS[0]}}"
echo "Running the complete non-mutating environment and configuration report"
ssh "${{SSH_OPTS[@]}}" "$TARGET" "sudo '$REMOTE_SCRIPT' report" 2>&1 | tee -a "$CHECK_LOG"
report_rc="${{PIPESTATUS[0]}}"
set -e
rc="$apply_rc"
[ "$rc" -ne 0 ] || rc="$report_rc"

if [ "$apply_rc" -eq 0 ] && [ "$report_rc" -eq 0 ]; then
  echo "$SENTINEL READY automatic_checks_passed=true manual_validation=false"
  echo "RESULT: VULNERABLE_REPRODUCTION_ENVIRONMENT_READY"
  echo "This proves configuration readiness, not CVE exploitability."
  exit 0
elif [ "$CONFIGURATION_STATUS" = unknown ]; then
  echo "$SENTINEL UNCERTIFIED configuration_decision=unknown configuration_rc=$rc"
  echo "RESULT: UNCERTIFIED (official evidence did not support a configuration decision)"
  exit 4
elif [ "$MANUAL_REQUIRED" = 1 ] && \
     grep -Fq 'manual_steps are present and cannot be automatically certified' "$CHECK_LOG"; then
  echo "$SENTINEL MANUAL_REQUIRED automatic_checks_passed=true manual_validation=true"
  echo "RESULT: automatic checks passed; manual prerequisites remain"
  exit 3
fi

echo "$SENTINEL FAILED configuration_rc=$rc apply_rc=$apply_rc report_rc=$report_rc"
echo "RESULT: guest configuration check FAILED" >&2
exit 1
'''
