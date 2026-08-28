"""Legacy combined QEMU/check wrapper; the primary workflow uses split generators."""
from __future__ import annotations

import base64
import re

from . import guest_configuration


SENTINEL = "##CVE-CONFIG-RESULT##"
_UBUNTU_RELEASES = {
    "20.04": ("focal", "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"),
    "22.04": ("jammy", "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"),
    "24.04": ("noble", "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"),
}


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value or "CVE")


def _sq(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def filename(cve_id: str) -> str:
    return f"run_qemu_check_{_safe_id(cve_id)}.sh"


def build(
    environment: dict,
    configuration: dict,
    cve_id: str,
    *,
    guest_script: str | None = None,
    memory_mb: int = 4096,
    cpus: int = 2,
    disk_size: str = "20G",
    timeout_s: int = 1800,
) -> str:
    """Build one host script that boots Ubuntu and checks guest configuration.

    The wrapper does not install or select a vulnerable kernel and never runs a
    PoC. It embeds the deterministic guest configuration script, applies its
    typed runtime settings, and reports whether all automatic checks passed.
    """
    if environment.get("status") != "selected":
        raise ValueError("QEMU configuration checking requires a selected base environment")
    if (environment.get("os_family") or "").strip().lower() != "ubuntu":
        raise ValueError("The QEMU configuration-check workflow currently supports Ubuntu only")
    os_version = (environment.get("os_version") or "").strip()
    release = _UBUNTU_RELEASES.get(os_version)
    if not release:
        supported = ", ".join(sorted(_UBUNTU_RELEASES))
        raise ValueError(
            f"Unsupported Ubuntu cloud-image version {os_version!r}; choose one of: {supported}"
        )
    if memory_mb < 1024 or cpus < 1 or timeout_s < 60:
        raise ValueError("QEMU resources must be at least 1024 MiB, 1 CPU, and a 60 second timeout")
    if not re.fullmatch(r"[1-9][0-9]*[GM]", str(disk_size)):
        raise ValueError("QEMU disk_size must look like 20G or 4096M")

    cve = _safe_id(cve_id)
    suite, image_url = release
    guest_name = guest_configuration.filename(cve)
    guest = guest_script if guest_script is not None else guest_configuration.build(
        environment, configuration, cve_id
    )
    if not guest.startswith("#!/bin/bash") or "\x00" in guest:
        raise ValueError("The embedded guest configuration script is invalid")
    guest_b64 = base64.b64encode(guest.encode("utf-8")).decode("ascii")
    manual_required = "1" if configuration.get("manual_steps") else "0"
    configuration_status = configuration.get("configuration_status") or "unknown"
    instance = f"config-check-{cve}-{suite}"

    return rf'''#!/bin/bash
# Disposable QEMU configuration check for {cve} on Ubuntu {os_version}.
# This wrapper verifies the selected image and validated configuration plan.
# It does not install a vulnerable kernel and does not contain or run a PoC.
set -Eeuo pipefail

SENTINEL={_sq(SENTINEL)}
IMAGE_URL={_sq(image_url)}
RELEASE={_sq(suite)}
USER_HOME="${{HOME:?ERROR: HOME is required to select safe VM storage paths}}"
STATE_ROOT="${{XDG_STATE_HOME:-$USER_HOME/.local/state}}/cve-configuration-qemu"
CACHE_ROOT="${{XDG_CACHE_HOME:-$USER_HOME/.cache}}/cve-reproduction"
WORK_DIR="${{CVE_QEMU_WORK_DIR:-$STATE_ROOT/qemu-check-{cve}}}"
CACHE_DIR="${{CVE_QEMU_CACHE_DIR:-$CACHE_ROOT/qemu-images}}"
BASE_IMAGE="${{CVE_BASE_IMAGE:-$CACHE_DIR/${{RELEASE}}-server-cloudimg-amd64.img}}"
DISK="$WORK_DIR/disk.qcow2"
SEED="$WORK_DIR/seed.img"
SERIAL_LOG="$WORK_DIR/serial.log"
QEMU_ERROR_LOG="$WORK_DIR/qemu-stderr.log"
PID_FILE="$WORK_DIR/qemu.pid"
SSH_KEY="$WORK_DIR/id_ed25519"
SSH_PORT="${{CVE_SSH_PORT:-2222}}"
TIMEOUT_S="${{CVE_QEMU_TIMEOUT:-{timeout_s}}}"
ACTION="${{CVE_ACTION:-create}}"
RESET="${{CVE_RESET:-0}}"
INSTALL_HOST_DEPS="${{CVE_INSTALL_HOST_DEPS:-1}}"
KEEP_ON_TIMEOUT="${{CVE_KEEP_ON_TIMEOUT:-0}}"
APT_SOURCES_FILE="${{CVE_APT_SOURCES_FILE:-}}"
APT_SOURCES_B64=''

if ! [[ "$TIMEOUT_S" =~ ^[0-9]+$ ]] || [ "$TIMEOUT_S" -lt 60 ]; then
  echo "ERROR: CVE_QEMU_TIMEOUT must be an integer of at least 60 seconds" >&2; exit 20
fi
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "ERROR: CVE_SSH_PORT must be an unprivileged TCP port from 1024 to 65535" >&2; exit 20
fi

print_connection() {{
  printf 'ssh -o StrictHostKeyChecking=no -i %q -p %q cve@127.0.0.1\n' "$SSH_KEY" "$SSH_PORT"
}}

if [ "$ACTION" = "stop" ]; then
  if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    kill "$(cat "$PID_FILE")"
    echo "Stopped disposable configuration-check VM"
    exit 0
  fi
  echo "No running configuration-check VM was found" >&2
  exit 1
elif [ "$ACTION" = "status" ]; then
  if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "VM_RUNNING pid=$(cat "$PID_FILE") serial_log=$SERIAL_LOG"
    print_connection
    grep -F "$SENTINEL" "$SERIAL_LOG" | tail -n 1 || true
    exit 0
  fi
  echo "VM_STOPPED serial_log=$SERIAL_LOG"
  [ -r "$SERIAL_LOG" ] && grep -F "$SENTINEL" "$SERIAL_LOG" | tail -n 1 || true
  exit 1
elif [ "$ACTION" = "ssh-command" ]; then
  [ -r "$SSH_KEY" ] || {{ echo "ERROR: SSH key has not been created yet" >&2; exit 1; }}
  print_connection
  exit 0
elif [ "$ACTION" != "create" ]; then
  echo "ERROR: CVE_ACTION must be create, stop, status, or ssh-command" >&2
  exit 20
fi

host_tools_ready() {{
  local tool
  for tool in qemu-system-x86_64 qemu-img cloud-localds curl sha256sum readlink ssh-keygen base64 tr; do
    command -v "$tool" >/dev/null 2>&1 || return 1
  done
}}

install_host_dependencies() {{
  host_tools_ready && return 0
  if [ "$INSTALL_HOST_DEPS" != "1" ]; then
    echo "ERROR: required QEMU host tools are missing and CVE_INSTALL_HOST_DEPS=$INSTALL_HOST_DEPS" >&2
    return 20
  fi
  command -v apt-get >/dev/null 2>&1 || {{
    echo "ERROR: automatic host setup supports apt-based Linux; install QEMU manually" >&2
    return 20
  }}
  local elevate=()
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || {{
      echo "ERROR: sudo is required to install missing QEMU host packages" >&2
      return 20
    }}
    elevate=(sudo)
  fi
  echo "Installing the minimal QEMU host dependencies"
  "${{elevate[@]}}" apt-get update -q
  "${{elevate[@]}}" apt-get install -y \
    qemu-kvm qemu-system-x86 qemu-utils cloud-image-utils curl coreutils openssh-client
}}

install_host_dependencies
for tool in qemu-system-x86_64 qemu-img cloud-localds curl sha256sum readlink ssh-keygen base64 tr; do
  command -v "$tool" >/dev/null 2>&1 || {{ echo "ERROR: missing host tool: $tool" >&2; exit 20; }}
done

if [ -n "$APT_SOURCES_FILE" ]; then
  [ -r "$APT_SOURCES_FILE" ] || {{
    echo "ERROR: CVE_APT_SOURCES_FILE is not readable: $APT_SOURCES_FILE" >&2; exit 23
  }}
  APT_SOURCES_B64="$(base64 < "$APT_SOURCES_FILE" | tr -d '\n')"
fi

mkdir -p "$WORK_DIR" "$CACHE_DIR"
if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "ERROR: VM is already running; use CVE_ACTION=stop before recreating it" >&2
  exit 21
fi
if [ "$RESET" = "1" ]; then
  rm -f -- "$DISK" "$SEED" "$WORK_DIR/user-data" "$WORK_DIR/meta-data" \
    "$SERIAL_LOG" "$QEMU_ERROR_LOG" "$PID_FILE" "$SSH_KEY" "$SSH_KEY.pub"
elif [ -e "$DISK" ] || [ -e "$SEED" ]; then
  echo "ERROR: VM state already exists in $WORK_DIR; set CVE_RESET=1 to recreate it" >&2
  exit 21
fi

if [ ! -r "$BASE_IMAGE" ]; then
  echo "Downloading clean Ubuntu $RELEASE cloud image"
  curl --fail --location --proto '=https' --tlsv1.2 "$IMAGE_URL" -o "$BASE_IMAGE.part"
  curl --fail --location --proto '=https' --tlsv1.2 "${{IMAGE_URL%/*}}/SHA256SUMS" \
    -o "$CACHE_DIR/${{RELEASE}}-SHA256SUMS"
  expected="$(awk -v name="$(basename "$IMAGE_URL")" \
    '$2 == name || $2 == "*" name {{ print $1; exit }}' "$CACHE_DIR/${{RELEASE}}-SHA256SUMS")"
  [ -n "$expected" ] || {{ echo "ERROR: image checksum was not published" >&2; exit 22; }}
  printf '%s  %s\n' "$expected" "$BASE_IMAGE.part" | sha256sum --check --status -
  mv -- "$BASE_IMAGE.part" "$BASE_IMAGE"
  chmod a-w "$BASE_IMAGE"
fi

base_abs="$(readlink -f "$BASE_IMAGE")"
qemu-img create -q -f qcow2 -F qcow2 -b "$base_abs" "$DISK"
qemu-img resize -q "$DISK" {_sq(disk_size)}

if [ ! -r "$SSH_KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C cve-qemu-check -f "$SSH_KEY"
fi
SSH_PUBLIC_KEY="$(cat "$SSH_KEY.pub")"

cat > "$WORK_DIR/meta-data" <<'CVE_META'
instance-id: {instance}
local-hostname: {instance}
CVE_META

cat > "$WORK_DIR/user-data" <<'CVE_USER_DATA'
#cloud-config
users:
  - default
  - name: cve
    groups: [sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - __CVE_SSH_PUBLIC_KEY__
ssh_pwauth: false
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
write_files:
  - path: /usr/local/sbin/{guest_name}
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: {guest_b64}
  - path: /usr/local/sbin/cve-qemu-configuration-check
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/bash
      set -Eeuo pipefail
      APT_SOURCES_B64='__CVE_APT_SOURCES_B64__'
      RESULT_LOG=/var/log/cve-configuration-check.log
      MANUAL_REQUIRED={manual_required}
      CONFIGURATION_STATUS={_sq(configuration_status)}
      if [ -n "$APT_SOURCES_B64" ]; then
        printf '%s' "$APT_SOURCES_B64" | base64 --decode > /etc/apt/sources.list
        rm -f /etc/apt/sources.list.d/ubuntu.sources
        echo 'CVE-QEMU-CHECK: installed user-supplied APT sources'
      fi
      set +e
      /usr/local/sbin/{guest_name} apply 2>&1 | tee "$RESULT_LOG"
      rc="${{PIPESTATUS[0]}}"
      set -e
      if [ "$rc" -eq 0 ]; then
        echo '{SENTINEL} READY automatic_checks_passed=true manual_validation=false'
      elif [ "$CONFIGURATION_STATUS" = unknown ]; then
        echo '{SENTINEL} UNCERTIFIED configuration_decision=unknown configuration_rc='"$rc"
        exit 4
      elif [ "$MANUAL_REQUIRED" = 1 ] && \
           grep -Fq 'manual_steps are present and cannot be automatically certified' "$RESULT_LOG"; then
        echo '{SENTINEL} MANUAL_REQUIRED automatic_checks_passed=true manual_validation=true'
      else
        echo '{SENTINEL} FAILED configuration_rc='"$rc"
        exit "$rc"
      fi
runcmd:
  - [ /usr/local/sbin/cve-qemu-configuration-check ]
final_message: 'CVE-QEMU-CHECK: cloud-init configuration check complete'
CVE_USER_DATA
sed -i "s|__CVE_SSH_PUBLIC_KEY__|$SSH_PUBLIC_KEY|" "$WORK_DIR/user-data"
sed -i "s|__CVE_APT_SOURCES_B64__|$APT_SOURCES_B64|" "$WORK_DIR/user-data"

cloud-localds "$SEED" "$WORK_DIR/user-data" "$WORK_DIR/meta-data"
: > "$SERIAL_LOG"
: > "$QEMU_ERROR_LOG"
ACCEL=(-accel tcg,thread=single)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-accel kvm -cpu host)
else
  echo "NOTICE: /dev/kvm is unavailable; using slower QEMU software emulation" >&2
fi

echo "Starting disposable QEMU configuration check; serial output: $SERIAL_LOG"
if ! qemu-system-x86_64 \
  "${{ACCEL[@]}}" -name {_sq(instance)} -m {memory_mb} -smp {cpus} \
  -display none -monitor none -serial file:"$SERIAL_LOG" \
  -drive file="$DISK",format=qcow2,if=virtio \
  -drive file="$SEED",format=raw,if=virtio,readonly=on \
  -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${{SSH_PORT}}-:22" \
  -boot c -daemonize -pidfile "$PID_FILE" 2>"$QEMU_ERROR_LOG"; then
  echo "ERROR: QEMU failed to launch" >&2
  cat "$QEMU_ERROR_LOG" >&2
  exit 24
fi
if [ ! -s "$PID_FILE" ]; then
  echo "ERROR: QEMU did not create its PID file" >&2
  cat "$QEMU_ERROR_LOG" >&2
  exit 24
fi
vm_pid="$(cat "$PID_FILE")"
if ! kill -0 "$vm_pid" 2>/dev/null; then
  echo "ERROR: QEMU exited immediately after launch" >&2
  cat "$QEMU_ERROR_LOG" >&2
  exit 24
fi

deadline=$((SECONDS + TIMEOUT_S))
while kill -0 "$vm_pid" 2>/dev/null; do
  if grep -Fq "$SENTINEL READY" "$SERIAL_LOG"; then
    echo "RESULT: automatic guest configuration checks PASSED"
    echo "This proves configuration readiness, not CVE exploitability."
    print_connection
    echo "Stop it with: CVE_ACTION=stop $0"
    exit 0
  elif grep -Fq "$SENTINEL MANUAL_REQUIRED" "$SERIAL_LOG"; then
    echo "RESULT: automatic checks PASSED; documented manual prerequisites remain"
    echo "Review configuration.json and complete the manual checks over SSH."
    print_connection
    echo "Stop it with: CVE_ACTION=stop $0"
    exit 3
  elif grep -Fq "$SENTINEL UNCERTIFIED" "$SERIAL_LOG"; then
    echo "RESULT: UNCERTIFIED (official evidence did not support a configuration decision)"
    echo "The VM ran the fail-closed guest script and remains available for diagnosis."
    print_connection
    exit 4
  elif grep -Fq "$SENTINEL FAILED" "$SERIAL_LOG"; then
    echo "RESULT: guest configuration check FAILED"
    tail -n 100 "$SERIAL_LOG" || true
    echo "The VM remains running for diagnosis. Connect with:"
    print_connection
    exit 1
  elif [ "$SECONDS" -ge "$deadline" ]; then
    if [ "$KEEP_ON_TIMEOUT" != "1" ]; then kill "$vm_pid" 2>/dev/null || true; fi
    echo "RESULT: INCONCLUSIVE (configuration-check timeout)" >&2
    tail -n 100 "$SERIAL_LOG" || true
    exit 2
  fi
  sleep 2
done

echo "RESULT: INCONCLUSIVE (VM exited before configuration result)" >&2
tail -n 100 "$SERIAL_LOG" || true
exit 2
'''
