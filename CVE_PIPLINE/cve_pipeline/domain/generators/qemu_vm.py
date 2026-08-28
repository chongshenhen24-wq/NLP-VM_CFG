"""Generate a VM-only QEMU lifecycle script for configuration evaluation."""
from __future__ import annotations

import base64
import re

from . import environment_identity


SENTINEL = "##CVE-VM-RESULT##"
KERNEL_SENTINEL = "##CVE-ENV-RESULT##"
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
    return f"build_qemu_{_safe_id(cve_id)}.sh"


def build(
    environment: dict,
    cve_id: str,
    *,
    memory_mb: int = 4096,
    cpus: int = 2,
    disk_size: str = "20G",
    timeout_s: int = 1800,
    kernel_script: str | None = None,
) -> str:
    """Build a host script that creates the exact selected vulnerable VM."""
    try:
        os_version, selected_suite = environment_identity.validate_selected_ubuntu(environment)
    except ValueError as exc:
        message = str(exc).replace("QEMU workflow", "QEMU VM creation")
        raise ValueError(message) from exc
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
    if suite != selected_suite:  # Keep the image table and selection validator fail-closed.
        raise ValueError("Internal Ubuntu release mapping mismatch")
    environment_id = environment_identity.fingerprint(environment, cve_id)
    kernel_target = environment_identity.validate_selected_kernel_target(environment)
    if not kernel_script or not kernel_script.startswith("#!/bin/bash") or "\x00" in kernel_script:
        raise ValueError(
            "Vulnerable QEMU construction requires the deterministic kernel provisioning script"
        )
    for variable, value in (
        ("TARGET_META_VERSION", kernel_target["meta_package_version"]),
        ("TARGET_KERNEL_RELEASE", kernel_target["running_kernel_release"]),
    ):
        if not re.search(
            rf"^{variable}={re.escape(_sq(value))}$", kernel_script, flags=re.MULTILINE
        ):
            raise ValueError(
                "Kernel provisioning payload does not match the selected exact build target"
            )
    kernel_payload = base64.b64encode(kernel_script.encode("utf-8")).decode("ascii")
    kernel_constraint = str(
        (environment.get("vulnerable_constraints") or {}).get(
            "running_kernel_package_constraint"
        ) or ""
    )
    instance = f"cve-vm-{cve}-{suite}"
    return rf'''#!/bin/bash
# Disposable QEMU VM builder for {cve} on Ubuntu {os_version}.
# This script builds the exact evidence-backed OS/kernel target. It contains no
# NLP-generated extra configuration and never runs a PoC.
set -Eeuo pipefail

SENTINEL={_sq(SENTINEL)}
KERNEL_SENTINEL={_sq(KERNEL_SENTINEL)}
ENVIRONMENT_ID={_sq(environment_id)}
EXPECTED_OS='ubuntu'
EXPECTED_OS_VERSION={_sq(os_version)}
KERNEL_PACKAGE_CONSTRAINT={_sq(kernel_constraint)}
EXPECTED_KERNEL_RELEASE={_sq(kernel_target['running_kernel_release'])}
IMAGE_URL={_sq(image_url)}
RELEASE={_sq(suite)}
USER_HOME="${{HOME:?ERROR: HOME is required to select safe VM storage paths}}"
STATE_ROOT="${{XDG_STATE_HOME:-$USER_HOME/.local/state}}/cve-configuration-qemu"
CACHE_ROOT="${{XDG_CACHE_HOME:-$USER_HOME/.cache}}/cve-reproduction"
WORK_DIR="${{CVE_QEMU_WORK_DIR:-$STATE_ROOT/qemu-build-{cve}}}"
CACHE_DIR="${{CVE_QEMU_CACHE_DIR:-$CACHE_ROOT/qemu-images}}"
BASE_IMAGE="${{CVE_BASE_IMAGE:-$CACHE_DIR/${{RELEASE}}-server-cloudimg-amd64.img}}"
DISK="$WORK_DIR/disk.qcow2"
SEED="$WORK_DIR/seed.img"
SERIAL_LOG="$WORK_DIR/serial.log"
QEMU_ERROR_LOG="$WORK_DIR/qemu-stderr.log"
PID_FILE="$WORK_DIR/qemu.pid"
ENVIRONMENT_FILE="$WORK_DIR/environment.identity"
SSH_KEY="$WORK_DIR/id_ed25519"
SSH_PORT="${{CVE_SSH_PORT:-2222}}"
TIMEOUT_S="${{CVE_QEMU_TIMEOUT:-{timeout_s}}}"
ACTION="${{CVE_ACTION:-create}}"
RESET="${{CVE_RESET:-0}}"
INSTALL_HOST_DEPS="${{CVE_INSTALL_HOST_DEPS:-1}}"
KEEP_ON_TIMEOUT="${{CVE_KEEP_ON_TIMEOUT:-0}}"

if ! [[ "$TIMEOUT_S" =~ ^[0-9]+$ ]] || [ "$TIMEOUT_S" -lt 60 ]; then
  echo "ERROR: CVE_QEMU_TIMEOUT must be an integer of at least 60 seconds" >&2; exit 20
fi
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "ERROR: CVE_SSH_PORT must be an unprivileged TCP port from 1024 to 65535" >&2; exit 20
fi

print_connection() {{
  printf 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i %q -p %q cve@127.0.0.1\n' "$SSH_KEY" "$SSH_PORT"
}}

if [ "$ACTION" = stop ]; then
  if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    kill "$(cat "$PID_FILE")"
    echo "Stopped disposable QEMU VM"
    exit 0
  fi
  echo "No running QEMU VM was found" >&2; exit 1
elif [ "$ACTION" = status ]; then
  if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "VM_RUNNING pid=$(cat "$PID_FILE") serial_log=$SERIAL_LOG environment_id=$ENVIRONMENT_ID"
    print_connection
    grep -E "$(printf '%s|%s' "$SENTINEL" "$KERNEL_SENTINEL")" "$SERIAL_LOG" | tail -n 1 || true
    exit 0
  fi
  echo "VM_STOPPED serial_log=$SERIAL_LOG"
  [ -r "$SERIAL_LOG" ] && grep -E "$(printf '%s|%s' "$SENTINEL" "$KERNEL_SENTINEL")" "$SERIAL_LOG" | tail -n 1 || true
  exit 1
elif [ "$ACTION" = ssh-command ]; then
  [ -r "$SSH_KEY" ] || {{ echo "ERROR: SSH key has not been created" >&2; exit 1; }}
  print_connection
  exit 0
elif [ "$ACTION" != create ]; then
  echo "ERROR: CVE_ACTION must be create, stop, status, or ssh-command" >&2; exit 20
fi

host_tools_ready() {{
  local tool
  for tool in qemu-system-x86_64 qemu-img cloud-localds curl sha256sum readlink ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 || return 1
  done
}}

install_host_dependencies() {{
  host_tools_ready && return 0
  if [ "$INSTALL_HOST_DEPS" != 1 ]; then
    echo "ERROR: required QEMU host tools are missing and automatic installation is disabled" >&2
    return 20
  fi
  command -v apt-get >/dev/null 2>&1 || {{
    echo "ERROR: automatic host setup supports apt-based Linux; install QEMU manually" >&2
    return 20
  }}
  local elevate=()
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || {{ echo "ERROR: sudo is required" >&2; return 20; }}
    elevate=(sudo)
  fi
  echo "Installing minimal QEMU host dependencies"
  "${{elevate[@]}}" apt-get update -q
  "${{elevate[@]}}" apt-get install -y \
    qemu-kvm qemu-system-x86 qemu-utils cloud-image-utils curl coreutils openssh-client
}}

install_host_dependencies
for tool in qemu-system-x86_64 qemu-img cloud-localds curl sha256sum readlink ssh-keygen; do
  command -v "$tool" >/dev/null 2>&1 || {{ echo "ERROR: missing host tool: $tool" >&2; exit 20; }}
done

mkdir -p "$WORK_DIR" "$CACHE_DIR"
if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "ERROR: VM is already running; use CVE_ACTION=stop first" >&2; exit 21
fi
if [ "$RESET" = 1 ]; then
  rm -f -- "$DISK" "$SEED" "$WORK_DIR/user-data" "$WORK_DIR/meta-data" \
    "$SERIAL_LOG" "$QEMU_ERROR_LOG" "$PID_FILE" "$ENVIRONMENT_FILE" \
    "$SSH_KEY" "$SSH_KEY.pub"
elif [ -e "$DISK" ] || [ -e "$SEED" ]; then
  echo "ERROR: VM state exists in $WORK_DIR; set CVE_RESET=1 to recreate it" >&2; exit 21
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
ssh-keygen -q -t ed25519 -N '' -C cve-qemu-builder -f "$SSH_KEY"
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
  - path: /usr/local/sbin/cve-kernel-target
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: {kernel_payload}
runcmd:
  - [ env, CVE_AUTO_REBOOT=1, /usr/local/sbin/cve-kernel-target, prepare ]
final_message: 'CVE-QEMU: initial provisioning stage complete'
CVE_USER_DATA
sed -i "s|__CVE_SSH_PUBLIC_KEY__|$SSH_PUBLIC_KEY|" "$WORK_DIR/user-data"

cloud-localds "$SEED" "$WORK_DIR/user-data" "$WORK_DIR/meta-data"
printf '%s\n' "$ENVIRONMENT_ID" > "$ENVIRONMENT_FILE"
: > "$SERIAL_LOG"
: > "$QEMU_ERROR_LOG"
ACCEL=(-accel tcg,thread=single)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-accel kvm -cpu host)
else
  echo "NOTICE: /dev/kvm is unavailable; using slower QEMU software emulation" >&2
fi

echo "Starting disposable QEMU VM; serial output: $SERIAL_LOG"
if ! qemu-system-x86_64 \
  "${{ACCEL[@]}}" -name {_sq(instance)} -m {memory_mb} -smp {cpus} \
  -display none -monitor none -serial file:"$SERIAL_LOG" \
  -drive file="$DISK",format=qcow2,if=virtio \
  -drive file="$SEED",format=raw,if=virtio,readonly=on \
  -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${{SSH_PORT}}-:22" \
  -boot c -daemonize -pidfile "$PID_FILE" 2>"$QEMU_ERROR_LOG"; then
  echo "ERROR: QEMU failed to launch" >&2; cat "$QEMU_ERROR_LOG" >&2; exit 24
fi
[ -s "$PID_FILE" ] || {{ echo "ERROR: QEMU did not create its PID file" >&2; exit 24; }}
vm_pid="$(cat "$PID_FILE")"
kill -0 "$vm_pid" 2>/dev/null || {{ echo "ERROR: QEMU exited immediately" >&2; exit 24; }}

deadline=$((SECONDS + TIMEOUT_S))
while kill -0 "$vm_pid" 2>/dev/null; do
  if grep -Fq "$KERNEL_SENTINEL READY" "$SERIAL_LOG"; then
    echo "$SENTINEL READY exact_kernel=$EXPECTED_KERNEL_RELEASE environment_id=$ENVIRONMENT_ID"
    echo "RESULT: EXACT_KERNEL_VM_BUILT"
    print_connection
    echo "The full environment is not READY yet. Next: run check_configuration_{cve}.sh from the same host."
    exit 0
  elif [ "$SECONDS" -ge "$deadline" ]; then
    if [ "$KEEP_ON_TIMEOUT" != 1 ]; then kill "$vm_pid" 2>/dev/null || true; fi
    echo "RESULT: INCONCLUSIVE (VM boot timeout)" >&2; tail -n 100 "$SERIAL_LOG" || true; exit 2
  fi
  sleep 2
done

echo "RESULT: INCONCLUSIVE (VM exited before cloud-init completed)" >&2
tail -n 100 "$SERIAL_LOG" || true
exit 2
'''
