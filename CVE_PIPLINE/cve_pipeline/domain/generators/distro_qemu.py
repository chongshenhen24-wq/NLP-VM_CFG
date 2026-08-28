"""Disposable Ubuntu cloud-image QEMU wrapper for a distro kernel recipe."""

from __future__ import annotations

import base64
import re

from . import distro_kernel


SENTINEL = "##CVE-ENV-RESULT##"
_UBUNTU_RELEASES = {
    "20.04": ("focal", "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"),
    "21.10": ("impish", "https://cloud-images.ubuntu.com/releases/impish/release/ubuntu-21.10-server-cloudimg-amd64.img"),
    "22.04": ("jammy", "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"),
    "24.04": ("noble", "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"),
}
_ARCHIVED_APT_SOURCES = {
    "impish": (
        "deb https://old-releases.ubuntu.com/ubuntu impish main restricted universe multiverse\n"
        "deb https://old-releases.ubuntu.com/ubuntu impish-updates main restricted universe multiverse\n"
        "deb https://old-releases.ubuntu.com/ubuntu impish-security main restricted universe multiverse\n"
    ),
}


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value or "kernel-cve")


def _sq(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def filename(cve_id: str) -> str:
    return f"run_qemu_{_safe_id(cve_id)}.sh"


def build(spec: dict, cve_id: str = "", memory_mb: int = 4096, cpus: int = 2,
          disk_size: str = "20G", timeout_s: int = 1800) -> str:
    """Create one host script: clean image, overlay, reboot, and kernel verification."""
    if (spec.get("os_family") or "").strip().lower() != "ubuntu":
        raise ValueError("The QEMU cloud-image workflow currently supports Ubuntu only")
    os_version = (spec.get("os_version") or "").strip()
    release = _UBUNTU_RELEASES.get(os_version)
    if not release:
        supported = ", ".join(sorted(_UBUNTU_RELEASES))
        raise ValueError(f"Unsupported Ubuntu cloud-image version {os_version!r}; choose one of: {supported}")
    if memory_mb < 1024 or cpus < 1 or timeout_s < 60:
        raise ValueError("QEMU resources must be at least 1024 MiB, 1 CPU, and a 60 second timeout")
    if not re.fullmatch(r"[1-9][0-9]*[GM]", str(disk_size)):
        raise ValueError("QEMU disk_size must look like 20G or 4096M")

    suite, image_url = release
    default_sources_b64 = base64.b64encode(
        _ARCHIVED_APT_SOURCES.get(suite, "").encode("utf-8")
    ).decode("ascii")
    cve = _safe_id(cve_id or "kernel-cve")
    guest = distro_kernel.build(spec, auto_reboot=False)
    guest_b64 = base64.b64encode(guest.encode("utf-8")).decode("ascii")
    instance = f"{cve}-{suite}"

    return f'''#!/bin/bash
# Disposable QEMU reproduction environment for {cve} on Ubuntu {os_version}.
# The embedded guest recipe came from the NLP-extracted kernel specification.
# Missing minimal host packages are installed on apt-based Linux by default.
# PoC validation is intentionally outside this environment-generation script.
set -Eeuo pipefail

SENTINEL={_sq(SENTINEL)}
IMAGE_URL={_sq(image_url)}
RELEASE={_sq(suite)}
USER_HOME="${{HOME:?ERROR: HOME is required to select safe VM storage paths}}"
STATE_ROOT="${{XDG_STATE_HOME:-$USER_HOME/.local/state}}/cve-reproduction"
CACHE_ROOT="${{XDG_CACHE_HOME:-$USER_HOME/.cache}}/cve-reproduction"
WORK_DIR="${{CVE_QEMU_WORK_DIR:-$STATE_ROOT/qemu-{cve}}}"
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
if ! [[ "$TIMEOUT_S" =~ ^[0-9]+$ ]] || [ "$TIMEOUT_S" -lt 60 ]; then
  echo "ERROR: CVE_QEMU_TIMEOUT must be an integer of at least 60 seconds" >&2; exit 20
fi
ACTION="${{CVE_ACTION:-create}}"
RESET="${{CVE_RESET:-0}}"
INSTALL_HOST_DEPS="${{CVE_INSTALL_HOST_DEPS:-1}}"
APT_SOURCES_FILE="${{CVE_APT_SOURCES_FILE:-}}"
APT_SOURCES_B64={_sq(default_sources_b64)}

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

need() {{ command -v "$1" >/dev/null 2>&1 || {{ echo "ERROR: missing host tool: $1" >&2; exit 20; }}; }}
for tool in qemu-system-x86_64 qemu-img cloud-localds curl sha256sum readlink ssh-keygen base64 tr; do need "$tool"; done

if [ -n "$APT_SOURCES_FILE" ]; then
  [ -r "$APT_SOURCES_FILE" ] || {{ echo "ERROR: CVE_APT_SOURCES_FILE is not readable: $APT_SOURCES_FILE" >&2; exit 23; }}
  APT_SOURCES_B64="$(base64 < "$APT_SOURCES_FILE" | tr -d '\n')"
fi

if [ "$ACTION" = "stop" ]; then
  if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    kill "$(cat "$PID_FILE")"
    echo "Stopped disposable VM"
    exit 0
  fi
  echo "No running VM was found" >&2
  exit 1
elif [ "$ACTION" != "create" ]; then
  echo "ERROR: CVE_ACTION must be create or stop" >&2
  exit 20
fi

virt_type="$(systemd-detect-virt 2>/dev/null || true)"
if [ "$virt_type" = "wsl" ] && [ ! -r /dev/kvm ]; then
  echo "NOTICE: WSL has no accessible /dev/kvm; QEMU will use slower software emulation" >&2
fi

mkdir -p "$WORK_DIR" "$CACHE_DIR"
if [ -r "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "ERROR: VM is already running; use CVE_ACTION=stop before recreating it" >&2
  exit 21
fi
if [ "$RESET" = "1" ]; then
  rm -f -- "$DISK" "$SEED" "$WORK_DIR/user-data" "$WORK_DIR/meta-data" "$SERIAL_LOG" "$QEMU_ERROR_LOG" "$PID_FILE" "$SSH_KEY" "$SSH_KEY.pub"
elif [ -e "$DISK" ] || [ -e "$SEED" ]; then
  echo "ERROR: disposable VM already exists in $WORK_DIR; set CVE_RESET=1 to recreate it" >&2
  exit 21
fi

if [ ! -r "$BASE_IMAGE" ]; then
  echo "Downloading clean Ubuntu $RELEASE cloud image"
  curl --fail --location --proto '=https' --tlsv1.2 "$IMAGE_URL" -o "$BASE_IMAGE.part"
  curl --fail --location --proto '=https' --tlsv1.2 "${{IMAGE_URL%/*}}/SHA256SUMS" -o "$CACHE_DIR/SHA256SUMS"
  expected="$(awk -v name="$(basename "$IMAGE_URL")" '$2 == name || $2 == "*" name {{ print $1; exit }}' "$CACHE_DIR/SHA256SUMS")"
  [ -n "$expected" ] || {{ echo "ERROR: image checksum was not published" >&2; exit 22; }}
  printf '%s  %s\n' "$expected" "$BASE_IMAGE.part" | sha256sum --check --status -
  mv -- "$BASE_IMAGE.part" "$BASE_IMAGE"
  chmod a-w "$BASE_IMAGE"
fi

base_abs="$(readlink -f "$BASE_IMAGE")"
qemu-img create -q -f qcow2 -F qcow2 -b "$base_abs" "$DISK"
qemu-img resize -q "$DISK" {_sq(disk_size)}

if [ ! -r "$SSH_KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C cve-qemu -f "$SSH_KEY"
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
  - path: /usr/local/sbin/cve-kernel-reproduction
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: {guest_b64}
  - path: /usr/local/sbin/cve-qemu-first-boot
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/bash
      set -u
      APT_SOURCES_B64='__CVE_APT_SOURCES_B64__'
      if [ -n "$APT_SOURCES_B64" ]; then
        printf '%s' "$APT_SOURCES_B64" | base64 --decode > /etc/apt/sources.list
        rm -f /etc/apt/sources.list.d/ubuntu.sources
        echo 'CVE-QEMU: installed user-supplied APT sources'
      fi
      if /usr/local/sbin/cve-kernel-reproduction prepare; then
        systemctl daemon-reload
        state="$(/usr/local/sbin/cve-kernel-reproduction status)"
        case "$state" in
          READY[[:space:]]*)
            echo 'CVE-QEMU: selected kernel is already running; no reboot required'
            ;;
          PREPARED[[:space:]]*reboot_required=true*)
            echo 'CVE-QEMU: environment prepared; reboot scheduled'
            shutdown -r +1 'Booting the selected CVE kernel'
            ;;
          *)
            echo '##CVE-ENV-RESULT## FAILED unexpected_prepare_state'
            shutdown -h +1 'CVE environment preparation returned an invalid state'
            exit 48
            ;;
        esac
      else
        rc=$?
        echo '##CVE-ENV-RESULT## FAILED prepare_rc='"$rc"
        shutdown -h +1 'CVE environment preparation failed'
        exit "$rc"
      fi
runcmd:
  - [ /usr/local/sbin/cve-qemu-first-boot ]
final_message: 'CVE-QEMU: cloud-init first boot complete'
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
  echo "NOTICE: /dev/kvm is unavailable; using legacy-compatible single-threaded QEMU software emulation" >&2
fi

echo "Starting disposable QEMU VM; serial output: $SERIAL_LOG"
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
  if grep -q "$SENTINEL READY" "$SERIAL_LOG"; then
    echo "RESULT: vulnerable kernel environment READY for manual validation"
    echo "VM remains running. Connect with:"
    printf 'ssh -o StrictHostKeyChecking=no -i %q -p %q cve@127.0.0.1\n' "$SSH_KEY" "$SSH_PORT"
    echo "Stop it with: CVE_ACTION=stop $0"
    exit 0
  elif grep -q "$SENTINEL FAILED" "$SERIAL_LOG"; then
    echo "RESULT: environment verification FAILED"
    tail -n 80 "$SERIAL_LOG" || true
    exit 1
  elif [ "$SECONDS" -ge "$deadline" ]; then
    kill "$vm_pid" 2>/dev/null || true
    echo "RESULT: INCONCLUSIVE (verification timeout; VM stopped)" >&2
    tail -n 80 "$SERIAL_LOG" || true
    exit 2
  fi
  sleep 2
done

echo "RESULT: INCONCLUSIVE (VM exited before post-reboot verification)" >&2
tail -n 80 "$SERIAL_LOG" || true
exit 2
'''

