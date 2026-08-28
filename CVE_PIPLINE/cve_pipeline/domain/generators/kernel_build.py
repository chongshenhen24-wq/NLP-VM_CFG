"""Kernel build-from-source generator (host script).

Produces a bash script that, on the Ubuntu build host:
  1. installs the kernel build toolchain
  2. shallow-clones the stable tree at the vulnerable tag (from the resolver)
  3. configures for a QEMU/KVM guest: `make defconfig && make kvm_guest.config`,
     then FORCE-enables exactly what direct-boot + verification need — serial
     console, virtio block (=> /dev/vda), ext4, devtmpfs — and the CVE's
     subsystem options, all built-in (=y) so no module install into the rootfs
  4. runs `make olddefconfig` to resolve deps, then VERIFIES the forced options
     actually stuck (olddefconfig silently drops options whose deps are unmet)
  5. builds bzImage and copies it out

Pure string builder. The config choices here MUST match the launcher/verify
(virtio disk => root=/dev/vda, ttyS0 console).
"""

_STABLE_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"

# Options that make a built kernel boot under QEMU direct-boot and be verifiable.
# scripts/config uses names WITHOUT the CONFIG_ prefix.
_BOOT_OPTS = [
    "SERIAL_8250", "SERIAL_8250_CONSOLE",   # serial output -> ttyS0 (or no sentinel)
    "VIRTIO", "VIRTIO_PCI", "VIRTIO_BLK",   # virtio disk -> /dev/vda
    "EXT4_FS",                               # rootfs
    "DEVTMPFS", "DEVTMPFS_MOUNT",            # /dev
    "BLK_DEV_INITRD",                        # harmless; helps if an initrd is ever used
    "PRINTK",                                # dmesg (Level-2 check)
]


def _norm(opt: str) -> str:
    """CONFIG_FOO or FOO -> FOO (scripts/config wants no prefix)."""
    o = opt.strip()
    return o[len("CONFIG_"):] if o.upper().startswith("CONFIG_") else o


def build_kernel_script(vulnerable_ref: str, config_options=None, subsystem=None,
                        jobs: str = "$(nproc)", src_dir: str = "linux",
                        output: str = "bzImage", source_url: str = _STABLE_URL) -> str:
    ref = vulnerable_ref
    cve_opts = [_norm(o) for o in (config_options or [])]
    all_force = _BOOT_OPTS + cve_opts
    enable_args = " ".join(f"--enable {o}" for o in all_force)
    check_list = " ".join(all_force)

    return f"""#!/bin/bash
# Build the vulnerable kernel from source at {ref}. Runs on the Ubuntu build host.
# Output: a bzImage suitable for QEMU direct-boot (virtio disk, ttyS0 console).
set -euo pipefail

REF={_sh(ref)}
SRC={_sh(src_dir)}
OUT={_sh(output)}

# 1. toolchain
sudo apt-get update -q
sudo apt-get install -y -q build-essential flex bison libssl-dev libelf-dev bc git kmod cpio

# 2. source at the vulnerable tag (shallow clone of just that tag)
if [ ! -d "$SRC" ]; then
  git clone --depth 1 --branch "$REF" {_sh(source_url)} "$SRC"
fi
cd "$SRC"
git checkout "$REF" 2>/dev/null || true
echo "source at: $(git describe --tags 2>/dev/null || git rev-parse --short HEAD)"

# 3. base config tuned for a QEMU/KVM guest, then force what we need
make defconfig
make kvm_guest.config 2>/dev/null || make kvmconfig 2>/dev/null || true   # name varies by version
scripts/config {enable_args}

# 4. resolve deps non-interactively, then confirm the forced options stuck
make olddefconfig
echo "==== config verification ===="
_bad=0
for opt in {check_list}; do
  st=$(scripts/config --state "$opt" 2>/dev/null || echo '?')
  echo "  CONFIG_$opt = $st"
  if [ "$st" != "y" ] && [ "$st" != "m" ]; then
    echo "  WARNING: CONFIG_$opt did not stick (dependency unmet) — boot/verify may fail"
    _bad=$((_bad+1))
  fi
done
if [ "$_bad" -ne 0 ]; then
  echo "ERROR: $_bad required kernel option(s) are missing; refusing to build an invalid reproduction." >&2
  exit 2
fi

# 5. build + export
make -j{jobs} bzImage
cp arch/x86/boot/bzImage "../$OUT"
cd ..
echo "built kernel: $OUT  (ref $REF)"
"""


def _sh(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"
