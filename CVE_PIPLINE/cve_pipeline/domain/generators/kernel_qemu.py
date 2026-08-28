"""QEMU direct-boot kernel-reproduction track.

Boots a freshly built bzImage directly (no bootloader, no reboot) against a
minimal Ubuntu (debootstrap) rootfs, runs the layered verification + a
user-supplied PoC in-guest, and reports the result back to the host over the
serial console via a unique sentinel line.

Three artifacts are generated (all pure string builders):
  build_rootfs_script()  -> host script: debootstrap a minimal Ubuntu disk image
                            with the verify script + PoC baked in, init runs verify
  verify_script()        -> in-guest: 4-level checks, prints ##CVE-RESULT## to serial
  launch_script()        -> host script: qemu-system-x86_64 -kernel ... over serial,
                            then greps the captured serial log for the sentinel

Boundary unchanged: the PoC is a user-supplied input that we RUN and read; no
exploit code is authored or generated here. Success = the PoC's own marker fires
(here: "the vulnerable path was reached"), not necessarily privilege escalation.
"""

SENTINEL = "##CVE-RESULT##"


def _sq(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


# --------------------------------------------------------------------------- #
#  In-guest verification (adapted from the tested verifier: serial sentinel)   #
# --------------------------------------------------------------------------- #
def verify_script(vulnerable_ref, subsystem=None, config_options=None,
                  kallsyms_symbols=None, modules=None,
                  poc_cmd=None, poc_success=None) -> str:
    rel = (vulnerable_ref or "").lstrip("vV")
    config_options = config_options or []
    kallsyms_symbols = kallsyms_symbols or []
    modules = modules or []

    L = ["#!/bin/bash",
         "# In-guest kernel verification. Prints a sentinel to serial for the host.",
         "set -u",
         "PASS=0; FAIL=0",
         'check() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $l"; PASS=$((PASS+1)); else echo "FAIL  $l"; FAIL=$((FAIL+1)); fi; }',
         'note()  { echo "----  $*"; }']

    L += ['note "Level 1: kernel version"',
          f'echo "    running: $(uname -r)   expected-prefix: {rel}"',
          'check "uname -r matches built ref" bash -c ' + _sq(f'[[ "$(uname -r)" == "{rel}"* ]]')]

    L += ['note "Level 2: clean boot"',
          'check "system not failed" bash -c ' + _sq('[[ "$(systemctl is-system-running 2>/dev/null)" != "failed" ]]'),
          'check "no oops/BUG/panic in dmesg" bash -c ' + _sq('! dmesg 2>/dev/null | grep -Eiq "kernel BUG|Oops|call trace|kernel panic|general protection fault"'),
          'check "uptime sane" bash -c ' + _sq('[[ "$(cut -d. -f1 /proc/uptime)" -ge 2 ]]')]

    L += ['note ' + _sq("Level 3: vulnerable subsystem present" + (f" ({subsystem})" if subsystem else ""))]
    if not (config_options or kallsyms_symbols or modules):
        L.append('echo "    (no subsystem markers provided; supply config/kallsyms/modules)"')
    for opt in config_options:
        L.append(f'check "config {opt} enabled" bash -c ' + _sq(f'(zcat /proc/config.gz 2>/dev/null; cat /boot/config-$(uname -r) 2>/dev/null) | grep -Eq "^{opt}=(y|m)"'))
    for sym in kallsyms_symbols:
        L.append(f'check "symbol {sym} in kallsyms" bash -c ' + _sq(f'grep -qi "{sym}" /proc/kallsyms'))
    for mod in modules:
        L.append(f'check "module {mod} present/built-in" bash -c ' + _sq(f'modinfo {mod} >/dev/null 2>&1 || grep -qi "{mod}" /proc/kallsyms'))

    L += ['note "Level 4: PoC (user-supplied; presence-of-bug marker)"']
    if not poc_cmd:
        L.append('echo "FAIL  no PoC provided; vulnerability was not exercised"')
        L.append('FAIL=$((FAIL+1))')
    else:
        L += ['note ' + _sq("running PoC: " + poc_cmd),
              'runuser -u cvepoc -- bash -c ' + _sq(poc_cmd) + ' || true    # exit code untrusted; marker decides',
              'check "PoC success condition (bug reached)" bash -c ' + _sq(poc_success or 'false')]

    # sentinel to serial, then power off so QEMU exits
    L += ['echo "    PASS=$PASS  FAIL=$FAIL"',
          f'if [[ $FAIL -eq 0 ]]; then echo "{SENTINEL} VERIFIED"; else echo "{SENTINEL} FAILED"; fi',
          'sync',
          '(command -v poweroff >/dev/null && poweroff -f) || echo o > /proc/sysrq-trigger || true']
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
#  Host: build a minimal Ubuntu rootfs disk image via debootstrap             #
# --------------------------------------------------------------------------- #
def build_rootfs_script(ubuntu_suite="jammy", image="rootfs.img", size_mb=1024,
                        verify_path="verify_kernel.sh", poc_path=None) -> str:
    poc_copy = (f'sudo install -d -m 0755 "$MNT/opt/cve" && sudo cp {_sq(poc_path)} "$MNT/opt/cve/poc" && sudo chmod 0755 "$MNT/opt/cve/poc"'
                if poc_path else 'echo "no PoC supplied - /opt/cve/poc absent"')
    return f"""#!/bin/bash
# Build a minimal Ubuntu ({ubuntu_suite}) rootfs disk image for QEMU direct-boot.
# Requires: debootstrap, mkfs.ext4, root (sudo). Runs on the Ubuntu build host.
set -eux
IMG={_sq(image)}
MNT=$(mktemp -d)

# 0. host tools required by this script and the launcher
sudo apt-get update -q
sudo apt-get install -y -q debootstrap qemu-utils qemu-system-x86 e2fsprogs

# 1. blank ext4 image
qemu-img create -f raw "$IMG" {size_mb}M
mkfs.ext4 -F "$IMG"
sudo mount -o loop "$IMG" "$MNT"

# 2. minimal Ubuntu userspace (glibc, systemd, bash) â€” small variant
sudo debootstrap --variant=minbase --include=systemd,systemd-sysv,kmod,udev,passwd,util-linux {ubuntu_suite} "$MNT" http://archive.ubuntu.com/ubuntu/

# 3. bake in the verify script + PoC; make verify run at boot then power off
sudo cp {_sq(verify_path)} "$MNT/root/verify_kernel.sh" && sudo chmod +x "$MNT/root/verify_kernel.sh"
{poc_copy}
sudo chroot "$MNT" useradd --create-home --shell /bin/bash cvepoc
sudo tee "$MNT/etc/systemd/system/cve-verify.service" >/dev/null <<UNIT
[Unit]
Description=CVE kernel verification
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/root/verify_kernel.sh
StandardOutput=journal+console
[Install]
WantedBy=multi-user.target
UNIT
sudo ln -sf /etc/systemd/system/cve-verify.service "$MNT/etc/systemd/system/multi-user.target.wants/cve-verify.service"
sudo bash -c 'echo "root:root" | chpasswd -R "$MNT"' || true

sudo umount "$MNT"; rmdir "$MNT"
echo "rootfs image ready: $IMG"
"""


# --------------------------------------------------------------------------- #
#  Host: launch QEMU direct-boot, capture serial, read the sentinel           #
# --------------------------------------------------------------------------- #
def launch_script(bzimage="bzImage", image="rootfs.img", memory_mb=2048,
                  serial_log="serial.log", timeout_s=180, append_extra="") -> str:
    append = f"console=ttyS0 root=/dev/vda rw {append_extra}".strip()
    return f"""#!/bin/bash
# Direct-boot the built kernel in QEMU and read the result from the serial log.
# Runs on the Ubuntu build host. No bootloader, no reboot.
set -u
BZ={_sq(bzimage)}
IMG={_sq(image)}
LOG={_sq(serial_log)}

KVM=""
[ -e /dev/kvm ] && KVM="-enable-kvm -cpu host"   # fast if KVM available; else TCG

: > "$LOG"
timeout {timeout_s} qemu-system-x86_64 \\
  $KVM -m {memory_mb} -no-reboot -nographic -nic none -nodefaults \\
  -kernel "$BZ" \\
  -drive file="$IMG",format=raw,if=virtio \\
  -append {_sq(append)} \\
  -serial file:"$LOG" \\
  || true   # timeout/poweroff is expected; result comes from the log

echo "---- serial tail ----"; tail -n 20 "$LOG"
if grep -q "{SENTINEL} VERIFIED" "$LOG"; then
  echo "RESULT: kernel reproduction VERIFIED"; exit 0
elif grep -q "{SENTINEL} FAILED" "$LOG"; then
  echo "RESULT: verification FAILED"; exit 1
else
  echo "RESULT: INCONCLUSIVE (no sentinel â€” kernel may have panicked or not booted; check $LOG)"; exit 2
fi
"""

