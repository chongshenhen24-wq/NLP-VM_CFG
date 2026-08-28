"""Kernel reproduction orchestrator (pure/offline part).

Given a resolved vulnerable ref + the CVE's subsystem markers + a user-supplied
PoC, emit the four scripts that make up one kernel reproduction, into
machines/<CVE>/:

    build_kernel.sh    host: git checkout ref -> config -> make bzImage
    build_rootfs.sh    host: debootstrap a minimal Ubuntu disk image
    verify_kernel.sh   guest: 4-level checks -> serial sentinel  (baked into rootfs)
    run_qemu.sh        host: direct-boot bzImage + rootfs, read the sentinel

This is deliberately offline (no network): resolution (which needs OSV/NVD/Ollama)
happens separately via `resolve-kernel`; this just materialises the scripts from
already-resolved values so it is fully testable.
"""
import os

from .domain.generators import kernel_build, kernel_qemu


def emit_kernel_scripts(cve_id: str, vulnerable_ref: str, out_dir: str,
                        config_options=None, subsystem=None, kallsyms_symbols=None,
                        modules=None, poc_cmd=None, poc_success=None,
                        ubuntu_suite="jammy", bzimage="bzImage", image="rootfs.img",
                        poc_path=None, poc_args="") -> dict:
    machine = os.path.join(out_dir, cve_id)
    os.makedirs(machine, exist_ok=True)

    host_poc = poc_path
    if not host_poc and poc_cmd and os.path.sep in str(poc_cmd) and " " not in str(poc_cmd):
        host_poc = str(poc_cmd)
    guest_poc_cmd = (("/opt/cve/poc" + (" " + poc_args.strip() if poc_args.strip() else ""))
                     if host_poc else poc_cmd)
    verify = kernel_qemu.verify_script(
        vulnerable_ref, subsystem=subsystem, config_options=config_options,
        kallsyms_symbols=kallsyms_symbols, modules=modules,
        poc_cmd=guest_poc_cmd, poc_success=poc_success)
    build = kernel_build.build_kernel_script(
        vulnerable_ref, config_options=config_options, subsystem=subsystem, output=bzimage)
    rootfs = kernel_qemu.build_rootfs_script(
        ubuntu_suite=ubuntu_suite, image=image, verify_path="verify_kernel.sh",
        poc_path=host_poc)
    launch = kernel_qemu.launch_script(bzimage=bzimage, image=image)

    written = {}
    for name, content in [("verify_kernel.sh", verify), ("build_kernel.sh", build),
                          ("build_rootfs.sh", rootfs), ("run_qemu.sh", launch)]:
        path = os.path.join(machine, name)
        with open(path, "w", newline="\n") as f:
            f.write(content)
        os.chmod(path, 0o755)
        written[name] = path
    return written

