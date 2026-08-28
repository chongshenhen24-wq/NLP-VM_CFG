import base64
import os
import re
import subprocess
import tempfile
import unittest

from cve_pipeline.domain.generators import distro_qemu
from cve_pipeline.interfaces.server import Handler
from official_fixtures import official_bundle


SPEC = {
    "package": "linux-image-generic",
    "package_manager": "apt",
    "version_constraint": "<6.8.0-124.124",
    "concrete_kernel_constraint": "<6.8.0-124.124",
    "os_family": "ubuntu",
    "os_version": "24.04",
    "config_directives": [],
    "setup_commands": [],
}


def embedded_guest(host_script: str) -> str:
    match = re.search(
        r"path: /usr/local/sbin/cve-kernel-reproduction.*?content: ([A-Za-z0-9+/=]+)",
        host_script,
        re.S,
    )
    if not match:
        raise AssertionError("embedded guest recipe was not found")
    return base64.b64decode(match.group(1)).decode("utf-8")


class DistroQemuTests(unittest.TestCase):
    def test_generates_disposable_cloud_image_workflow(self):
        script = distro_qemu.build(SPEC, "CVE-2026-46333")
        guest = embedded_guest(script)

        self.assertIn("cloud-images.ubuntu.com/noble/current", script)
        self.assertIn("/SHA256SUMS", script)
        self.assertIn("sha256sum --check --status", script)
        self.assertIn("qemu-img create -q -f qcow2 -F qcow2 -b", script)
        self.assertIn('cloud-localds "$SEED"', script)
        self.assertIn("shutdown -r +1", script)
        self.assertIn('##CVE-ENV-RESULT## READY', guest)
        self.assertIn("CONCRETE_CONSTRAINT='<6.8.0-124.124'", guest)
        self.assertIn("concrete_package_version=", guest)
        self.assertIn("FAILED concrete_kernel_constraint", guest)
        self.assertIn("manual_validation=true", guest)
        self.assertNotIn("POC_", guest)
        self.assertNotIn("runuser", guest)
        self.assertNotIn("VERIFIED", guest)
        self.assertIn("StandardOutput=journal+console", guest)
        self.assertNotIn("-no-reboot", script)
        self.assertIn("hostfwd=tcp:127.0.0.1:", script)
        self.assertIn("CVE_RESET", script)
        self.assertIn("CVE_QEMU_TIMEOUT", script)
        self.assertIn("deadline=$((SECONDS + TIMEOUT_S))", script)
        self.assertIn("CVE_INSTALL_HOST_DEPS", script)
        self.assertIn("CVE_APT_SOURCES_FILE", script)
        self.assertIn("installed user-supplied APT sources", script)
        self.assertIn("APT repository update failed", guest)
        self.assertIn("XDG_STATE_HOME", script)
        self.assertIn("XDG_CACHE_HOME", script)
        self.assertNotIn("$PWD/qemu-", script)
        self.assertIn("apt-get install -y", script)
        self.assertIn("qemu-kvm qemu-system-x86 qemu-utils cloud-image-utils", script)
        self.assertIn("openssh-client", script)
        self.assertIn("ssh-keygen", script)
        self.assertIn("name: cve", script)
        self.assertIn("ssh_authorized_keys", script)
        self.assertIn('-daemonize -pidfile "$PID_FILE"', script)
        self.assertIn("VM remains running", script)
        self.assertIn("CVE_ACTION=stop", script)
        self.assertNotIn("cve-qemu-finalize.service", script)
        self.assertNotIn("systemctl poweroff", script)
        self.assertIn("selected kernel is already running; no reboot required", script)
        self.assertIn("PREPARED[[:space:]]*reboot_required=true", script)
        self.assertIn('virt_type="$(systemd-detect-virt', script)
        self.assertIn("WSL has no accessible /dev/kvm", script)
        self.assertIn("ACCEL=(-accel tcg,thread=single)", script)
        self.assertIn("legacy-compatible single-threaded QEMU software emulation", script)
        self.assertIn("qemu-stderr.log", script)
        self.assertIn("ERROR: QEMU failed to launch", script)
        self.assertIn('if [ ! -s "$PID_FILE" ]', script)
        self.assertNotIn("chmod +s", script)
        self.assertNotIn("setcap", script)
        self.assertNotIn("dnsmasq", script)
        self.assertEqual(distro_qemu.filename("CVE-2026-46333"),
                         "run_qemu_CVE-2026-46333.sh")

    def test_poc_payload_is_rejected_by_api(self):
        handler = object.__new__(Handler)
        with self.assertRaisesRegex(ValueError, "outside this pipeline"):
            handler._generate({"environment": {}, "configuration": {"configuration_status": "not_required"},
                               "poc_base64": "dGVzdA=="})

    @unittest.skipIf(os.name == "nt", "requires a real bash runtime, not the Windows WSL launcher")
    def test_generated_host_script_has_valid_bash_syntax(self):
        script = distro_qemu.build(SPEC, "CVE-2026-46333")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            completed = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
        finally:
            os.unlink(path)

    def test_rejects_unsupported_cloud_image(self):
        with self.assertRaisesRegex(ValueError, "supports Ubuntu only"):
            distro_qemu.build(dict(SPEC, os_family="debian"), "CVE-X")
        with self.assertRaisesRegex(ValueError, "Unsupported Ubuntu"):
            distro_qemu.build(dict(SPEC, os_version="26.04"), "CVE-X")

    def test_archived_impish_uses_verified_image_and_old_releases(self):
        script = distro_qemu.build(
            dict(SPEC, os_version="21.10",
                 version_constraint="<5.13.0.35.44",
                 concrete_kernel_constraint="<5.13.0-35.40"),
            "CVE-2022-0847",
        )
        self.assertIn("releases/impish/release/ubuntu-21.10-server", script)
        encoded = re.search(r"^APT_SOURCES_B64='([^']+)'$", script, re.M).group(1)
        sources_list = base64.b64decode(encoded).decode()
        self.assertIn("old-releases.ubuntu.com/ubuntu impish-security", sources_list)

    def test_browser_never_generates_qemu(self):
        handler = object.__new__(Handler)
        out = handler._generate({"environment": {"status": "selected", "os_family": "ubuntu", "os_version": "24.04"},
                                 "configuration": {"configuration_status": "not_required",
                                                   "evidence": [{"claim": "none", "source": "Primary CVE description", "excerpt": "No extra configuration is required."}]},
                                 "sources": official_bundle(cve="CVE-2026-46333"), "description": "No extra configuration is required.",
                                 "cve": "CVE-2026-46333"})
        self.assertEqual(out["filename"], "configure_CVE-2026-46333.sh")
        self.assertNotIn("qemu-system-x86_64", out["script"])
        self.assertIn("guest-configuration", out["generator_used"])

    def test_browser_validates_the_existing_guest(self):
        handler = object.__new__(Handler)
        out = handler._generate({"environment": {"status": "selected", "os_family": "ubuntu", "os_version": "24.04"},
                                 "configuration": {"configuration_status": "not_required",
                                                   "evidence": [{"claim": "none", "source": "Primary CVE description", "excerpt": "No extra configuration is required."}]},
                                 "sources": official_bundle(cve="CVE-2026-46333"), "description": "No extra configuration is required.",
                                 "cve": "CVE-2026-46333"})
        self.assertIn("verify_environment", out["script"])
        self.assertNotIn("grub-reboot", out["script"])
        self.assertNotIn("qemu-system-x86_64", out["script"])
        self.assertNotIn("POC_", out["script"])


if __name__ == "__main__":
    unittest.main()
