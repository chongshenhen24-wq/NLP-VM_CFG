"""Generate the ordered Packer provisioner handoff for an exact kernel target."""
from __future__ import annotations

import re

from . import environment_identity


def filename(cve_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id or "CVE")
    return f"packer_stages_{safe}.pkr.hcl"


def build(environment: dict, cve_id: str, kernel_script_name: str,
          configuration_script_name: str) -> str:
    """Return provisioner blocks to merge into the existing Packer build.

    A flat ``scripts`` array cannot safely express the mandatory reboot between
    kernel installation and configuration.  The handoff therefore makes the
    disconnect, post-reboot verification, and final configuration explicit.
    """
    kernel = environment_identity.validate_selected_kernel_target(environment)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id or "CVE")
    base = f"machines/{safe}"
    return f'''# Merge these ordered provisioners into the existing Packer build.
# Exact target: {environment.get("os_family")} {environment.get("os_version")},
# {kernel["meta_package"]}={kernel["meta_package_version"]},
# running kernel {kernel["running_kernel_release"]}.
# Do not flatten these stages into one scripts list: the reboot boundary is required.

provisioner "shell" {{
  script            = "{base}/{kernel_script_name}"
  environment_vars  = ["CVE_AUTO_REBOOT=1"]
  execute_command   = "chmod +x {{{{ .Path }}}}; sudo -E {{{{ .Vars }}}} {{{{ .Path }}}} prepare"
  expect_disconnect = true
}}

provisioner "shell" {{
  pause_before        = "45s"
  start_retry_timeout = "10m"
  inline              = ["sudo /usr/local/sbin/cve-kernel-reproduction verify"]
}}

provisioner "shell" {{
  script          = "{base}/{configuration_script_name}"
  execute_command = "chmod +x {{{{ .Path }}}}; sudo -E {{{{ .Vars }}}} {{{{ .Path }}}} apply"
}}
'''
