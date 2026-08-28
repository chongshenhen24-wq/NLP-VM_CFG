# Reference only. Every successful kernel-CVE run now writes a CVE-specific
# machines/<CVE>/packer_stages_<CVE>.pkr.hcl fragment with exact filenames and
# target metadata. Merge that generated fragment into the existing build.
#
# The required order is deliberately not represented as a flat scripts list:
#
#   1. provision_kernel_<CVE>.sh prepare (CVE_AUTO_REBOOT=1)
#   2. expect the SSH disconnect and wait for the reboot
#   3. /usr/local/sbin/cve-kernel-reproduction verify
#   4. configure_<CVE>.sh apply
#
# The build must fail if any stage returns non-zero. Configuration must never
# run against the pre-reboot/current kernel and still be labelled READY.
