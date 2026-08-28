# Meeting Requirements Traceability

| Requirement | Implemented behaviour | Main code | Verification |
|---|---|---|---|
| Start with a CVE ID and online evidence | Enrichment collects multiple recognized official services and retains every source/failure | `adapters/sources.py` | source-policy and replay tests |
| Download machine-readable CPE/version data | NVD CPEs feed deterministic selection; when NVD has none, official CNA/OSV arrays are an explicitly labelled fallback rather than fake CPE data | `sources.py`; `environment.py` | CPE, fallback-label, and missing-range stop tests |
| Select any OS/kernel inside the vulnerable range | Canonical fixes establish downstream boundaries; one exact earlier Launchpad publication becomes `build-target.json` | `sources.py`; `vulnerable_target.py` | `test_official_candidate_becomes_exact_infrastructure_target` |
| Do not silently use the current cloud-image kernel | Exact meta-package and `uname -r` values are pinned and verified; absent packages fail | `distro_kernel.py`; `guest_configuration.py` | exact-target cross-script tests |
| Existing infrastructure builds the VM | A machine-readable target, deterministic provisioner, and ordered Packer fragment are generated | `pipeline.py`; `packer_handoff.py` | reboot-order handoff test |
| Reboot before extra configuration | Packer handoff expects disconnect, waits, verifies the new kernel, then configures | `packer_handoff.py` | `test_packer_handoff_preserves_reboot_before_configuration` |
| QEMU can independently simulate the same build | QEMU embeds the matching kernel provisioner and waits for post-reboot exact-kernel verification | `qemu_vm.py` | split QEMU and payload-mismatch tests |
| NLP must not select OS/kernel | Configuration schema has no target, QEMU, GRUB, package-version, arbitrary-shell, or PoC fields | `schema.py`; `prompts.py` | negative extraction/generation tests |
| NLP finds extra reachability configuration | Typed modules, kernel config, sysctls, helper packages, services, file settings, and manual gates are extracted from descriptions/references | `configuration.py`; `ollama.py` | grounding and completeness tests |
| Missing configuration evidence is not “no change” | `unknown` fails closed; `not_required` needs explicit no-op/default evidence | `configuration.py`; `guest_configuration.py` | unknown/no-op tests |
| Configuration must be applied inside the selected guest | Guest script verifies exact OS/kernel/package identity before mutation | `guest_configuration.py` | aggregate-report and exact-target tests |
| Show all check results | `report` prints every PASS/FAIL and a summary even after a mismatch | `guest_configuration.py`; `configuration_check.py` | complete-report test |
| Files from different runs must not mix | Shared SHA-256 identity includes exact target and vulnerable constraints | `environment_identity.py` | identity mismatch tests |
| PoC is final manual validation | PoC fields are rejected and no generated target/configuration script contains exploit commands | `server.py`; schemas/generators | PoC rejection tests |

## Exact runtime order

```text
sources.json
  -> environment.json
  -> build-target.json
  -> provision exact kernel in VM
  -> reboot
  -> verify exact running kernel
  -> configuration.json (NLP-derived, evidence-grounded)
  -> apply configuration
  -> aggregate verification
  -> READY / MANUAL_REQUIRED / UNCERTIFIED / FAILED
```

The implementation can generate NLP configuration before an external Packer
job is physically executed, but the generated runtime contract forbids applying
or certifying that configuration until the exact VM target has been built and
verified. For the integrated QEMU evaluation path, the VM builder must complete
successfully before the separate checker can report READY.
