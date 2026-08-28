# Kernel CVE Reproduction Pipeline

This dissertation prototype converts a kernel CVE ID into an exact,
evidence-backed vulnerable VM target and a separately generated extra-
configuration stage. PoC execution is intentionally outside the pipeline.

## Required flow

```text
CVE ID
  -> collect machine-readable CPE/version data from official sources
  -> map the upstream record to a downstream Ubuntu release and fixed boundary
  -> choose one exact earlier Launchpad kernel publication
  -> hand the exact OS/kernel target to the existing VM infrastructure
  -> use NLP only on descriptions and reference evidence
  -> generate typed extra-configuration instructions
  -> apply and verify the exact kernel plus every configuration requirement
  -> report READY only when all automatic checks pass
```

Target selection and NLP are deliberately separated. NLP has no schema field
for the OS, kernel version, package version, QEMU, GRUB, arbitrary shell, or
PoC. A model response therefore cannot change the vulnerable target.

## Outputs

Each successful kernel-CVE run writes:

```text
machines/<CVE>/
|-- sources.json
|-- environment.json
|-- build-target.json
|-- configuration.json
|-- extraction-attempt-1.txt
|-- provision_kernel_<CVE>.sh
|-- configure_<CVE>.sh
`-- packer_stages_<CVE>.pkr.hcl
```

`build-target.json` is the infrastructure contract. It names one Ubuntu
version, architecture, exact `linux-image-generic` version, exact expected
running kernel release, vulnerable boundaries, selection policy, and evidence
URLs. If those fields cannot be proven, the kernel workflow stops before NLP.

`provision_kernel_<CVE>.sh` pins the exact meta-package, verifies that it is
inside the vulnerable range, installs it without package removal, verifies its
concrete image dependency and headers, selects the exact GRUB entry, reboots,
and verifies the running release. An unavailable exact package is unresolved;
the script never silently substitutes the newest kernel.

`configure_<CVE>.sh` contains only evidence-grounded extra settings. Before it
applies anything, it verifies the exact OS, codename, architecture, meta-package
version, running kernel release, and concrete vulnerable boundary. Its
non-mutating `report` action prints every check rather than stopping at the
first mismatch.

The generated Packer fragment expresses the mandatory order:

1. install the exact target kernel;
2. reboot and expect SSH to disconnect;
3. verify the post-reboot kernel;
4. apply and verify extra configuration.

A flat `scripts` list cannot represent this reboot boundary safely.

## Evidence policy

The standard `--sources enrich` run attempts NVD, CVE.org/CNA, OSV, Debian
Security Tracker, Ubuntu Security Tracker, Canonical's tracker Git data, and
Launchpad package publications. At least two recognized official HTTPS services
must supply non-empty evidence. Every success and failure is retained before
NLP runs.

NVD CPEs establish the affected product/range when they are available. Because
new CVEs can appear in a CNA record before NVD adds CPEs, official structured
CNA/OSV affected-version arrays are the only permitted fallback. The selected
mode, source names, NVD CPE count, and fallback flag are recorded under
`machine_readable_version_evidence`; fallback data is never called CPE data.
If neither form exists, target selection stops before NLP.

Canonical's downstream tracker establishes the Ubuntu fixed package boundary.
Launchpad supplies exact binary meta-package publications. For generic upstream
Linux CPEs, the project does not treat an upstream version number as proof of a
particular Ubuntu package state.

Up to three bounded public advisory references can provide configuration
details missing from a short CVE description. References help NLP but do not
count toward the official-source threshold.

## Commands

```powershell
# Generate the exact infrastructure target and extra-configuration artefacts
python -m cve_pipeline run --cve CVE-2026-43500 --sources enrich --print-plan

# Reproduce a run from a retained official-source snapshot
python -m cve_pipeline run --cve CVE-2026-43500 `
  --source-bundle examples\official-snapshot-CVE-2026-43500.json --print-plan

# Also generate an independent disposable QEMU builder and later checker
python -m cve_pipeline run --cve CVE-2026-43500 `
  --source-bundle examples\official-snapshot-CVE-2026-43500.json `
  --qemu-check --print-plan

# Batch evaluation
python -m cve_pipeline batch --file cves.txt --eval-log runs.jsonl

# Local review UI
python -m cve_pipeline serve
```

The default local extraction model is `qwen2.5:14b` through Ollama. Python 3.11
or later is required.

## Disposable QEMU validation

With `--qemu-check`, two host scripts are added:

- `build_qemu_<CVE>.sh` downloads and checksum-verifies the selected Ubuntu
  image, creates a disposable overlay, installs the exact selected kernel,
  reboots it, and waits for post-reboot kernel verification. It reports
  `EXACT_KERNEL_VM_BUILT`, not full readiness;
- `check_configuration_<CVE>.sh` connects over key-only loopback SSH, transfers
  the configuration payload, and runs `apply` followed by the complete report.
  Only this final stage can report `VULNERABLE_REPRODUCTION_ENVIRONMENT_READY`.

Run them on an Ubuntu/Debian QEMU host:

```bash
bash build_qemu_CVE-YYYY-NNNN.sh
bash check_configuration_CVE-YYYY-NNNN.sh
CVE_ACTION=status bash build_qemu_CVE-YYYY-NNNN.sh
CVE_ACTION=ssh-command bash build_qemu_CVE-YYYY-NNNN.sh
CVE_ACTION=stop bash build_qemu_CVE-YYYY-NNNN.sh
```

The builder uses KVM when available and otherwise uses slower TCG emulation.
The builder, checker, and guest payload share a SHA-256 environment identity
covering the CVE, OS, complete vulnerable constraints, and exact kernel target.
Files from different selections cannot be mixed.

## Result semantics

- `READY`: exact OS/kernel target and every automatic configuration check pass.
- `MANUAL_REQUIRED`: automatic checks pass, but evidence contains a prerequisite
  that cannot be certified automatically.
- `UNCERTIFIED`: configuration evidence is insufficient; unknown never means
  no configuration.
- `FAILED`: one or more known requirements do not match.
- `INCONCLUSIVE`: the VM or transport did not yield a reliable result.
- `MISMATCH`: generated files belong to different environment selections.

`READY` means the reproduction environment matches the selected vulnerable
target and configuration evidence. It is not exploitability proof. A reviewed
PoC can be run later under the laboratory's separate validation procedure.

## Fail-closed rules

- No exact package publication: no kernel provisioner and no NLP continuation.
- No NVD CPE or official structured CNA/OSV version range: no target selection.
- Exact package absent from APT: build fails; no alternate package is selected.
- Wrong OS, kernel, or package version: configuration is not applied.
- `configuration_status=unknown`: apply and verify refuse certification.
- Manual prerequisites: automatic READY is refused.
- `linux-image*` and `linux-headers*` are rejected from NLP actions.
- PoC fields are rejected by the API.
- Model JSON or grounding failure receives one bounded repair attempt; a second
  failure produces a retained, fail-closed unknown artefact.

See [ARCHITECTURE.md](ARCHITECTURE.md), [USER_GUIDE.md](USER_GUIDE.md), and
[MEETING_REQUIREMENTS.md](MEETING_REQUIREMENTS.md) for design and traceability.
For unattended multi-CVE experiments, ground-truth templates, repeat runs, and
automatic success-rate calculation, see [EVALUATION.md](EVALUATION.md).
