# Architecture (v4)

## End-to-end design

```text
                              deterministic path (no NLP)
CVE ID -> official source bundle -> CPE/affected ranges -> Ubuntu fixed boundary
                                                        -> exact Launchpad kernel
                                                        -> build-target.json
                                                        -> existing VM builder
                                                                  |
                              descriptive path (NLP only)          |
CVE descriptions + references -> typed extra configuration        |
                              -> configure_<CVE>.sh <---------------+
                                                                  |
                    exact target verification + configuration verification
                                                                  |
                                                        reproduction READY

PoC validation remains a separate downstream activity.
```

## Stage contracts

### 1. Source acquisition

`adapters/sources.py` collects source-labelled evidence. NVD contributes CPE
matches; CVE.org/CNA and OSV contribute structured affected versions; Debian
and Ubuntu trackers contribute distribution status; Launchpad contributes exact
Ubuntu binary meta-package publications. At least two allow-listed official
HTTPS services must return evidence.

The source bundle is written before later stages, so source outages and rejected
claims remain auditable. Saved bundles are CVE-checked, hashed, and subjected to
a freshly calculated provenance policy.

`machine_readable_version_evidence` makes source semantics explicit. Its mode
is `nvd-cpe` when real NVD CPE matches exist,
`structured-version-fallback` when NVD has no CPE but CNA/OSV publishes typed
affected-version arrays, and `unavailable` otherwise. The last state blocks
kernel target selection. Free-form descriptions and tracker prose do not pass
this gate.

### 2. Environment and exact target selection

`domain/environment.py` selects the OS release and vulnerable package boundaries
without a model. For an upstream Linux CPE, Canonical's downstream row is
required because distribution fixes are backported.

`domain/vulnerable_target.py` then accepts one exact earlier Launchpad
publication only when all of the following agree:

- Ubuntu version and suite;
- meta-package name and exact version;
- concrete image package name;
- exact expected `uname -r` release;
- Canonical's fixed ABI and vulnerable boundaries; and
- official evidence URLs.

Missing or inconsistent package evidence produces `needs-input`. A kernel range
alone is never enough to build or certify a VM.

### 3. Infrastructure build handoff

`build-target.json` is the machine-readable contract for the existing VM
infrastructure. `provision_kernel_<CVE>.sh` is deterministic implementation of
that contract. It pins one exact package rather than resolving “whatever is
newest” at build time.

`packer_stages_<CVE>.pkr.hcl` preserves the required install, disconnect,
reboot, post-reboot verification, and configuration order. The ordinary flat
script registry receives only the post-build configuration payload because it
cannot express a safe reboot boundary.

The optional `qemu_vm.py` path implements the same contract independently for
evaluation: it checksum-verifies a cloud image, embeds the deterministic kernel
provisioner in cloud-init, reboots, and waits for the post-reboot kernel READY
marker. It contains no NLP configuration and no PoC.

### 4. NLP configuration extraction

Only after a concrete kernel target is available does the primary pipeline call
the local model. `domain/schema.py` permits typed configuration prerequisites:

- modules;
- kernel `CONFIG_*` checks and one-of alternatives;
- sysctls;
- helper packages;
- services;
- exact file settings;
- non-executable manual prerequisites; and
- evidence-linked claims.

It has no target-selection or arbitrary-shell fields. `configuration.py`
reconciles each action against exact evidence spans, restores clearly omitted
requirements, preserves documented alternatives, and removes unsupported
actions. One rejected response receives one repair attempt.

### 5. Apply and verification

`guest_configuration.py` verifies the exact build contract before applying
configuration:

- OS family, version, codename, and architecture;
- selected target status;
- exact running kernel release;
- exact installed meta-package version;
- concrete running image package inside the vulnerable boundary; and
- every typed configuration requirement.

The `report` action is non-mutating and evaluates all applicable checks. The
host-side `configuration_check.py` always runs that report, even if safe apply
failed, to distinguish a wrong kernel from a missing module or setting.

### 6. Shared identity and readiness

`environment_identity.py` hashes a canonical schema containing the CVE, OS,
architecture, all vulnerable constraints, target status, exact meta-package,
concrete package, and exact running kernel. The QEMU builder, checker, and guest
payload must carry the same digest.

Automatic `READY` requires the exact built target and all configuration checks.
It never means a PoC succeeded. `manual_steps` and `unknown` configuration both
prevent automatic certification.

The QEMU builder's success marker is `EXACT_KERNEL_VM_BUILT`; it deliberately
does not claim full readiness. Only the separate apply-and-report checker emits
`VULNERABLE_REPRODUCTION_ENVIRONMENT_READY`.

## Failure boundaries

| Failure | Outcome |
|---|---|
| Fewer than two official sources | Stop before selection/NLP |
| No complete OS mapping | `needs-input` |
| No NVD CPE and no structured CNA/OSV affected versions | Stop before NLP |
| No exact earlier package publication | Stop before NLP |
| Exact package absent from APT | Kernel build fails |
| Rebooted into another kernel | Post-reboot verification fails |
| Model output invalid or ungrounded twice | Fail-closed `unknown` |
| Wrong OS/kernel/package at configuration time | Apply refused |
| Manual prerequisite remains | `MANUAL_REQUIRED` |
| Exploit not run | No effect on environment readiness; record separately |
