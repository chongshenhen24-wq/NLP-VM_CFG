# User Guide

## 1. Start the local extraction model

```powershell
ollama pull qwen2.5:14b
ollama serve
```

Run project commands from the repository directory with Python 3.11 or later.

## 2. Generate a complete target and configuration plan

```powershell
python -m cve_pipeline run --cve CVE-2026-43500 --sources enrich --print-plan
```

The command performs these decisions in order:

1. collect machine-readable and descriptive official evidence;
2. require at least two recognized official services;
3. select an Ubuntu release and downstream vulnerable boundaries;
4. select one exact earlier Launchpad kernel publication;
5. write the infrastructure target and kernel provisioner;
6. ask NLP only for extra configuration;
7. ground and normalize the NLP output;
8. write apply/verify scripts and infrastructure handoff.

If exact package evidence is absent, the kernel workflow stops after writing the
available source/environment/target evidence. It does not ask NLP and does not
substitute a current kernel.

## 3. Review the generated files

Under `machines/<CVE>/`:

- `sources.json`: official evidence, CPE/version arrays, references, and errors;
- `environment.json`: selected OS, vulnerable boundaries, and the explicit
  `nvd-cpe` / `structured-version-fallback` evidence mode;
- `build-target.json`: exact package and running-kernel contract;
- `provision_kernel_<CVE>.sh`: exact kernel install/reboot/verify logic;
- `configuration.json`: typed NLP result with citations;
- `configure_<CVE>.sh`: exact-target guard plus configuration apply/report;
- `packer_stages_<CVE>.pkr.hcl`: ordered integration fragment;
- `extraction-attempt-N.txt`: raw model output retained for audit.

In `build-target.json`, require `status: selected`. Check the exact
`meta_package_version`, `running_kernel_release`, constraints, and evidence URLs.

Configuration states are:

- `required`: evidence supports extra settings;
- `not_required`: evidence explicitly supports the default/no-op state;
- `unknown`: evidence cannot support a decision, so certification is refused.

## 4. Use existing Packer infrastructure

Merge the generated `packer_stages_<CVE>.pkr.hcl` provisioner blocks into the
existing build. Do not copy the kernel and configuration scripts into one flat
script list. The required order is:

```text
kernel prepare -> reboot/disconnect -> kernel verify -> configuration apply
```

The generated fragment already includes `CVE_AUTO_REBOOT=1`,
`expect_disconnect=true`, a post-reboot retry window, exact kernel verification,
and the final configuration script.

If the existing Packer variables file exposes only a flat `scripts` list, the
project registers only the post-build configuration payload. The reboot-aware
fragment must still be merged at the build level before that list is executed.

## 5. Build and test with disposable QEMU

Generate the independent QEMU path:

```powershell
python -m cve_pipeline run --cve CVE-2026-43500 `
  --source-bundle examples\official-snapshot-CVE-2026-43500.json `
  --qemu-check --print-plan
```

Copy the generated scripts to an Ubuntu/Debian QEMU host and run:

```bash
bash build_qemu_CVE-2026-43500.sh
bash check_configuration_CVE-2026-43500.sh
```

The builder downloads the selected Ubuntu image over HTTPS, verifies its
published SHA-256 digest, creates a disposable overlay, installs the exact
kernel from `build-target.json`, reboots, and waits for post-reboot verification.
Only then should the separate checker be run.

Useful lifecycle commands:

```bash
CVE_ACTION=status bash build_qemu_CVE-2026-43500.sh
CVE_ACTION=ssh-command bash build_qemu_CVE-2026-43500.sh
CVE_ACTION=stop bash build_qemu_CVE-2026-43500.sh
CVE_RESET=1 bash build_qemu_CVE-2026-43500.sh
```

Use the same `CVE_SSH_PORT` value for builder and checker when overriding port
2222. KVM is used when `/dev/kvm` is accessible; otherwise TCG is slower and a
larger `CVE_QEMU_TIMEOUT` may be required.

## 6. Apply or inspect configuration manually in a built guest

After the exact kernel stage has been completed:

```bash
sudo bash configure_CVE-YYYY-NNNN.sh report
sudo bash configure_CVE-YYYY-NNNN.sh apply
sudo bash configure_CVE-YYYY-NNNN.sh verify
sudo bash configure_CVE-YYYY-NNNN.sh status
```

`report` is non-mutating and prints all checks. `apply` first checks the exact
OS, kernel release, meta-package version, and vulnerable concrete-package
boundary. A current patched image such as `6.8.0-136.136` cannot satisfy a target
that selected `6.8.0-31-generic`.

## 7. Interpret results

- `READY`: exact target and all automatic configuration checks pass.
- `MANUAL_REQUIRED`: automatic checks pass but manual evidence requirements
  remain.
- `UNCERTIFIED`: NLP evidence was insufficient.
- `FAILED`: one or more known checks failed.
- `INCONCLUSIVE`: build/boot/SSH did not provide a reliable result.
- `MISMATCH`: builder/checker/payload identity differs.

READY is environmental evidence, not a successful exploit.

## 8. Validate a PoC separately

After READY, use the laboratory's reviewed PoC procedure. Record hashes,
commands, exit status, privilege before/after, crash logs, and VM snapshot ID in
a separate validation record. The project does not download or run a PoC.

## 9. Reproducible source replay

```powershell
python -m cve_pipeline run --cve CVE-2026-43500 `
  --source-bundle examples\official-snapshot-CVE-2026-43500.json --print-plan
```

The bundle's CVE identity and SHA-256 are recorded, and the official-source
policy is recalculated. Stored claims about provenance are not trusted.

For batch replay, place bundles at `<root>/<CVE>/sources.json` and run:

```powershell
python -m cve_pipeline batch --file cves.txt --source-bundle-dir <root>
```

## 10. Common failures

- **No exact buildable target:** Launchpad/Canonical data did not resolve an
  earlier publication. Collect again with `--sources enrich`; do not invent one.
- **Exact package absent in APT:** provide a reviewed Ubuntu archive/snapshot
  containing the package. The script correctly refuses substitution.
- **Wrong kernel after reboot:** inspect GRUB and serial logs; configuration must
  not continue.
- **Configuration check shows current kernel:** the clean image was built without
  the generated exact-target stage. Rebuild it.
- **NLP unknown:** inspect source/reference coverage and retained extraction
  attempts. Unknown is not a no-op.
- **QEMU timeout under TCG:** increase `CVE_QEMU_TIMEOUT`; inspect `serial.log` and
  `qemu-stderr.log` in the printed work directory.
