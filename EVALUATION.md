# Automated Dissertation Evaluation

This workflow collects generation, exact-kernel VM, configuration-readiness,
repeatability, and separate PoC-validation results without editing generated
artefacts between CVEs.

## 1. Establish ground truth first

Copy `evaluation/ground-truth-template.csv` and review each CVE against official
records before reading the model's `configuration.json`. At minimum, fill:

- `review_status=reviewed`;
- official evidence URLs;
- expected Ubuntu release and fixed boundary;
- `actual_default_ready=yes|no`; and
- the expected extra configuration.

This avoids treating the system under evaluation as its own reference answer.

## 2. Generate the complete pilot run

Keep Ollama running, then execute from PowerShell:

```powershell
cd "C:\\"
ollama serve
```

In a second PowerShell terminal:

```powershell
.\evaluation\generate_all.ps1
```

The script creates a timestamped directory under `evaluation/runs/` containing
the CVE list, generation manifest, JSONL audit log, all machine directories,
the Linux runner, and copies of the two manual-review templates. Batch failures
are retained in `generation.jsonl` and do not stop later CVEs.

For a different dataset:

```powershell
.\evaluation\generate_all.ps1 -InputFile .\my-30-cves.txt
```

For a reproducible replay, add `-SourceBundleDir` pointing to a directory with
`<CVE>.json` or `<CVE>/sources.json` bundles. A missing bundle still uses live
collection and is recorded as such.

## 3. Transfer one directory

Copy the timestamped run to the Ubuntu QEMU host:

```powershell
scp -r ".\evaluation\runs\YYYYMMDD-HHMMSS" user@TEST_HOST:~/cve-evaluation
```

Use the same unprivileged Linux user throughout. The VM builder and checker
share user-scoped state and key paths.

## 4. Run the exact-kernel and configuration evaluation

On the Ubuntu host:

```bash
cd ~/cve-evaluation
chmod 700 run_qemu_evaluation.sh
./run_qemu_evaluation.sh
```

The runner processes one CVE at a time, recreates a clean overlay, stops the VM
after checking, retains separate logs, and writes:

```text
runtime-results/runtime-repetition-1.csv
```

`/dev/kvm` is used automatically when accessible. TCG software emulation is
supported but can make a large experiment impractically slow.

For repeatability, rebuild the chosen set with repetition numbers:

```bash
EVAL_REPETITION=2 ./run_qemu_evaluation.sh
EVAL_REPETITION=3 ./run_qemu_evaluation.sh
```

To evaluate only a ten-CVE repeatability subset, place those ten generated CVE
directories in a separate `machines-repeat/` directory and run:

```bash
EVAL_MACHINES_DIR="$PWD/machines-repeat" EVAL_REPETITION=2 ./run_qemu_evaluation.sh
```

## 5. Record exploit validation separately

Edit `manual-validation.csv` only after the automatic run. Use these controlled
values:

- `poc_attempted=yes|no`;
- `poc_compatible=yes|no|unknown`;
- `poc_result=confirmed|failed|incompatible|inconclusive|not_attempted`;
- the expected security impact; and
- the retained evidence-file path.

A kernel panic counts as confirmation only for an expected crash/denial-of-
service effect with a matching, repeatable fault signature. Absence of a
Metasploit module or compatible offsets is not a VM-generation failure.

## 6. Return runtime data and produce the report

Copy `runtime-results/`, `ground-truth.csv`, and `manual-validation.csv` back
into the timestamped run directory on the analysis machine. Then run:

```powershell
python -m cve_pipeline.evaluation.report `
  --machines-dir ".\evaluation\runs\YYYYMMDD-HHMMSS\machines" `
  --generation-log ".\evaluation\runs\YYYYMMDD-HHMMSS\generation.jsonl" `
  --runtime-csv ".\evaluation\runs\YYYYMMDD-HHMMSS\runtime-results\runtime-repetition-1.csv" `
  --ground-truth ".\evaluation\runs\YYYYMMDD-HHMMSS\ground-truth.csv" `
  --manual-validation ".\evaluation\runs\YYYYMMDD-HHMMSS\manual-validation.csv" `
  --output-dir ".\evaluation\runs\YYYYMMDD-HHMMSS\report"
```

Add another `--runtime-csv` argument for every repeat file. Outputs are:

- `combined-results.csv`: one auditable row per CVE/repetition;
- `metrics.json`: exact numerators, denominators, rates, and confusion matrix;
- `evaluation-report.md`: dissertation-friendly aggregate and per-CVE tables.

## Result boundaries

- `EXACT_KERNEL_VM_BUILT` proves the VM booted the exact selected target.
- `VULNERABLE_REPRODUCTION_ENVIRONMENT_READY` proves exact-target and
  configuration conformance.
- `confirmed` in `manual-validation.csv` records separate vulnerability-impact
  evidence.

These are deliberately separate success rates so an unavailable or
incompatible PoC cannot be misreported as a VM-generation failure.
