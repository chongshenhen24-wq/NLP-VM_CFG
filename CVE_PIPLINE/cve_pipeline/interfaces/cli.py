"""Command-line interface. Single CVE or a batch from a file."""
import argparse
import json
import sys

from ..config import Config
from ..adapters import sources
from ..pipeline import run_one, run_batch

def _add_common(p):
    p.add_argument("--endpoint", default="http://localhost:11434")
    p.add_argument("--extract-model", default="qwen2.5:14b",
                   help="model used only to extract guest configuration prerequisites")
    p.add_argument("--machines-dir", default="machines")
    p.add_argument("--os", default="auto")
    p.add_argument("--os-version", default=None,
                   help="explicit base image version when CPE evidence is incomplete; never passed to NLP")
    p.add_argument("--no-register", action="store_true")
    p.add_argument("--nvd-api-key", default=None)
    p.add_argument("--eval-log", default=None)
    p.add_argument("--sources", choices=["enrich", "nvd", "offline"], default="enrich",
                   help=("evidence acquisition mode; generation requires enrich and at least two "
                         "recognized official sources (nvd/offline are diagnostic only)"))
    p.add_argument("--source-timeout", type=int, default=15,
                   help="seconds per optional evidence source")


def _add_qemu_options(p):
    p.add_argument("--qemu-check", action="store_true",
                   help=("generate separate disposable Ubuntu VM-builder and "
                         "configuration-check scripts"))
    p.add_argument("--qemu-memory", type=int, default=4096, metavar="MIB")
    p.add_argument("--qemu-cpus", type=int, default=2)
    p.add_argument("--qemu-disk-size", default="20G")
    p.add_argument("--qemu-timeout", type=int, default=1800, metavar="SECONDS")


def _cfg(a):
    return Config(endpoint=a.endpoint, extract_model=a.extract_model,
                  machines_dir=a.machines_dir, register=not a.no_register,
                  nvd_api_key=a.nvd_api_key, eval_log=a.eval_log, source_mode=a.sources,
                  source_timeout=a.source_timeout,
                  source_bundle_dir=getattr(a, "source_bundle_dir", None))


def _print_result(res):
    if res.get("error"):
        print(f"[!] {res['cve']}: {res['error']}", file=sys.stderr)
        return
    environment = res["environment"]
    configuration = res["configuration"]
    build_target = res.get("build_target") or {}
    os_label = environment.get("os_family") or "unresolved"
    if environment.get("os_version"):
        os_label += "/" + environment["os_version"]
    print(f"[i] {res['cve']}: environment={environment['status']} ({os_label}) "
          f"basis={environment['selection_basis']} target={build_target.get('status', 'not-applicable')} "
          f"configuration={configuration['configuration_status']}")
    version_evidence = environment.get("machine_readable_version_evidence") or {}
    if version_evidence:
        print(f"    machine-readable range {version_evidence.get('status')} "
              f"(NVD CPEs={version_evidence.get('nvd_cpe_count', 0)}, "
              f"fallback={str(bool(version_evidence.get('fallback_used'))).lower()})")
    kernel = build_target.get("kernel") or {}
    if kernel:
        print(f"    exact kernel target {kernel.get('running_kernel_release')} "
              f"via {kernel.get('meta_package')}={kernel.get('meta_package_version')}")
    if res.get("configuration_fallback"):
        print("[!] NLP output was not certifiable after two attempts; the unknown script is fail-closed")
        print(f"    validation failures: {len(res.get('extraction_validation_errors') or [])}")
    print("    existing VM infrastructure must consume the exact build target before configuration")
    if res.get("sources_path"):
        policy = res.get("official_source_policy") or {}
        print(f"    evidence {res['sources_path']} | official sources: "
              f"{policy.get('count', 0)}/{policy.get('minimum_required', 2)} | "
              f"source failures: {len(res['sources'].get('errors', []))}")
    print(f"    environment {res['environment_path']}")
    print(f"    infrastructure target {res['build_target_path']}")
    if res.get("kernel_script_path"):
        print(f"    kernel provisioner {res['kernel_script_path']}")
    if res.get("packer_handoff_path"):
        print(f"    ordered Packer handoff {res['packer_handoff_path']}")
    print(f"    requirements {res['configuration_path']}")
    print(f"    wrote {res['script_path']} | registered with existing infrastructure: {res['registered']}")
    if res.get("qemu_check"):
        print(f"    exact-target QEMU VM builder {res['qemu_script_path']}")
        print(f"    separate configuration checker {res['configuration_check_script_path']}")
        print("    on the Ubuntu/Debian QEMU host, run the builder first and the checker second")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="cve_pipeline",
        description="CVE -> exact vulnerable VM target -> evidence-linked guest configuration.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    one = sub.add_parser("run", help="one CVE")
    one.add_argument("--cve", required=True)
    _add_common(one)
    one_desc = one.add_mutually_exclusive_group()
    one_desc.add_argument(
        "--description",
        help="optional analyst note retained for audit; it never replaces official-source evidence",
    )
    one_desc.add_argument(
        "--description-file",
        help="UTF-8 analyst note retained for audit; it never replaces official-source evidence",
    )
    one.add_argument("--print-plan", action="store_true",
                     help="print the deterministic environment and extracted configuration JSON")
    one.add_argument("--source-bundle",
                     help=("saved official sources.json for reproducible replay; provenance is "
                           "revalidated and must still contain at least two official sources"))
    _add_qemu_options(one)

    batch = sub.add_parser("batch", help="many CVEs from a file (one id per line)")
    batch.add_argument("--file", required=True)
    _add_common(batch)
    batch.add_argument(
        "--source-bundle-dir",
        help="replay <dir>/<CVE>/sources.json or <dir>/<CVE>.json; missing bundles use live sources",
    )
    _add_qemu_options(batch)

    serve = sub.add_parser("serve", help="run the local API + web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    a = p.parse_args(argv)

    if a.cmd == "serve":
        from .server import serve as run_server
        run_server(a.host, a.port)
        return 0

    if a.cmd == "batch":
        ids = [ln.strip() for ln in open(a.file) if ln.strip() and not ln.startswith("#")]
        results = run_batch(
            ids, _cfg(a), a.os,
            os_version_hint=a.os_version,
            qemu_check=a.qemu_check,
            qemu_memory_mb=a.qemu_memory,
            qemu_cpus=a.qemu_cpus,
            qemu_disk_size=a.qemu_disk_size,
            qemu_timeout_s=a.qemu_timeout,
        )
        for r in results:
            _print_result(r)
        okc = sum(1 for r in results if not r.get("error"))
        selected = sum(1 for r in results if (r.get("environment") or {}).get("status") == "selected")
        required = sum(1 for r in results if (r.get("configuration") or {}).get("configuration_status") == "required")
        fallback = sum(1 for r in results if r.get("configuration_fallback"))
        targets = sum(1 for r in results if (r.get("build_target") or {}).get("status") == "selected")
        print(f"\n[i] batch: {okc}/{len(results)} produced artefacts; {selected} base environments selected; "
              f"{targets} exact kernel targets selected; "
              f"{required} require extra guest configuration; {fallback} fail-closed fallbacks")
        return 0

    # run
    try:
        source_bundle = sources.load_bundle(a.source_bundle, a.cve) if a.source_bundle else None
        res = run_one(a.cve, _cfg(a), a.os, description=_description_from_args(a),
                      os_version_hint=a.os_version, source_bundle=source_bundle,
                      qemu_check=a.qemu_check, qemu_memory_mb=a.qemu_memory,
                      qemu_cpus=a.qemu_cpus, qemu_disk_size=a.qemu_disk_size,
                      qemu_timeout_s=a.qemu_timeout)
    except Exception as e:  # noqa: BLE001
        print(f"[!] {e}", file=sys.stderr)
        return 2
    _print_result(res)
    if a.print_plan:
        print(json.dumps({"environment": res["environment"],
                          "build_target": res["build_target"],
                          "configuration": res["configuration"]}, indent=2))
    return 0


def _description_from_args(a):
    value = getattr(a, "description", None)
    path = getattr(a, "description_file", None)
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            value = handle.read()
    return value


