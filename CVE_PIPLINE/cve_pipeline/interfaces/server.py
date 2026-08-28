"""Local API and thin UI for exact target selection plus configuration."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..adapters import ollama, sources
from ..domain import configuration as configuration_mod
from ..domain import environment as environment_mod
from ..domain import prompts
from ..domain import vulnerable_target as vulnerable_target_mod
from ..domain.generators import (
    configuration_check, distro_kernel, guest_configuration, packer_handoff, qemu_vm,
)

_WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "web")


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel):
        path = os.path.join(_WEB, rel)
        if not os.path.isfile(path):
            self.send_error(404)
            return
        ctype = ("text/html" if path.endswith(".html")
                 else "application/javascript" if path.endswith(".js") else "text/plain")
        with open(path, "rb") as handle:
            body = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        rel = "index.html" if self.path in ("/", "") else self.path.lstrip("/").split("?")[0]
        self._static(rel)

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", 0))
            request = json.loads(self.rfile.read(size).decode() or "{}")
            route = self.path.split("?")[0]
            if route == "/api/extract":
                result = self._extract(request)
            elif route == "/api/generate":
                result = self._generate(request)
            else:
                self.send_error(404)
                return
            self._json(200, result)
        except Exception as exc:  # return a bounded, user-visible local error
            self._json(500, {"error": str(exc)})

    def _extract(self, request):
        cve = request.get("cve")
        if not cve:
            raise ValueError("A CVE ID is required for official-source collection.")
        bundle = sources.collect(
            cve, request.get("nvd_api_key"), request.get("sources", "enrich"),
            int(request.get("source_timeout", 15)),
        )
        if request.get("description"):
            bundle["analyst_note"] = request["description"]
        coverage = sources.require_multiple_official_sources(bundle)
        description = bundle.get("description")
        if not description:
            raise ValueError("No description was available from the collected official sources.")

        environment = environment_mod.select(
            bundle, request.get("os_hint", "auto"), request.get("os_version_hint")
        )
        build_target = vulnerable_target_mod.select(bundle, environment)
        environment["build_target"] = build_target
        kernel_constraints = environment.get("vulnerable_constraints") or {}
        if (
            kernel_constraints.get("running_kernel_package_constraint")
            and build_target.get("status") != "selected"
        ):
            return {
                "environment": environment,
                "build_target": build_target,
                "configuration": configuration_mod.normalize({
                    "configuration_status": "unknown",
                    "summary": (
                        "NLP was not run because an exact vulnerable kernel target "
                        "could not be proven from official package evidence."
                    ),
                }),
                "description": description,
                "raw": "",
                "validation_errors": [build_target.get("reason", "unresolved build target")],
                "reconciliation_notes": [],
                "configuration_fallback": True,
                "ground_truth": sources.nvd_ground_truth(bundle),
                "sources": bundle,
                "official_source_policy": coverage,
                "workflow": "unresolved-vulnerable-vm-target",
            }
        base_evidence = sources.prompt_evidence(bundle)
        errors = []
        configuration = None
        reconciliation_notes = []
        extraction_fallback = False
        raw = ""
        for _attempt in (1, 2):
            evidence = base_evidence
            if errors:
                evidence = prompts.configuration_repair_evidence(
                    base_evidence, errors[-1], raw
                )
            parse_error = None
            try:
                parsed, raw = ollama.extract_configuration(
                    description,
                    request.get("endpoint", "http://localhost:11434"),
                    request.get("model", "qwen2.5:14b"),
                    evidence,
                )
            except ollama.InvalidModelJSON as exc:
                parsed, raw, parse_error = None, exc.raw, str(exc)
            if parse_error:
                errors.append(parse_error)
                continue
            try:
                candidate = configuration_mod.normalize(parsed)
                candidate, candidate_notes = configuration_mod.reconcile_and_ground(
                    candidate, bundle, description
                )
                configuration_mod.validate_evidence(candidate, bundle, description)
                configuration = candidate
                reconciliation_notes = candidate_notes
                break
            except ValueError as exc:
                errors.append(str(exc))
        if configuration is None:
            extraction_fallback = True
            configuration = configuration_mod.normalize({
                "configuration_status": "unknown",
                "summary": (
                    "Configuration extraction could not be certified after two attempts. "
                    "The generated script is fail-closed; inspect the validation errors "
                    "before manual use."
                ),
            })
        return {
            "environment": environment,
            "build_target": build_target,
            "configuration": configuration,
            "description": description,
            "raw": raw,
            "validation_errors": errors,
            "reconciliation_notes": reconciliation_notes,
            "configuration_fallback": extraction_fallback,
            "ground_truth": sources.nvd_ground_truth(bundle),
            "sources": bundle,
            "official_source_policy": coverage,
            "workflow": "vulnerable-vm+guest-configuration",
        }

    def _generate(self, request):
        if any(request.get(key) for key in ("poc_base64", "poc_success", "poc_args", "poc_path")):
            raise ValueError("PoC validation is outside this pipeline")
        configuration = configuration_mod.normalize(request.get("configuration"))
        bundle = request.get("sources")
        description = request.get("description")
        if not isinstance(bundle, dict) or not isinstance(description, str):
            raise ValueError("generation requires the validated source bundle and primary description")
        cve = request.get("cve") or "CVE"
        sources.validate_bundle_identity(bundle, cve)
        coverage = sources.require_multiple_official_sources(bundle)
        configuration_mod.validate_evidence(configuration, bundle, description)
        environment = request.get("environment")
        if not isinstance(environment, dict):
            raise ValueError("environment must be the object returned by /api/extract")
        build_target = environment.get("build_target") or {}
        kernel_constraints = environment.get("vulnerable_constraints") or {}
        kernel_script = None
        kernel_name = None
        if kernel_constraints.get("running_kernel_package_constraint"):
            evidence_environment = environment_mod.select(bundle)
            evidence_target = vulnerable_target_mod.select(bundle, evidence_environment)
            requested_contract = {
                key: build_target.get(key)
                for key in ("status", "os_family", "os_version", "suite", "architecture", "kernel")
            }
            evidence_contract = {
                key: evidence_target.get(key)
                for key in ("status", "os_family", "os_version", "suite", "architecture", "kernel")
            }
            if requested_contract != evidence_contract:
                raise ValueError(
                    "environment/build target was altered after official evidence selection"
                )
            if build_target.get("status") != "selected":
                raise ValueError("generation requires an exact vulnerable kernel build target")
            kernel = build_target["kernel"]
            kernel_script = distro_kernel.build({
                "package": kernel["meta_package"],
                "version_constraint": kernel["meta_package_constraint"],
                "concrete_kernel_constraint": kernel["concrete_package_constraint"],
                "target_meta_version": kernel["meta_package_version"],
                "target_kernel_release": kernel["running_kernel_release"],
                "os_family": build_target["os_family"],
                "os_version": build_target["os_version"],
                "package_manager": "apt",
            })
            kernel_name = distro_kernel.filename(cve)
        guest_script = guest_configuration.build(environment, configuration, cve)
        handoff = (
            packer_handoff.build(
                environment, cve, kernel_name, guest_configuration.filename(cve)
            )
            if kernel_name else None
        )
        if request.get("qemu_check"):
            qemu_script = qemu_vm.build(
                environment, cve,
                memory_mb=int(request.get("qemu_memory", 4096)),
                cpus=int(request.get("qemu_cpus", 2)),
                disk_size=str(request.get("qemu_disk_size", "20G")),
                timeout_s=int(request.get("qemu_timeout", 1800)),
                kernel_script=kernel_script,
            )
            check_script = configuration_check.build(
                environment, configuration, cve, guest_script=guest_script,
            )
            return {
                "script": qemu_script,
                "filename": qemu_vm.filename(cve),
                "check_script": check_script,
                "check_filename": configuration_check.filename(cve),
                "guest_script": guest_script,
                "guest_filename": guest_configuration.filename(cve),
                "kernel_script": kernel_script,
                "kernel_filename": kernel_name,
                "packer_handoff": handoff,
                "packer_handoff_filename": (
                    packer_handoff.filename(cve) if handoff else None
                ),
                "build_target": build_target,
                "generator_used": "exact vulnerable QEMU builder plus separate configuration checker",
                "workflow": "vulnerable-qemu-vm+guest-configuration-check",
                "official_source_policy": coverage,
            }
        return {
            "script": guest_script,
            "filename": guest_configuration.filename(cve),
            "kernel_script": kernel_script,
            "kernel_filename": kernel_name,
            "packer_handoff": handoff,
            "packer_handoff_filename": (
                packer_handoff.filename(cve) if handoff else None
            ),
            "build_target": build_target,
            "generator_used": "exact kernel target plus deterministic guest-configuration template",
            "workflow": "vulnerable-vm+guest-configuration",
            "official_source_policy": coverage,
        }

    def log_message(self, *_args):
        pass


def serve(host="127.0.0.1", port=8765):
    print(f"CVE configuration UI + API on http://{host}:{port}  (Ctrl-C to stop)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
