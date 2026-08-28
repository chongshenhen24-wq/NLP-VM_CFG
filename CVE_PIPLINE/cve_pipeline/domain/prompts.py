"""Prompt builders for the two NLP stages, plus reply cleanup. Pure."""
import json
import re
from .schema import SCHEMA_TEXT, CONFIGURATION_SCHEMA_TEXT
from .generators.bash import LINEINFILE_HELPER

_EXTRACTION_RULES = (
    "Prefer information explicitly stated in the description. For version_constraint: exact stated "
    "version -> \"==<version>\"; \"before X\"/\"prior to X\" -> \"<X\"; \"A through B\" -> \">=A,<=B\". "
    "Do NOT invent a version the text does not state. Set config_file/config_directives ONLY when a "
    "config change is required (runtime/request bugs need neither: null and []). Service -> service_name "
    "(init.d/systemd) or start_command (command-launched). Do NOT put the package install or venv "
    "creation in setup_commands; DO include post-install init (e.g. \"superset db upgrade && superset "
    "init\"). For Linux kernel CVEs on Ubuntu/Debian, use an installable distro kernel binary/meta "
    "package (for example linux-image-generic), never the bare source package linux. Keep "
    "version_constraint in that exact installable package's version namespace. Also set "
    "concrete_kernel_constraint to the independently stated vulnerable constraint for the resolved "
    "linux-image-N binary; do not mix meta-package and concrete/source-package revisions. Copy both "
    "distro revisions from evidence and never substitute an upstream kernel tag. "
    "Windows -> os_family \"windows\" + os_version. Unknown -> null or []."
)


def extraction(description: str, os_hint: str = "auto", source_evidence: str = ""):
    system = (
        "You are a vulnerability analysis assistant supporting automated CVE reproduction. "
        "Given a CVE description, extract the parameters needed to write a provisioning script "
        "that installs the vulnerable package/service in the exact vulnerable state.\n\n"
        "Respond with ONLY valid JSON, no markdown, no fences, no prose. Match this schema:\n"
        + SCHEMA_TEXT + "\n\n" + _EXTRACTION_RULES
    )
    user = f"OS family hint from user: {os_hint}\n\nCVE description:\n{description}"
    if source_evidence:
        user += "\n\n" + source_evidence
    return system, user


def configuration_extraction(description: str, source_evidence: str = ""):
    """Prompt the model only for prerequisites applied inside an existing VM."""
    system = (
        "You analyse CVE evidence to identify EXTRA GUEST CONFIGURATION that must be applied "
        "after a separate, deterministic system has already created a VM with a vulnerable OS "
        "and vulnerable package/kernel version. You MUST NOT choose an OS, kernel, package "
        "version, cloud image, QEMU option, exploit, or PoC. You MUST NOT output installation "
        "steps for the vulnerable version. Extract only prerequisites that expose or enable the "
        "affected component: loadable kernel modules, required kernel CONFIG symbols, sysctls, "
        "small enablement packages, services, or exact configuration-file settings.\n\n"
        "Respond with ONLY valid JSON matching this schema:\n" + CONFIGURATION_SCHEMA_TEXT + "\n\n"
        "Decision rule: use configuration_status=not_required only when the evidence supports "
        "that the vulnerable component is reachable in the default installation. Use unknown "
        "when evidence is missing, conflicting, or merely implies a prerequisite. A subsystem "
        "name, affected source-file path, attack vector, or fixed-version table does NOT prove a "
        "module, CONFIG symbol, package, sysctl, service, or file setting is required. Do not emit "
        "a kernel_modules entry unless the evidence explicitly calls that exact name a module and "
        "states that it must be loaded. Never convert an affected component such as af_unix, "
        "nf_tables, net/sched, or a source-file name into a module or service. Do not emit "
        "mitigations or security-hardening settings: actions must expose the vulnerable component, "
        "not reduce its risk. Never convert uncertainty into a blank script. When required, every "
        "action must have a reason and at "
        "least one evidence item must identify an EXACT source label or URL shown in the supplied "
        "evidence. For the primary description use the literal source label 'Primary CVE description'. "
        "Every evidence excerpt MUST be a non-empty, contiguous, exact copy from its cited source; "
        "never invent a URL, citation, or quotation. Never use ellipses. Each action needs an "
        "evidence excerpt containing its exact module name, CONFIG symbol, sysctl, package, service, "
        "or file-setting key. A root-cause sentence that omits the prerequisite is not evidence for "
        "that action. Cite only the minimum evidence needed; do not "
        "copy package-version tables unless they explicitly support a configuration prerequisite. "
        "For configuration_status=unknown, use empty action and evidence lists. Use manual_steps for an explicit prerequisite "
        "that cannot safely be represented by a typed field. "
        "If evidence says a CONFIG symbol is enabled but does not distinguish built-in (=y) from "
        "modular (=m), or lists a bare CONFIG symbol under a Requirements/Kernel configuration "
        "heading, use the value 'enabled'. If the evidence writes CONFIG_NAME=y, =m, or =n, copy "
        "that exact value; never weaken it to 'enabled'. For 'CONFIG_A and one of CONFIG_B, "
        "CONFIG_C', put CONFIG_A in kernel_config and put CONFIG_B and CONFIG_C together in one "
        "kernel_config_alternatives.one_of group; never turn an OR requirement into mandatory entries. "
        "List EVERY module explicitly named as required; do not collapse or omit items in an "
        "'X and Y modules' statement. Do not duplicate typed actions in manual_steps. Do not place shell "
        "commands in any field. kernel_config entries are verification requirements: the guest "
        "script must never rebuild or replace the kernel. packages are helper/enablement packages "
        "only and must never include a kernel image or headers. manual_steps are comments for "
        "requirements that cannot be represented safely by the typed fields."
    )
    user = "Source: Primary CVE description\n" + description
    if source_evidence:
        user += "\n\n" + source_evidence
    return system, user


def configuration_repair_evidence(base_evidence: str, error: str, rejected_json: str) -> str:
    """Build bounded context for the one stateless model repair attempt."""
    rejected = (rejected_json or "").strip()[:8000]
    return (
        base_evidence
        + "\n\nREPAIR REQUEST (the rejected JSON below is NOT source evidence):\n"
        + "Deterministic validator error: " + error
        + "\nReturn one corrected, complete JSON object. Preserve only requirements supported "
          "by the source evidence. If the evidence does not explicitly support a safe decision, "
          "use configuration_status=unknown with empty action lists. Do not leave evidence excerpts blank. "
          "REMOVE the rejected action unless its exact typed signature appears in source evidence; "
          "do not repeat it with different wording. A sentence saying that disabling a feature "
          "prevents exploitation is a mitigation, not an instruction to disable that feature."
        + "\n\nRejected JSON:\n" + rejected
    )


def generation(spec: dict):
    system = (
        "You write bash provisioning scripts for automated CVE reproduction from a JSON spec.\n"
        "Rules:\n"
        "1. First line: #!/bin/bash -eux\n"
        "2. echo before each meaningful step.\n"
        "3. Install per package_manager+version_constraint. pip: python3 -m venv /opt/venv && "
        "source /opt/venv/bin/activate then pip install \"<pkg><constraint>\" (ALWAYS quote a "
        "specifier with < or >). apt exact ==X -> apt-get install -y -q <pkg>=X. Never emit "
        "${version}/$(version) placeholders — substitute concrete values.\n"
        "4. Include this helper VERBATIM:\n" + LINEINFILE_HELPER + "\n"
        "5. Run setup_commands after the helper, before the service.\n"
        "6. service_name -> stop before config, start last; or run start_command at the end.\n"
        "7. Each config_directive: lineinfile '<key>' '<key>=<value>' <config_file>. Empty -> no config.\n"
        "8. Output ONLY raw bash. No markdown, no fences."
    )
    user = "Specification JSON:\n" + json.dumps(spec, indent=2)
    return system, user


_FENCE_OPEN = re.compile(r"^```[\w-]*\s*")
_FENCE_CLOSE = re.compile(r"```$")


def strip_fences(raw: str) -> str:
    s = (raw or "").strip()
    return _FENCE_CLOSE.sub("", _FENCE_OPEN.sub("", s)).strip()


# ---- kernel-CVE extraction (introduced/fixed commits + versions from prose) ----
KERNEL_SCHEMA = """{
  "subsystem": string or null,            // affected area, e.g. "crypto/algif_aead"
  "introduced_version": string or null,   // e.g. "4.14"
  "introduced_commit": string or null,    // short or full hash
  "fixes": [ {"version": string, "commit": string or null} ],  // one per stable branch, e.g. 6.18.22 / 6.19.12 / 7.0
  "notes": string
}"""


def kernel_extraction(description: str, source_evidence: str = ""):
    system = (
        "You extract Linux kernel CVE fix metadata for automated reproduction. From the "
        "advisory text, identify the subsystem, the version/commit where the bug was INTRODUCED, "
        "and EVERY version/commit where it was FIXED (kernel CVEs are usually fixed across several "
        "stable branches — list them all). Respond with ONLY valid JSON, no prose, matching:\n"
        + KERNEL_SCHEMA + "\n\n"
        "Copy commit hashes and versions exactly as written. Do NOT guess a 'vulnerable' version — "
        "only report introduced and fixed as stated. If a field is absent, use null or []."
    )
    user = "CVE advisory:\n" + description
    if source_evidence:
        user += "\n\n" + source_evidence
    return system, user
