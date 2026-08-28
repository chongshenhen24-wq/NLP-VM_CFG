"""Validation and normalization for NLP-extracted guest configuration needs."""
from __future__ import annotations

import copy
import json
import re

STATUSES = {"required", "not_required", "unknown"}
_NAME = re.compile(r"^[A-Za-z0-9_.@+:{}/-]+$")
_MODULE = re.compile(r"^[A-Za-z0-9_-]+$")
_SYSCTL = re.compile(r"^[A-Za-z0-9_.-]+$")
_CONFIG = re.compile(r"^CONFIG_[A-Z0-9_]+$")


def _text(value, field: str, *, allow_empty=True) -> str:
    value = "" if value is None else str(value).strip()
    if (not allow_empty and not value) or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError(f"Invalid {field}")
    return value


def _list(value, field: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def normalize(raw: dict | None) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Configuration extraction must be a JSON object")
    status = str(raw.get("configuration_status") or "unknown").strip().lower()
    if status not in STATUSES:
        raise ValueError("configuration_status must be required, not_required, or unknown")
    result = {
        "configuration_status": status,
        "summary": _text(raw.get("summary"), "summary"),
        "kernel_modules": [],
        "kernel_config": [],
        "kernel_config_alternatives": [],
        "sysctls": [],
        "packages": [],
        "services": [],
        "file_settings": [],
        "manual_steps": [],
        "evidence": [],
    }

    for item in _list(raw.get("kernel_modules"), "kernel_modules"):
        name = _text((item or {}).get("name"), "module name", allow_empty=False)
        if not _MODULE.fullmatch(name):
            raise ValueError(f"Unsafe kernel module name: {name}")
        state = str((item or {}).get("state") or "loaded").lower()
        if state != "loaded":
            raise ValueError("Only the non-destructive kernel module state 'loaded' is supported")
        result["kernel_modules"].append({
            "name": name, "state": state,
            "persistent": bool((item or {}).get("persistent", True)),
            "reason": _text((item or {}).get("reason"), "module reason"),
        })

    for item in _list(raw.get("kernel_config"), "kernel_config"):
        symbol = _text((item or {}).get("symbol"), "kernel config symbol", allow_empty=False)
        value = _text((item or {}).get("value"), "kernel config value", allow_empty=False)
        if not _CONFIG.fullmatch(symbol) or value not in {"y", "m", "n", "enabled"}:
            raise ValueError(f"Invalid kernel config requirement: {symbol}={value}")
        result["kernel_config"].append({"symbol": symbol, "value": value,
                                        "reason": _text((item or {}).get("reason"), "kernel config reason")})

    for group in _list(raw.get("kernel_config_alternatives"), "kernel_config_alternatives"):
        if not isinstance(group, dict):
            raise ValueError("Each kernel config alternative group must be an object")
        options = []
        seen = set()
        for item in _list(group.get("one_of"), "kernel_config_alternatives.one_of"):
            if not isinstance(item, dict):
                raise ValueError("Each kernel config alternative must be an object")
            symbol = _text(item.get("symbol"), "kernel config alternative symbol", allow_empty=False)
            value = _text(item.get("value"), "kernel config alternative value", allow_empty=False)
            if not _CONFIG.fullmatch(symbol) or value not in {"y", "m", "n", "enabled"}:
                raise ValueError(f"Invalid kernel config alternative: {symbol}={value}")
            option_key = (symbol, value)
            if option_key in seen:
                raise ValueError(f"Duplicate kernel config alternative: {symbol}={value}")
            seen.add(option_key)
            options.append({"symbol": symbol, "value": value})
        if len(options) < 2:
            raise ValueError("kernel_config_alternatives.one_of requires at least two options")
        result["kernel_config_alternatives"].append({
            "one_of": options,
            "reason": _text(group.get("reason"), "kernel config alternative reason"),
        })

    for item in _list(raw.get("sysctls"), "sysctls"):
        key = _text((item or {}).get("key"), "sysctl key", allow_empty=False)
        value = _text((item or {}).get("value"), "sysctl value", allow_empty=False)
        if not _SYSCTL.fullmatch(key):
            raise ValueError(f"Unsafe sysctl key: {key}")
        result["sysctls"].append({"key": key, "value": value,
                                   "reason": _text((item or {}).get("reason"), "sysctl reason")})

    for item in _list(raw.get("packages"), "packages"):
        item = {"name": item} if isinstance(item, str) else (item or {})
        name = _text(item.get("name"), "package name", allow_empty=False)
        if not _NAME.fullmatch(name) or name.startswith(("linux-image", "linux-headers")):
            raise ValueError(f"Unsafe or infrastructure-owned package: {name}")
        result["packages"].append({"name": name, "reason": _text(item.get("reason"), "package reason")})

    for item in _list(raw.get("services"), "services"):
        name = _text((item or {}).get("name"), "service name", allow_empty=False)
        if not _NAME.fullmatch(name):
            raise ValueError(f"Unsafe service name: {name}")
        result["services"].append({
            "name": name,
            "state": "active",
            "enabled": bool((item or {}).get("enabled", False)),
            "reason": _text((item or {}).get("reason"), "service reason"),
        })

    for item in _list(raw.get("file_settings"), "file_settings"):
        path = _text((item or {}).get("path"), "file path", allow_empty=False)
        key = _text((item or {}).get("key"), "file setting key", allow_empty=False)
        value = _text((item or {}).get("value"), "file setting value")
        separator = str((item or {}).get("separator") or "=")
        if not path.startswith("/") or not _NAME.fullmatch(key) or separator not in {"=", " "}:
            raise ValueError(f"Unsafe file setting: {path} {key}")
        result["file_settings"].append({"path": path, "key": key, "value": value,
                                         "separator": separator,
                                         "reason": _text((item or {}).get("reason"), "file setting reason")})

    manual_steps = [_text(item, "manual step", allow_empty=False)
                    for item in _list(raw.get("manual_steps"), "manual_steps")]
    module_names = [item["name"].casefold() for item in result["kernel_modules"]]
    config_symbols = {item["symbol"] for item in result["kernel_config"]}
    for step in manual_steps:
        lowered = step.casefold()
        mentioned_symbols = set(re.findall(r"\bCONFIG_[A-Z0-9_]+\b", step))
        duplicate_module_step = (
            module_names and all(name in lowered for name in module_names)
            and ("load" in lowered or "startup" in lowered)
        )
        duplicate_summary_step = (
            "as specified" in lowered
            and ((result["kernel_modules"] and "module" in lowered)
                 or (result["kernel_config"] and "kernel configuration" in lowered))
        )
        duplicate_config_step = (
            bool(mentioned_symbols)
            and mentioned_symbols.issubset(config_symbols)
            and bool(re.search(r"\b(set|enable(?:d)?|configure|configuration)\b", lowered))
        )
        if not duplicate_module_step and not duplicate_summary_step and not duplicate_config_step:
            result["manual_steps"].append(step)
    for item in _list(raw.get("evidence"), "evidence"):
        if not isinstance(item, dict):
            raise ValueError("Each evidence item must be an object")
        result["evidence"].append({
            "claim": _text(item.get("claim"), "evidence claim", allow_empty=False),
            "source": _text(item.get("source"), "evidence source", allow_empty=False),
            "excerpt": re.sub(r"\s+", " ", str(item.get("excerpt") or "")).strip(),
        })

    actions = sum(len(result[field]) for field in (
        "kernel_modules", "kernel_config", "kernel_config_alternatives", "sysctls",
        "packages", "services", "file_settings", "manual_steps"
    ))
    if status == "required" and actions == 0:
        raise ValueError("configuration_status is required but no requirement was extracted")
    if status == "not_required" and actions:
        raise ValueError("not_required configuration must be an explicit no-op")
    if status == "unknown":
        # Unknown certifies no configuration claim and the generated script
        # refuses to apply. Discard contradictory action/citation noise rather
        # than retaining commands the model has itself marked unsupported. The
        # untouched raw response remains available for the audit trail.
        for field in (
            "kernel_modules", "kernel_config", "kernel_config_alternatives", "sysctls", "packages", "services",
            "file_settings", "manual_steps", "evidence",
        ):
            result[field] = []
    return result


def action_count(configuration: dict) -> int:
    return sum(len(configuration.get(field) or []) for field in (
        "kernel_modules", "kernel_config", "kernel_config_alternatives", "sysctls",
        "packages", "services", "file_settings", "manual_steps"
    ))


def _evidence_text(source: dict) -> str:
    values = []
    for key in ("description", "summary", "details", "excerpt", "affected", "cpe_matches"):
        value = source.get(key)
        if value:
            values.append(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
    return " ".join(values)


def _flat(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip().casefold()


def _named_loaded_modules(text: str) -> set[str]:
    """Extract explicit ``foo and bar modules are loaded`` prerequisites."""
    found = set()
    stopwords = {
        "a", "an", "and", "are", "be", "both", "kernel", "linux", "module", "modules",
        "must", "only", "or", "specific", "the", "these", "those", "to", "when",
    }
    pattern = re.compile(
        r"([^.;:\n]{1,180}?)\bmodules?\s+(?:must\s+be\s+|is\s+|are\s+)?loaded\b",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text or ""):
        fragment = re.split(r"\b(?:when|requires?|unless|if)\b", match.group(1), flags=re.IGNORECASE)[-1]
        for token in re.findall(r"\b[a-z][a-z0-9_-]{2,}\b", fragment.casefold()):
            if token not in stopwords:
                found.add(token)
    return found


def _available_sources(bundle: dict, description: str) -> dict[str, str]:
    available = {"Primary CVE description": description or ""}
    for source in bundle.get("sources") or []:
        text = _evidence_text(source)
        name, url = source.get("name"), source.get("url")
        if name:
            available[name] = text
        if url:
            available[url] = text
        # This was the display form used by prompt_evidence before source labels
        # were made unambiguous. Accept it so cached/replayed model output is not
        # rejected even though it still resolves to the same collected source.
        if name and url:
            available[f"{name} - {url}"] = text
    for reference in bundle.get("reference_evidence") or []:
        if reference.get("url"):
            url = reference["url"]
            text = reference.get("excerpt") or ""
            available[url] = text
            available[f"advisory reference - {url}"] = text
    return available


def _chunks(text: str) -> list[str]:
    """Return exact, reasonably small source spans suitable for citations."""
    chunks = []
    for line in re.split(r"[\r\n]+", text or ""):
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"(?<=[.!?;])\s+|\s+(?=[*-]\s+[A-Z])", line)
        chunks.extend(part.strip() for part in parts if part.strip())
    return chunks


def _find_excerpt(available: dict[str, str], predicate) -> tuple[str, str] | None:
    matches = []
    for source_name, source_text in available.items():
        for chunk in _chunks(source_text):
            if predicate(_flat(chunk)):
                matches.append((len(chunk), source_name, chunk))
    if not matches:
        return None
    _, source_name, excerpt = min(matches, key=lambda item: item[0])
    return source_name, excerpt


def _requirement_context(text: str) -> bool:
    return bool(re.search(
        r"\b(requirements?|required|requires?|needed|needs|must|enabled|capabilit(?:y|ies|es)|"
        r"kernel\s+config(?:uration)?|trigger(?:ing)?|prerequisite)s?\b",
        text,
    ))


def _config_value_in_text(text: str, symbol: str) -> str | None:
    match = re.search(rf"\b{re.escape(symbol.casefold())}\s*=\s*([ymn])\b", text)
    return match.group(1) if match else None


def _explicit_requirements(available: dict[str, str]) -> dict:
    singles: dict[str, str] = {}
    alternatives: list[dict[str, str]] = []
    capabilities = set()
    user_namespaces = False
    loaded_modules = set()
    manual_alternatives = []

    for source_text in available.values():
        flat_source = _flat(source_text)
        for match in re.finditer(r"\beither\b(.{0,400})", flat_source):
            alternative_text = match.group(1)
            if ("igmp" in alternative_text and "cap_net_admin" in alternative_text
                    and re.search(r"\buser\s+namespaces?\b", alternative_text)):
                markers = {"igmp", "cap_net_admin", "user namespace"}
                if markers not in manual_alternatives:
                    manual_alternatives.append(markers)
        for chunk in _chunks(source_text):
            flat = _flat(chunk)
            if not _requirement_context(flat):
                continue
            capabilities.update(token.upper() for token in re.findall(r"\bcap_[a-z0-9_]+\b", flat))
            if re.search(r"\buser\s+namespaces?\b", flat):
                explicitly_no = re.search(
                    r"user\s+namespaces?\s+(?:required|needed)\s*:\s*no\b", flat
                )
                if not explicitly_no:
                    user_namespaces = True
            loaded_modules.update(_named_loaded_modules(chunk))

            symbols = [token.upper() for token in re.findall(r"\bconfig_[a-z0-9_]+\b", flat)]
            if not symbols:
                continue
            alternative_symbols = []
            one_of = re.search(r"\bone\s+of\b(.*)", flat)
            if one_of:
                alternative_symbols = [
                    token.upper() for token in re.findall(r"\bconfig_[a-z0-9_]+\b", one_of.group(1))
                ]
                if len(alternative_symbols) >= 2:
                    group = {
                        symbol: (_config_value_in_text(flat, symbol) or "enabled")
                        for symbol in alternative_symbols
                    }
                    if group not in alternatives:
                        alternatives.append(group)
            for symbol in symbols:
                if symbol in alternative_symbols:
                    continue
                value = _config_value_in_text(flat, symbol) or "enabled"
                old = singles.get(symbol)
                if old is None or (old == "enabled" and value != "enabled"):
                    singles[symbol] = value
    return {
        "singles": singles,
        "alternatives": alternatives,
        "capabilities": capabilities,
        "user_namespaces": user_namespaces,
        "loaded_modules": loaded_modules,
        "manual_alternatives": manual_alternatives,
    }


def _config_supported(text: str, symbol: str, value: str) -> bool:
    flat = _flat(text)
    symbol = symbol.casefold()
    if value in {"y", "m", "n"}:
        return bool(re.search(rf"\b{re.escape(symbol)}\s*=\s*{value}\b", flat))
    return symbol in flat and _requirement_context(flat)


def _manual_markers(step: str) -> list[str]:
    markers = [token.casefold() for token in re.findall(r"\bCAP_[A-Z0-9_]+\b", step)]
    lowered = step.casefold()
    if re.search(r"\buser\s+namespaces?\b", lowered):
        markers.append("user namespace")
    if "igmp" in lowered:
        markers.append("igmp")
    return list(dict.fromkeys(markers))


def _manual_marker_supported(text: str, marker: str) -> bool:
    if marker not in text:
        return False
    if marker == "user namespace":
        if re.search(r"\b(disabl(?:e|ed|ing)|prevent(?:s|ed|ing)?)\b", text):
            return False
        if "cap_" in text and " or " in text:
            return True
        return bool(re.search(
            r"\b(required|needed|must|access|available|enabled|gained|yes)\b", text
        ))
    if marker == "igmp":
        return bool(re.search(r"\b(send|sending|possibility|required|needed|must)\b", text))
    return True


def reconcile_and_ground(configuration: dict, bundle: dict, description: str) -> tuple[dict, list[str]]:
    """Canonicalise explicit requirements and rebuild exact action-level citations.

    NLP still decides which typed prerequisites to emit. This deterministic
    stage can preserve an explicit ``=y/m/n`` value, recover OR semantics that
    the model flattened, and select exact source spans. It never turns an
    affected component name into an action.
    """
    result = copy.deepcopy(configuration)
    available = _available_sources(bundle, description)
    explicit = _explicit_requirements(available)
    notes = []

    if result["configuration_status"] == "unknown":
        if (explicit["singles"] or explicit["alternatives"] or explicit["capabilities"]
                or explicit["user_namespaces"] or explicit["loaded_modules"]
                or explicit["manual_alternatives"]):
            raise ValueError("configuration_status=unknown conflicts with explicit prerequisites in evidence")
        return result, notes

    if result["configuration_status"] == "not_required":
        match = _find_excerpt(available, lambda text: bool(re.search(
            r"\b(?:no|not)\s+(?:additional|extra|specific)?\s*"
            r"(?:guest\s+)?(?:configuration|setting|setup|prerequisite)s?\s+"
            r"(?:is|are|was|were)?\s*(?:required|needed|necessary)\b"
            r"|\b(?:enabled|available|loaded|reachable)\s+by\s+default\b"
            r"|\bdefault\s+(?:installation|configuration|setting)s?\b",
            text,
        )))
        if not match:
            raise ValueError("not_required is not explicitly supported by collected evidence")
        source, excerpt = match
        result["evidence"] = [{
            "claim": "No extra guest configuration is required.",
            "source": source,
            "excerpt": excerpt,
        }]
        return result, notes

    # Preserve the precision of the source. Refine generic ``enabled`` when
    # the evidence states y/m/n, and remove a model-invented exact value when
    # the evidence only says that a bare symbol is required.
    for item in result.get("kernel_config") or []:
        explicit_value = explicit["singles"].get(item["symbol"])
        if item["value"] == "enabled" and explicit_value in {"y", "m", "n"}:
            notes.append(f"{item['symbol']}: enabled -> {explicit_value} from exact evidence")
            item["value"] = explicit_value
        elif item["value"] in {"y", "m", "n"} and explicit_value == "enabled":
            notes.append(f"{item['symbol']}: {item['value']} -> enabled because evidence is mode-neutral")
            item["value"] = "enabled"

    # A common model error is to encode a single CONFIG_X=y requirement as an
    # alternative between CONFIG_X=y and CONFIG_X=m. If the source gives one
    # exact singleton value, collapse that malformed group before validating
    # real one-of groups.
    repaired_groups = []
    represented_singletons = {item["symbol"] for item in result.get("kernel_config") or []}
    for group in result.get("kernel_config_alternatives") or []:
        symbols = {item["symbol"] for item in group["one_of"]}
        if len(symbols) == 1:
            symbol = next(iter(symbols))
            expected_value = explicit["singles"].get(symbol)
            if expected_value:
                if symbol not in represented_singletons:
                    result["kernel_config"].append({
                        "symbol": symbol,
                        "value": expected_value,
                        "reason": "The source states one exact kernel configuration requirement.",
                    })
                    represented_singletons.add(symbol)
                notes.append(f"Collapsed a false same-symbol alternative to {symbol}={expected_value}")
                continue
        repaired_groups.append(group)
    result["kernel_config_alternatives"] = repaired_groups

    # Recover an explicitly documented one-of group if the model flattened at
    # least one of its options into mandatory kernel_config entries.
    for expected_group in explicit["alternatives"]:
        expected_symbols = set(expected_group)
        existing_group = next((
            group for group in result.get("kernel_config_alternatives") or []
            if {item["symbol"] for item in group["one_of"]} == expected_symbols
        ), None)
        if existing_group:
            for option in existing_group["one_of"]:
                expected_value = expected_group[option["symbol"]]
                if option["value"] == "enabled" and expected_value in {"y", "m", "n"}:
                    option["value"] = expected_value
                elif option["value"] in {"y", "m", "n"} and expected_value == "enabled":
                    option["value"] = "enabled"
            continue
        flattened = [
            item for item in result.get("kernel_config") or [] if item["symbol"] in expected_symbols
        ]
        if flattened:
            result["kernel_config"] = [
                item for item in result["kernel_config"] if item["symbol"] not in expected_symbols
            ]
            result["kernel_config_alternatives"].append({
                "one_of": [
                    {"symbol": symbol, "value": expected_group[symbol]}
                    for symbol in expected_group
                ],
                "reason": "The evidence requires at least one of these kernel options.",
            })
            notes.append("Recovered explicit one-of kernel configuration semantics")

    # Unsupported extras are not allowed to survive merely because the model
    # also found valid prerequisites. Removing them is safe: each typed action
    # needs its exact signature in the evidence, and this stage never adds an
    # executable action that the source did not name.
    supported_modules = []
    for item in result.get("kernel_modules") or []:
        name = item["name"].casefold()
        if _find_excerpt(available, lambda text, name=name: (
            name in text and "module" in text
            and bool(re.search(r"\b(load(?:ed|ing)?|required|requires?|must)\b", text))
        )):
            supported_modules.append(item)
        else:
            notes.append(f"Removed unsupported kernel module action: {item['name']}")
    result["kernel_modules"] = supported_modules

    supported_sysctls = []
    for item in result.get("sysctls") or []:
        key, value = item["key"].casefold(), item["value"].casefold()
        if _find_excerpt(available, lambda text, key=key, value=value: key in text and value in text):
            supported_sysctls.append(item)
        else:
            notes.append(f"Removed unsupported sysctl action: {item['key']}={item['value']}")
    result["sysctls"] = supported_sysctls

    supported_packages = []
    for item in result.get("packages") or []:
        name = item["name"].casefold()
        if _find_excerpt(available, lambda text, name=name: (
            name in text and bool(re.search(r"\b(package|install|required|dependency)\b", text))
        )):
            supported_packages.append(item)
        else:
            notes.append(f"Removed unsupported package action: {item['name']}")
    result["packages"] = supported_packages

    supported_services = []
    for item in result.get("services") or []:
        name = item["name"].casefold()
        if _find_excerpt(available, lambda text, name=name: (
            name in text and "service" in text
            and bool(re.search(r"\b(active|enable(?:d)?|running|start(?:ed)?)\b", text))
        )):
            supported_services.append(item)
        else:
            notes.append(f"Removed unsupported service action: {item['name']}")
    result["services"] = supported_services

    supported_file_settings = []
    for item in result.get("file_settings") or []:
        markers = [item["path"].casefold(), item["key"].casefold(), item["value"].casefold()]
        if _find_excerpt(available, lambda text, markers=markers: all(marker in text for marker in markers)):
            supported_file_settings.append(item)
        else:
            notes.append(f"Removed unsupported file-setting action: {item['path']} {item['key']}")
    result["file_settings"] = supported_file_settings

    # Capabilities and namespace access cannot be applied generically without
    # changing the threat model. Canonical manual gates avoid model wording
    # that accidentally turns a mitigation into an enablement action.
    canonical_manual = []
    for step in result.get("manual_steps") or []:
        markers = _manual_markers(step)
        covers_explicit = any(marker.upper() in explicit["capabilities"] for marker in markers)
        covers_explicit = covers_explicit or (
            "user namespace" in markers and explicit["user_namespaces"]
        )
        if covers_explicit:
            notes.append("Replaced model-written capability/namespace step with a canonical manual gate")
        else:
            canonical_manual.append(step)
    for capability in sorted(explicit["capabilities"]):
        canonical_manual.append(f"Ensure the test process has the {capability} capability.")
    if explicit["user_namespaces"]:
        if explicit["capabilities"]:
            canonical_manual.append(
                "Ensure unprivileged user namespaces are available when they are used to obtain "
                "the required capability."
            )
        else:
            canonical_manual.append("Ensure unprivileged user namespaces are available.")
    for alternative in explicit["manual_alternatives"]:
        canonical_manual = [
            step for step in canonical_manual
            if not (set(_manual_markers(step)) & alternative)
        ]
        if alternative == {"igmp", "cap_net_admin", "user namespace"}:
            canonical_manual.append(
                "Ensure IGMP packets can be sent, or ensure CAP_NET_ADMIN is available "
                "directly or through user namespaces."
            )
            notes.append("Canonicalised the explicit IGMP/capability/user-namespace alternative")
    result["manual_steps"] = list(dict.fromkeys(canonical_manual))

    manual_marker_sets = [set(_manual_markers(step)) for step in result["manual_steps"]]
    for alternative in explicit["manual_alternatives"]:
        if not any(alternative <= markers for markers in manual_marker_sets):
            raise ValueError(
                "Explicit manual alternative prerequisite is missing: "
                + ", ".join(sorted(alternative))
            )

    represented = {item["symbol"] for item in result.get("kernel_config") or []}
    missing = sorted(set(explicit["singles"]) - represented)
    for symbol in missing:
        value = explicit["singles"][symbol]
        result["kernel_config"].append({
            "symbol": symbol,
            "value": value,
            "reason": "Recovered from an explicit kernel-configuration requirement in the evidence.",
        })
        notes.append(f"Recovered omitted explicit kernel configuration: {symbol}={value}")
    represented_groups = [
        {item["symbol"] for item in group["one_of"]}
        for group in result.get("kernel_config_alternatives") or []
    ]
    for group in explicit["alternatives"]:
        if set(group) not in represented_groups:
            raise ValueError(
                "Explicit one-of kernel configuration prerequisite is missing: "
                + ", ".join(group)
            )

    representation_text = _flat(json.dumps({
        "manual_steps": result.get("manual_steps") or [],
        "sysctls": result.get("sysctls") or [],
    }))
    missing_caps = sorted(cap for cap in explicit["capabilities"] if cap.casefold() not in representation_text)
    if missing_caps:
        raise ValueError("Explicit capability prerequisite is missing: " + ", ".join(missing_caps))
    if explicit["user_namespaces"] and not re.search(r"\buser\s+namespaces?\b", representation_text):
        raise ValueError("Explicit user-namespace prerequisite is missing")

    grounded = []
    seen = set()

    def add_grounded(claim: str, match: tuple[str, str] | None, error: str) -> None:
        if not match:
            raise ValueError(error)
        source, excerpt = match
        key = (source, excerpt, claim)
        if key not in seen:
            grounded.append({"claim": claim, "source": source, "excerpt": excerpt})
            seen.add(key)

    for item in result.get("kernel_config") or []:
        add_grounded(
            f"{item['symbol']}={item['value']} is required",
            _find_excerpt(available, lambda text, item=item: _config_supported(
                text, item["symbol"], item["value"]
            )),
            f"Kernel configuration action lacks direct evidence: {item['symbol']}={item['value']}",
        )
    for group in result.get("kernel_config_alternatives") or []:
        symbols = [item["symbol"] for item in group["one_of"]]
        add_grounded(
            "At least one kernel configuration option is required: " + ", ".join(symbols),
            _find_excerpt(available, lambda text, symbols=symbols: (
                "one of" in text and all(symbol.casefold() in text for symbol in symbols)
            )),
            "Kernel configuration alternative group lacks direct one-of evidence: " + ", ".join(symbols),
        )
    for item in result.get("kernel_modules") or []:
        name = item["name"].casefold()
        add_grounded(
            f"Kernel module {item['name']} must be loaded",
            _find_excerpt(available, lambda text, name=name: (
                name in text and "module" in text
                and bool(re.search(r"\b(load(?:ed|ing)?|required|requires?|must)\b", text))
            )),
            f"Kernel module action is not explicitly supported as a load requirement: {item['name']}",
        )
    for item in result.get("sysctls") or []:
        key, value = item["key"].casefold(), item["value"].casefold()
        add_grounded(
            f"sysctl {item['key']}={item['value']} is required",
            _find_excerpt(available, lambda text, key=key, value=value: key in text and value in text),
            f"Sysctl action lacks direct evidence: {item['key']}={item['value']}",
        )
    for item in result.get("packages") or []:
        name = item["name"].casefold()
        add_grounded(
            f"Enablement package {item['name']} is required",
            _find_excerpt(available, lambda text, name=name: (
                name in text and bool(re.search(r"\b(package|install|required|dependency)\b", text))
            )),
            f"Package action lacks direct evidence: {item['name']}",
        )
    for item in result.get("services") or []:
        name = item["name"].casefold()
        add_grounded(
            f"Service {item['name']} must be active",
            _find_excerpt(available, lambda text, name=name: (
                name in text and "service" in text
                and bool(re.search(r"\b(active|enable(?:d)?|running|start(?:ed)?)\b", text))
            )),
            f"Service action lacks direct evidence: {item['name']}",
        )
    for item in result.get("file_settings") or []:
        markers = [item["path"].casefold(), item["key"].casefold(), item["value"].casefold()]
        add_grounded(
            f"File setting {item['path']} {item['key']} is required",
            _find_excerpt(available, lambda text, markers=markers: all(marker in text for marker in markers)),
            f"File-setting action lacks direct evidence: {item['path']} {item['key']}",
        )
    for step in result.get("manual_steps") or []:
        markers = _manual_markers(step)
        if not markers:
            raise ValueError("Manual prerequisite lacks a machine-checkable evidence marker: " + step)
        for marker in markers:
            add_grounded(
                "Manual prerequisite: " + step,
                _find_excerpt(available, lambda text, marker=marker: _manual_marker_supported(
                    text, marker
                )),
                f"Manual prerequisite lacks direct evidence for marker {marker}: {step}",
            )

    if not grounded:
        raise ValueError("A required decision has no directly grounded prerequisite")
    result["evidence"] = grounded
    return result, notes


def validate_evidence(configuration: dict, bundle: dict, description: str) -> None:
    """Require every action to resolve to an exact, semantically relevant source span."""
    available = _available_sources(bundle, description)

    evidence = configuration.get("evidence") or []
    if configuration.get("configuration_status") in {"required", "not_required"} and not evidence:
        raise ValueError("A required or not_required decision must cite collected evidence")
    for item in evidence:
        source_name = item.get("source") or ""
        if source_name not in available:
            raise ValueError(f"Configuration evidence cites an uncollected source: {source_name}")
        excerpt = _flat(item.get("excerpt") or "")
        source_text = _flat(available[source_name])
        if not excerpt:
            raise ValueError(f"Configuration evidence from {source_name} has no exact excerpt")
        if excerpt not in source_text:
            raise ValueError(
                f"Configuration evidence excerpt was not found in collected source: {source_name}"
            )
    if configuration.get("configuration_status") == "not_required":
        cited_text = _flat(" ".join(item.get("excerpt") or "" for item in evidence))
        explicit_noop = re.search(
            r"\b(?:no|not)\s+(?:additional|extra|specific)?\s*"
            r"(?:guest\s+)?(?:configuration|setting|setup|prerequisite)s?\s+"
            r"(?:is|are|was|were)?\s*(?:required|needed|necessary)\b"
            r"|\b(?:enabled|available|loaded|reachable)\s+by\s+default\b"
            r"|\bdefault\s+(?:installation|configuration|setting)s?\b",
            cited_text,
        )
        if not explicit_noop:
            raise ValueError(
                "not_required is not explicitly supported by cited evidence about default "
                "availability or the absence of extra configuration"
            )
    cited_text = _flat(" ".join(item.get("excerpt") or "" for item in evidence))
    for requirement in configuration.get("kernel_config") or []:
        if not _config_supported(cited_text, requirement["symbol"], requirement["value"]):
            raise ValueError(
                f"Kernel configuration action is not supported by its cited evidence: "
                f"{requirement['symbol']}={requirement['value']}"
            )
    for group in configuration.get("kernel_config_alternatives") or []:
        symbols = [item["symbol"] for item in group["one_of"]]
        if "one of" not in cited_text or not all(symbol.casefold() in cited_text for symbol in symbols):
            raise ValueError(
                "Kernel configuration alternative group is not supported by one-of evidence: "
                + ", ".join(symbols)
            )
    named_modules = set()
    for item in evidence:
        source_name = item.get("source") or ""
        named_modules.update(_named_loaded_modules(available.get(source_name, "")))
    represented_modules = {item["name"].casefold() for item in configuration.get("kernel_modules") or []}
    missing_modules = sorted(named_modules - represented_modules)
    if missing_modules:
        raise ValueError(
            "Named kernel module prerequisite is missing from typed actions: "
            + ", ".join(missing_modules)
        )
    for module in represented_modules:
        supported = _find_excerpt({"cited": cited_text}, lambda text, module=module: (
            module in text and "module" in text
            and bool(re.search(r"\b(load(?:ed|ing)?|required|requires?|must)\b", text))
        ))
        if not supported:
            raise ValueError(
                "Kernel module action is not explicitly supported as a load requirement: " + module
            )

    explicit = _explicit_requirements(available)
    represented_configs = {item["symbol"] for item in configuration.get("kernel_config") or []}
    missing_configs = sorted(set(explicit["singles"]) - represented_configs)
    if configuration.get("configuration_status") == "required" and missing_configs:
        raise ValueError("Explicit kernel configuration prerequisite is missing: " + ", ".join(missing_configs))
    represented_groups = [
        {item["symbol"] for item in group["one_of"]}
        for group in configuration.get("kernel_config_alternatives") or []
    ]
    if configuration.get("configuration_status") == "required":
        for group in explicit["alternatives"]:
            if set(group) not in represented_groups:
                raise ValueError(
                    "Explicit one-of kernel configuration prerequisite is missing: " + ", ".join(group)
                )
        manual_marker_sets = [
            set(_manual_markers(step)) for step in configuration.get("manual_steps") or []
        ]
        for alternative in explicit["manual_alternatives"]:
            if not any(alternative <= markers for markers in manual_marker_sets):
                raise ValueError(
                    "Explicit manual alternative prerequisite is missing: "
                    + ", ".join(sorted(alternative))
                )
    # An ``unknown`` result produced by the bounded extraction fallback has no
    # actions to validate and generates a script that refuses to apply. The
    # stricter unknown-vs-explicit-evidence check lives in
    # reconcile_and_ground(), where it can trigger the repair attempt.
