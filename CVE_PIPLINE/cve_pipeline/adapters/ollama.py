"""Ollama adapter. Thinking-model safe (think:false + <think> fallback)."""
import json
import re
import urllib.request
import urllib.error

from ..domain import prompts
from ..domain.schema import CONFIGURATION_JSON_SCHEMA


class InvalidModelJSON(ValueError):
    """A model reply that can be retained and passed to the bounded repair."""

    def __init__(self, message: str, raw: str):
        super().__init__(message)
        self.raw = raw


def _generate(endpoint, model, system, prompt, force_json, timeout=300):
    body = {"model": model, "system": system, "prompt": prompt, "stream": False,
            "think": False, "options": {"num_predict": 4096}}
    if force_json:
        body["format"] = force_json if isinstance(force_json, dict) else "json"
    req = urllib.request.Request(endpoint.rstrip("/") + "/api/generate",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:200] if e.fp else ""
        raise RuntimeError(f"Ollama HTTP {e.code}: {detail} (check model via {endpoint}/api/tags)")
    out = data.get("response") or ""
    if not out.strip():
        out = re.sub(r"(?s)<think>.*?</think>", "", data.get("thinking") or "").strip()
    return out


def extract(description, endpoint, model, os_hint="auto", source_evidence=""):
    system, user = prompts.extraction(description, os_hint, source_evidence)
    raw = _generate(endpoint, model, system, user, force_json=True)
    cleaned = prompts.strip_fences(raw)
    try:
        return json.loads(cleaned), raw
    except json.JSONDecodeError as e:
        raise ValueError(f"Extraction model did not return valid JSON: {e}\nRaw: {raw[:400]}")


def extract_configuration(description, endpoint, model, source_evidence=""):
    system, user = prompts.configuration_extraction(description, source_evidence)
    raw = _generate(endpoint, model, system, user, force_json=CONFIGURATION_JSON_SCHEMA)
    cleaned = prompts.strip_fences(raw)
    try:
        return json.loads(cleaned), raw
    except json.JSONDecodeError as e:
        raise InvalidModelJSON(
            f"Configuration model did not return one valid JSON object: {e}", raw
        ) from e


def generate_bash(spec, endpoint, model):
    system, user = prompts.generation(spec)
    raw = _generate(endpoint, model, system, user, force_json=False)
    script = prompts.strip_fences(raw)
    return (script if script.endswith("\n") else script + "\n"), raw
