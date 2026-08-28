"""Pipeline configuration — one object instead of long parameter lists."""
from dataclasses import dataclass


@dataclass
class Config:
    endpoint: str = "http://localhost:11434"
    extract_model: str = "qwen2.5:14b"
    gen_model: str = "qwen2.5:14b"       # retained for legacy callers; v4 never asks a model to write shell
    generator: str = "template"          # retained for legacy callers; v4 is always deterministic
    machines_dir: str = "machines"
    register: bool = True
    nvd_api_key: str | None = None
    eval_log: str | None = None
    source_mode: str = "enrich"         # only enrich can satisfy the generation provenance gate
    source_timeout: int = 15
    source_bundle_dir: str | None = None  # prior official-evidence snapshots for reproducible replay
