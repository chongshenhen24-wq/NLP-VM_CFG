"""The extraction schema — one definition, used by the prompt AND documented for
every consumer. Change a field here and update spec.py + a generator; nothing
else hardcodes the shape.
"""

# Field order is canonical (used for stable serialisation).
FIELDS = (
    "package", "package_manager", "version_constraint", "concrete_kernel_constraint", "service_name",
    "start_command", "config_file", "os_family", "os_version",
    "config_directives", "setup_commands", "notes",
)

SCHEMA_TEXT = """{
  "package": string,                                   // package name to install
  "package_manager": "apt" | "pip" | "dnf" | "unknown",// how this package is installed
  "version_constraint": string or null,                // constraint in the exact installable package namespace
  "concrete_kernel_constraint": string or null,        // kernel only: independent constraint for the resolved linux-image-N package
  "service_name": string or null,                      // init.d/systemd service used with 'service X stop/start'; null if launched by a command
  "start_command": string or null,                     // command to start a non-init.d service (e.g. "superset run -p 8088"); null otherwise
  "config_file": string or null,                       // config path to edit ONLY if a config change is required; else null
  "os_family": "debian" | "ubuntu" | "rhel" | "windows" | "unknown",
  "os_version": string or null,                        // e.g. "22.04", "12", "Server 2016"; else null
  "config_directives": [ {"key": string, "value": string} ],       // settings REQUIRED to reproduce; [] if none (many vulns need none)
  "setup_commands": [ {"description": string, "command": string} ], // pre-install OS steps + post-install init (e.g. db migrations). NOT the package install/venv/service start-stop. [] if none.
  "notes": string                                      // 1-3 sentences: version range, attack vector, assumptions
}"""

# Version 3 schema: the model extracts only configuration prerequisites. Base
# OS and vulnerable-version selection are intentionally outside this schema.
CONFIGURATION_SCHEMA_TEXT = """{
  "configuration_status": "required" | "not_required" | "unknown",
  "summary": string,
  "kernel_modules": [
    {"name": string, "state": "loaded", "persistent": boolean, "reason": string}
  ],
  "kernel_config": [
    {"symbol": "CONFIG_*", "value": "y" | "m" | "n" | "enabled", "reason": string}
  ],
  "kernel_config_alternatives": [
    {
      "one_of": [
        {"symbol": "CONFIG_*", "value": "y" | "m" | "n" | "enabled"}
      ],
      "reason": string
    }
  ],
  "sysctls": [
    {"key": string, "value": string, "reason": string}
  ],
  "packages": [
    {"name": string, "reason": string}
  ],
  "services": [
    {"name": string, "state": "active", "enabled": boolean, "reason": string}
  ],
  "file_settings": [
    {"path": string, "key": string, "value": string, "separator": "=" | " ", "reason": string}
  ],
  "manual_steps": [string],
  "evidence": [
    {"claim": string, "source": string, "excerpt": string}
  ]
}"""


# Ollama accepts a JSON Schema object in its ``format`` field.  Keep this next
# to the human-readable prompt schema so the model and deterministic validator
# describe the same shape.  Semantic and evidence checks still happen in
# configuration.py; this schema only prevents avoidable formatting failures.
CONFIGURATION_JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "configuration_status", "summary", "kernel_modules", "kernel_config",
        "kernel_config_alternatives",
        "sysctls", "packages", "services", "file_settings", "manual_steps", "evidence",
    ],
    "properties": {
        "configuration_status": {
            "type": "string", "enum": ["required", "not_required", "unknown"],
        },
        "summary": {"type": "string"},
        "kernel_modules": {
            "type": "array", "maxItems": 16,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["name", "state", "persistent", "reason"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
                    "state": {"type": "string", "const": "loaded"},
                    "persistent": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
            },
        },
        "kernel_config": {
            "type": "array", "maxItems": 32,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["symbol", "value", "reason"],
                "properties": {
                    "symbol": {"type": "string", "pattern": "^CONFIG_[A-Z0-9_]+$"},
                    "value": {"type": "string", "enum": ["y", "m", "n", "enabled"]},
                    "reason": {"type": "string"},
                },
            },
        },
        "kernel_config_alternatives": {
            "type": "array", "maxItems": 16,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["one_of", "reason"],
                "properties": {
                    "one_of": {
                        "type": "array", "minItems": 2, "maxItems": 16,
                        "items": {
                            "type": "object", "additionalProperties": False,
                            "required": ["symbol", "value"],
                            "properties": {
                                "symbol": {"type": "string", "pattern": "^CONFIG_[A-Z0-9_]+$"},
                                "value": {"type": "string", "enum": ["y", "m", "n", "enabled"]},
                            },
                        },
                    },
                    "reason": {"type": "string"},
                },
            },
        },
        "sysctls": {
            "type": "array", "maxItems": 32,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["key", "value", "reason"],
                "properties": {
                    "key": {"type": "string", "pattern": "^[A-Za-z0-9_.-]+$"},
                    "value": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
        },
        "packages": {
            "type": "array", "maxItems": 32,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["name", "reason"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[A-Za-z0-9_.@+:{}/-]+$"},
                    "reason": {"type": "string"},
                },
            },
        },
        "services": {
            "type": "array", "maxItems": 16,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["name", "state", "enabled", "reason"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[A-Za-z0-9_.@+:{}/-]+$"},
                    "state": {"type": "string", "const": "active"},
                    "enabled": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
            },
        },
        "file_settings": {
            "type": "array", "maxItems": 32,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["path", "key", "value", "separator", "reason"],
                "properties": {
                    "path": {"type": "string", "pattern": "^/.*$"},
                    "key": {"type": "string", "minLength": 1,
                            "pattern": "^[A-Za-z0-9_.@+:{}/-]+$"},
                    "value": {"type": "string"},
                    "separator": {"type": "string", "enum": ["=", " "]},
                    "reason": {"type": "string"},
                },
            },
        },
        "manual_steps": {"type": "array", "maxItems": 16,
                         "items": {"type": "string", "minLength": 1}},
        "evidence": {
            "type": "array", "maxItems": 8,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["claim", "source", "excerpt"],
                "properties": {
                    "claim": {"type": "string", "minLength": 1},
                    "source": {"type": "string", "minLength": 1},
                    "excerpt": {"type": "string", "minLength": 1},
                },
            },
        },
    },
}
