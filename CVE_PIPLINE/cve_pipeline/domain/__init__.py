"""Domain layer — pure logic, no I/O.

Everything here is a pure function of its inputs (no network, no filesystem,
no clock). This is the single source of truth for how a CVE spec is shaped,
sanitized, and turned into a provisioning script. Adapters and interfaces
depend on this layer; it depends on nothing above it.
"""
