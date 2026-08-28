import unittest
from unittest import mock

from cve_pipeline.adapters import ollama
from cve_pipeline.domain import configuration, environment
from cve_pipeline.domain.generators import guest_configuration
from cve_pipeline.domain.schema import CONFIGURATION_JSON_SCHEMA


class ConfigurationWorkflowTests(unittest.TestCase):
    def test_unknown_fails_closed(self):
        normalized = configuration.normalize({"configuration_status": "unknown", "summary": "Insufficient evidence."})
        script = guest_configuration.build({"os_family": None, "os_version": None}, normalized, "CVE-1")
        self.assertIn("configuration evidence is insufficient", script)
        self.assertNotIn("environment_ready=true\"\n}", script.split("configuration evidence remains unknown")[0])

    def test_unknown_discards_unverified_optional_citations(self):
        normalized = configuration.normalize({
            "configuration_status": "unknown",
            "summary": "Insufficient evidence.",
            "kernel_modules": [{"name": "unsupported", "state": "loaded"}],
            "manual_steps": ["Do something unsupported"],
            "evidence": [{"claim": "guess", "source": "invented", "excerpt": "..."}],
        })
        self.assertEqual(normalized["evidence"], [])
        self.assertEqual(normalized["kernel_modules"], [])
        self.assertEqual(normalized["manual_steps"], [])

    def test_not_required_needs_explicit_default_or_noop_evidence(self):
        value = configuration.normalize({
            "configuration_status": "not_required",
            "evidence": [{"claim": "kernel flaw", "source": "Primary CVE description",
                          "excerpt": "A flaw exists in the demo kernel component."}],
        })
        with self.assertRaisesRegex(ValueError, "not explicitly supported"):
            configuration.validate_evidence(
                value, {"sources": []}, "A flaw exists in the demo kernel component."
            )

    def test_unresolved_environment_fails_before_configuration(self):
        normalized = configuration.normalize({"configuration_status": "unknown"})
        script = guest_configuration.build({"status": "needs-input"}, normalized, "CVE-1")
        self.assertIn("base environment is unresolved", script)

    def test_not_required_is_strictly_empty(self):
        with self.assertRaisesRegex(ValueError, "explicit no-op"):
            configuration.normalize({"configuration_status": "not_required",
                                     "kernel_modules": [{"name": "fuse", "state": "loaded"}]})

    def test_kernel_image_cannot_be_smuggled_as_configuration(self):
        with self.assertRaisesRegex(ValueError, "infrastructure-owned"):
            configuration.normalize({"configuration_status": "required",
                                     "packages": [{"name": "linux-image-generic"}]})

    def test_direct_ubuntu_cpe_selects_environment_without_nlp(self):
        bundle = {"sources": [{"name": "NVD", "url": "https://example.test", "cpe_matches": [{
            "criteria": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*"
        }]}]}
        selected = environment.select(bundle)
        self.assertEqual(selected["status"], "selected")
        self.assertEqual(selected["os_version"], "22.04")
        self.assertEqual(selected["selection_basis"], "nvd-cpe")

    def test_application_cpe_does_not_invent_base_image(self):
        bundle = {"sources": [{"name": "NVD", "url": "https://example.test", "cpe_matches": [{
            "criteria": "cpe:2.3:a:example:demo:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"
        }]}]}
        selected = environment.select(bundle, "ubuntu")
        self.assertEqual(selected["status"], "needs-input")
        self.assertIsNone(selected["os_version"])

    def test_researcher_can_supply_missing_platform_without_nlp(self):
        selected = environment.select({"sources": []}, "ubuntu", "24.04")
        self.assertEqual(selected["status"], "selected")
        self.assertEqual(selected["selection_basis"], "user-supplied-platform")
        self.assertEqual(selected["suite"], "noble")

    def test_non_vulnerable_platform_cpe_can_select_image_without_becoming_the_product(self):
        bundle = {"sources": [{"name": "NVD", "url": "https://example.test", "cpe_matches": [
            {"criteria": "cpe:2.3:a:example:demo:*:*:*:*:*:*:*:*", "vulnerable": True,
             "versionEndExcluding": "2.0"},
            {"criteria": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*", "vulnerable": False},
        ]}]}
        selected = environment.select(bundle)
        self.assertEqual(selected["status"], "selected")
        self.assertEqual(selected["os_version"], "22.04")
        self.assertEqual(selected["vulnerable_constraints"], {})

    def test_model_cannot_cite_an_uncollected_source(self):
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_modules": [{"name": "fuse", "state": "loaded"}],
            "evidence": [{"claim": "FUSE is needed", "source": "https://example.invalid/advisory",
                          "excerpt": "FUSE is needed"}],
        })
        with self.assertRaisesRegex(ValueError, "uncollected source"):
            configuration.validate_evidence(value, {"sources": []}, "FUSE is needed")

    def test_prompt_display_source_alias_resolves_to_collected_source(self):
        excerpt = "The demo component is available in the default installation."
        bundle = {"sources": [{
            "name": "Ubuntu Security Tracker", "url": "https://ubuntu.test/CVE-1",
            "excerpt": excerpt,
        }]}
        value = configuration.normalize({
            "configuration_status": "not_required",
            "evidence": [{
                "claim": "Default installation is sufficient",
                "source": "Ubuntu Security Tracker - https://ubuntu.test/CVE-1",
                "excerpt": excerpt,
            }],
        })
        configuration.validate_evidence(value, bundle, "unrelated primary description")

    def test_configuration_extraction_uses_json_schema_format(self):
        response = {
            "configuration_status": "unknown", "summary": "insufficient evidence",
            "kernel_modules": [], "kernel_config": [], "sysctls": [], "packages": [],
            "services": [], "file_settings": [], "manual_steps": [], "evidence": [],
        }
        with mock.patch("cve_pipeline.adapters.ollama._generate",
                        return_value=__import__("json").dumps(response)) as generate:
            parsed, _ = ollama.extract_configuration("description", "http://local", "model")
        self.assertEqual(parsed["configuration_status"], "unknown")
        self.assertIs(generate.call_args.kwargs["force_json"], CONFIGURATION_JSON_SCHEMA)

    def test_evidence_excerpt_must_exist_in_source(self):
        value = configuration.normalize({
            "configuration_status": "not_required",
            "evidence": [{"claim": "Default is sufficient", "source": "Primary CVE description",
                          "excerpt": "invented quotation"}],
        })
        with self.assertRaisesRegex(ValueError, "excerpt was not found"):
            configuration.validate_evidence(value, {"sources": []}, "No additional setting is described.")

    def test_enabled_kernel_symbol_does_not_invent_y_or_m(self):
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_DEMO", "value": "enabled"}],
            "evidence": [{"claim": "symbol required", "source": "Primary CVE description",
                          "excerpt": "CONFIG_DEMO must be enabled"}],
        })
        configuration.validate_evidence(value, {"sources": []}, "CONFIG_DEMO must be enabled")
        script = guest_configuration.build({}, value, "CVE-1")
        self.assertIn("^CONFIG_DEMO=(y|m)$", script)

    def test_exact_kernel_symbol_value_requires_exact_evidence(self):
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_DEMO", "value": "y"}],
            "evidence": [{"claim": "symbol required", "source": "Primary CVE description",
                          "excerpt": "CONFIG_DEMO must be enabled"}],
        })
        with self.assertRaisesRegex(ValueError, "not supported"):
            configuration.validate_evidence(value, {"sources": []}, "CONFIG_DEMO must be enabled")

    def test_every_explicitly_named_module_must_be_represented(self):
        description = "The algif_aead and authencesn modules are loaded to expose the component."
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_modules": [{"name": "algif_aead", "state": "loaded"}],
            "evidence": [{"claim": "modules required", "source": "Primary CVE description",
                          "excerpt": description}],
        })
        with self.assertRaisesRegex(ValueError, "authencesn"):
            configuration.validate_evidence(value, {"sources": []}, description)

    def test_generic_manual_step_does_not_duplicate_typed_actions(self):
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_modules": [{"name": "demo", "state": "loaded"}],
            "kernel_config": [{"symbol": "CONFIG_DEMO", "value": "enabled"}],
            "manual_steps": ["Ensure modules are loaded and kernel configuration is set as specified"],
            "evidence": [{"claim": "requirements", "source": "Primary CVE description",
                          "excerpt": "demo module loaded and CONFIG_DEMO enabled"}],
        })
        self.assertEqual(value["manual_steps"], [])

    def test_symbol_manual_step_does_not_duplicate_typed_kernel_check(self):
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_AF_RXRPC", "value": "enabled"}],
            "manual_steps": [
                "Ensure CONFIG_AF_RXRPC is set to y in the kernel configuration."
            ],
        })
        self.assertEqual(value["manual_steps"], [])

    def test_affected_component_cannot_be_promoted_to_module(self):
        description = (
            "Requirements:\n- Kernel configuration: CONFIG_UNIX=y\n\n"
            "Affected component: af_unix."
        )
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_modules": [{"name": "af_unix", "state": "loaded"}],
            "kernel_config": [{"symbol": "CONFIG_UNIX", "value": "y"}],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertEqual(grounded["kernel_modules"], [])
        self.assertTrue(any("Removed unsupported kernel module" in note for note in notes))
        configuration.validate_evidence(grounded, {"sources": []}, description)

    def test_bare_required_kernel_symbols_mean_enabled(self):
        description = (
            "Requirements:\n- Kernel configuration: CONFIG_VSOCKETS, "
            "CONFIG_VSOCKETS_LOOPBACK"
        )
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [
                {"symbol": "CONFIG_VSOCKETS", "value": "enabled"},
                {"symbol": "CONFIG_VSOCKETS_LOOPBACK", "value": "enabled"},
            ],
        })
        grounded, _ = configuration.reconcile_and_ground(value, {"sources": []}, description)
        configuration.validate_evidence(grounded, {"sources": []}, description)
        self.assertEqual([item["value"] for item in grounded["kernel_config"]],
                         ["enabled", "enabled"])

    def test_omitted_explicit_kernel_symbol_is_recovered(self):
        description = (
            "Requirements: Kernel configuration: CONFIG_NETFILTER=y, "
            "CONFIG_IP_SET=y, CONFIG_IP_SET_LIST_SET=y"
        )
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [
                {"symbol": "CONFIG_NETFILTER", "value": "y"},
                {"symbol": "CONFIG_IP_SET", "value": "y"},
            ],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertIn(
            {"symbol": "CONFIG_IP_SET_LIST_SET", "value": "y",
             "reason": "Recovered from an explicit kernel-configuration requirement in the evidence."},
            grounded["kernel_config"],
        )
        self.assertTrue(any("Recovered omitted" in note for note in notes))
        configuration.validate_evidence(grounded, {"sources": []}, description)

    def test_common_capabilities_heading_typo_is_still_grounded(self):
        description = (
            "Requirements:\n- Capabilites: CAP_NET_ADMIN\n"
            "- Kernel configuration: CONFIG_NETFILTER=y"
        )
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_NETFILTER", "value": "y"}],
        })
        grounded, _ = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertTrue(any("CAP_NET_ADMIN" in step for step in grounded["manual_steps"]))
        configuration.validate_evidence(grounded, {"sources": []}, description)

    def test_exact_source_value_refines_generic_enabled(self):
        description = "Requirements: Kernel configuration: CONFIG_NET_SCHED=y"
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_NET_SCHED", "value": "enabled"}],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertEqual(grounded["kernel_config"][0]["value"], "y")
        self.assertIn("enabled -> y", notes[0])
        configuration.validate_evidence(grounded, {"sources": []}, description)

    def test_bare_source_symbol_removes_model_invented_build_mode(self):
        description = "Requirements: Kernel configuration: CONFIG_NETFILTER"
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_NETFILTER", "value": "y"}],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertEqual(grounded["kernel_config"][0]["value"], "enabled")
        self.assertIn("mode-neutral", notes[0])
        configuration.validate_evidence(grounded, {"sources": []}, description)

    def test_kernel_configuration_one_of_is_preserved_and_verified_as_or(self):
        description = (
            "Requirements to trigger the vulnerability: Kernel configuration: CONFIG_TLS "
            "and one of CONFIG_CRYPTO_PCRYPT, CONFIG_CRYPTO_CRYPTD"
        )
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [
                {"symbol": "CONFIG_TLS", "value": "enabled"},
                {"symbol": "CONFIG_CRYPTO_PCRYPT", "value": "enabled"},
                {"symbol": "CONFIG_CRYPTO_CRYPTD", "value": "enabled"},
            ],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertEqual([item["symbol"] for item in grounded["kernel_config"]], ["CONFIG_TLS"])
        self.assertEqual(
            {item["symbol"] for item in grounded["kernel_config_alternatives"][0]["one_of"]},
            {"CONFIG_CRYPTO_PCRYPT", "CONFIG_CRYPTO_CRYPTD"},
        )
        self.assertTrue(any("one-of" in note for note in notes))
        configuration.validate_evidence(grounded, {"sources": []}, description)
        script = guest_configuration.build({}, grounded, "CVE-1")
        alternative_line = next(line for line in script.splitlines()
                                if "no kernel config alternative is satisfied" in line)
        self.assertIn("CONFIG_CRYPTO_PCRYPT", alternative_line)
        self.assertIn(" || ", alternative_line)

    def test_false_same_symbol_alternative_collapses_to_exact_source_value(self):
        description = "Requirements: Kernel configuration: CONFIG_IP_SET_LIST_SET=y"
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config_alternatives": [{
                "one_of": [
                    {"symbol": "CONFIG_IP_SET_LIST_SET", "value": "y"},
                    {"symbol": "CONFIG_IP_SET_LIST_SET", "value": "m"},
                ]
            }],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertEqual(grounded["kernel_config_alternatives"], [])
        self.assertEqual(
            grounded["kernel_config"][0],
            {"symbol": "CONFIG_IP_SET_LIST_SET", "value": "y",
             "reason": "The source states one exact kernel configuration requirement."},
        )
        self.assertTrue(any("Collapsed" in note for note in notes))

    def test_unknown_conflicts_with_explicit_prerequisites_during_reconciliation(self):
        value = configuration.normalize({"configuration_status": "unknown"})
        with self.assertRaisesRegex(ValueError, "unknown conflicts"):
            configuration.reconcile_and_ground(
                value, {"sources": []},
                "Requirements: Kernel configuration: CONFIG_IO_URING",
            )

    def test_root_cause_text_cannot_support_a_configuration_action(self):
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_NF_TABLES", "value": "enabled"}],
        })
        with self.assertRaisesRegex(ValueError, "lacks direct evidence"):
            configuration.reconcile_and_ground(
                value, {"sources": []},
                "The root cause is an input sanitization bug in nf_tables_api.c.",
            )

    def test_mitigation_sysctl_is_removed_and_namespace_is_a_manual_gate(self):
        description = (
            "Triggering requires CONFIG_NET_SCH_HFSC to be enabled. The user must have "
            "CAP_NET_ADMIN, which can be gained with access to unprivileged user namespaces. "
            "Disabling unprivileged user namespaces prevents exploitation."
        )
        value = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_NET_SCH_HFSC", "value": "y"}],
            "sysctls": [{"key": "kernel.unprivileged_userns_clone", "value": "0"}],
            "manual_steps": ["Disable unprivileged user namespaces to prevent exploitation."],
        })
        grounded, notes = configuration.reconcile_and_ground(value, {"sources": []}, description)
        self.assertEqual(grounded["sysctls"], [])
        self.assertTrue(any("Removed unsupported sysctl" in note for note in notes))
        self.assertTrue(any("CAP_NET_ADMIN" in step for step in grounded["manual_steps"]))
        self.assertTrue(any("available" in step and "user namespaces" in step
                            for step in grounded["manual_steps"]))
        self.assertFalse(any("Disable" in step for step in grounded["manual_steps"]))

    def test_explicit_manual_or_condition_cannot_be_omitted(self):
        description = (
            "Requirements:\n- Kernel configuration: CONFIG_IP_MULTICAST=y\n"
            "- Either:\n  - Possibility to send IGMP packets\n"
            "  - CAP_NET_ADMIN or user namespaces"
        )
        incomplete = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_IP_MULTICAST", "value": "y"}],
        })
        recovered, notes = configuration.reconcile_and_ground(incomplete, {"sources": []}, description)
        self.assertTrue(any("IGMP" in step and "CAP_NET_ADMIN" in step
                            for step in recovered["manual_steps"]))
        self.assertTrue(any("Canonicalised" in note for note in notes))
        configuration.validate_evidence(recovered, {"sources": []}, description)

        complete = configuration.normalize({
            "configuration_status": "required",
            "kernel_config": [{"symbol": "CONFIG_IP_MULTICAST", "value": "y"}],
            "manual_steps": [
                "Ensure IGMP packets can be sent, or CAP_NET_ADMIN or user namespaces are available."
            ],
        })
        grounded, _ = configuration.reconcile_and_ground(complete, {"sources": []}, description)
        configuration.validate_evidence(grounded, {"sources": []}, description)


if __name__ == "__main__":
    unittest.main()
