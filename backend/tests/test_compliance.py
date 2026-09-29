import unittest
import asyncio
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import URLError

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from starlette.datastructures import UploadFile

from app import main
from app.canonical import BENCHMARK, BENCHMARK_VERSION
from app.engine import evaluate, normalize_config
from app.models import Device, LearnedPattern, TrainingMapping
from pydantic import ValidationError
from app import database, llm


CISCO = """hostname test-router
version 17.9.4 IOS-XE
ip ssh version 2
"""

JUNIPER = """set system host-name branch-srx-01
set version 21.4R3.15
set system services ssh protocol-version v2
"""


class ComplianceEngineTests(unittest.TestCase):
    def finding(self, baseline, control_id="2.1.1.2"):
        return next(f for f in evaluate(baseline) if f.control_id == control_id)

    def test_cisco_sshv2_is_normalized_and_passes(self):
        baseline = normalize_config(CISCO)
        finding = self.finding(baseline)
        self.assertEqual(baseline.vendor, "Cisco")
        self.assertEqual(baseline.ssh_version, "2")
        self.assertEqual(finding.status, "pass")
        self.assertEqual(finding.canonical_control, "management.ssh.version")

    def test_cisco_sshv1_fails(self):
        baseline = normalize_config(CISCO.replace("version 2", "version 1"))
        self.assertEqual(self.finding(baseline).status, "fail")

    def test_cisco_green_path_fixture_passes_current_rules(self):
        config = (Path(__file__).resolve().parents[2] / "test-configs" / "cisco-rule-engine-green-path.cfg").read_text()
        findings = evaluate(normalize_config(config))
        statuses = [finding.status for finding in findings]
        self.assertEqual(len(statuses), 56)
        self.assertEqual(set(statuses), {"pass"})
        self.assertEqual(sum(finding.control_id == "2.2.8" for finding in findings), 1)

    def test_unsupported_juniper_controls_remain_unknown(self):
        baseline = normalize_config("set system host-name branch-srx-01\n")
        self.assertEqual(self.finding(baseline).status, "unknown")

    def test_unknown_controls_do_not_inflate_posture_score(self):
        device = main.build_device("juniper.set", JUNIPER)
        self.assertEqual(device.score, round(1 / 56 * 100))
        self.assertEqual(device.status, "attention")

    def test_login_success_failure_is_one_compound_benchmark_rule(self):
        baseline = normalize_config(CISCO + "login on-failure log\n")
        finding = self.finding(baseline, "2.2.8")
        self.assertEqual(finding.status, "fail")
        self.assertEqual(finding.actual, "partially enabled")

    def test_juniper_ssh_is_cross_vendor_and_not_human_validated(self):
        baseline = normalize_config(JUNIPER)
        finding = self.finding(baseline)
        self.assertEqual(baseline.vendor, "Juniper")
        self.assertEqual(finding.status, "pass")
        self.assertEqual(finding.assessment_type, "cross_vendor")
        self.assertAlmostEqual(finding.mapping_confidence, 0.97)
        self.assertFalse(finding.human_validated)

    def test_approved_mapping_sets_canonical_fact(self):
        pattern = LearnedPattern(
            id="p1",
            source_pattern="ssh strength two",
            canonical_control="management.ssh.version",
            canonical_value="2",
            label="SSHv2",
            vendor="Cisco",
            platform="IOS / NX-OS",
            category="Access control",
            confidence=0.84,
            human_validated=True,
            confirmed_at="2026-09-29T00:00:00+00:00",
            training_item_id="t1",
        )
        baseline = normalize_config(CISCO + "ssh strength two\n", [pattern])
        self.assertEqual(baseline.ssh_version, "2")
        self.assertIn("ssh_version", baseline.known_fields)
        finding = self.finding(baseline)
        self.assertEqual(finding.status, "pass")
        self.assertTrue(finding.human_validated)

    def test_api_finding_contract_has_one_cis_control_identifier(self):
        finding = self.finding(normalize_config(CISCO)).model_dump()
        self.assertEqual(finding["framework"], "CIS")
        self.assertEqual(finding["benchmark"], BENCHMARK)
        self.assertEqual(finding["benchmark_version"], BENCHMARK_VERSION)
        self.assertIn("control_id", finding)
        self.assertNotIn("cis_id", finding)
        self.assertIn("profile", finding)
        self.assertIn("evidence", finding)

    def test_report_endpoint_returns_pdf_with_complete_rule_set(self):
        original = main.current_device
        original_text = main.current_config_text
        main.current_config_text = CISCO
        main.current_device = main.build_device("test.cfg", CISCO)
        try:
            response = main.report(main.current_device.id)
            async def read_body():
                return b"".join([chunk async for chunk in response.body_iterator])
            body = asyncio.run(read_body())
        finally:
            main.current_device = original
            main.current_config_text = original_text
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertTrue(body.startswith(b"%PDF-"))
        self.assertIn(b"3.1.1", body)

    def test_ollama_fallback_does_not_guess_a_compliance_mapping(self):
        with patch.object(llm, "urlopen", side_effect=URLError("offline")):
            suggestion = llm.suggest_mapping("vendor ssh activate", ["Access control"], "Juniper", "Junos")
        self.assertIsNone(suggestion["canonical_control"])
        self.assertIsNone(suggestion["canonical_value"])
        self.assertEqual(suggestion["provider"], "heuristic-fallback")

    def test_training_api_rejects_unknown_canonical_controls(self):
        with self.assertRaises(ValidationError):
            TrainingMapping(
                label="bad mapping",
                canonical_control="security.not_a_real_field",
                canonical_value=True,
                category="Access control",
            )

    def test_devices_endpoint_declares_shared_response_model(self):
        route = next(r for r in main.app.routes if getattr(r, "path", None) == "/api/devices")
        self.assertEqual(route.response_model, list[Device])


class LearningLoopTests(unittest.TestCase):
    def test_approved_mapping_is_reused_without_another_llm_call(self):
        saved_devices = Mock()
        saved_training = Mock()
        saved_patterns = Mock()
        suggestion = {
            "semantic_meaning": "Enables SSH protocol version 2",
            "category": "Access control",
            "canonical_control": "management.ssh.version",
            "canonical_value": "2",
            "confidence": 0.91,
            "provider": "ollama",
        }
        original = {
            "current_device": main.current_device,
            "current_config_text": main.current_config_text,
            "training_items": main.training_items,
            "learned_patterns": main.learned_patterns,
        }
        try:
            main.current_config_text = ""
            main.training_items = []
            main.learned_patterns = []
            main.current_device = main.build_device("sample.cfg", "hostname sample\nversion 17.9 IOS-XE\n")
            with patch.object(main, "save_device", saved_devices), \
                    patch.object(main, "save_training", saved_training), \
                    patch.object(main, "save_pattern", saved_patterns), \
                    patch.object(main, "suggest_mapping", return_value=suggestion) as llm:
                config = CISCO + "ssh strength two\n"
                upload = UploadFile(filename="unknown.cfg", file=BytesIO(config.encode()))
                first = asyncio.run(main.ingest(upload))
                item = next(t for t in main.training_items if t.status == "pending")
                self.assertEqual(llm.call_count, 1)

                approved = main.approve_training(item.id, TrainingMapping(
                    label="Enable SSHv2",
                    canonical_control="management.ssh.version",
                    canonical_value="2",
                    semantic_meaning="Enables SSH protocol version 2",
                    vendor="Cisco",
                    platform="IOS / NX-OS",
                    category="Access control",
                    confidence=0.91,
                ))
                self.assertEqual(approved.status, "approved")
                self.assertEqual(main.current_device.baseline.ssh_version, "2")
                self.assertEqual(next(f for f in main.current_device.findings if f.control_id == "2.1.1.2").status, "pass")
                self.assertEqual(saved_patterns.call_count, 1)

                second = asyncio.run(main.ingest(UploadFile(
                    filename="unknown-again.cfg", file=BytesIO(config.encode())
                )))
                self.assertEqual(llm.call_count, 1)
                self.assertEqual(main.current_device.baseline.ssh_version, "2")
                self.assertEqual(main.current_device.baseline.unrecognized_lines, [])
        finally:
            main.current_device = original["current_device"]
            main.current_config_text = original["current_config_text"]
            main.training_items = original["training_items"]
            main.learned_patterns = original["learned_patterns"]


class PersistenceTests(unittest.TestCase):
    def test_canonical_mapping_round_trips_through_sqlite(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        try:
            with patch.object(database, "_engine", engine):
                database.Base.metadata.create_all(engine)
                pattern = LearnedPattern(
                    id="persisted-p1",
                    source_pattern="ssh strength two",
                    canonical_control="management.ssh.version",
                    canonical_value="2",
                    label="SSHv2",
                    vendor="Cisco",
                    platform="IOS / NX-OS",
                    category="Access control",
                    confidence=0.91,
                    human_validated=True,
                    confirmed_at="2026-09-29T00:00:00+00:00",
                    training_item_id="persisted-t1",
                )
                database.save_pattern(pattern)
                [loaded] = database.load_patterns()
                self.assertEqual(loaded.canonical_control, pattern.canonical_control)
                self.assertEqual(loaded.canonical_value, "2")
                self.assertEqual(loaded.source_pattern, pattern.source_pattern)
                self.assertEqual(loaded.confidence, 0.91)
                self.assertTrue(loaded.human_validated)

                from app.models import TrainingItem
                item = TrainingItem(
                    id="persisted-t1",
                    raw_line="ssh strength two",
                    suggested_category="Access control",
                    semantic_meaning="Enables SSHv2",
                    canonical_control="management.ssh.version",
                    canonical_value="2",
                    confidence=0.91,
                    vendor="Cisco",
                    platform="IOS / NX-OS",
                    provider="ollama",
                )
                database.save_training(item)
                [loaded_item] = database.load_training()
                self.assertEqual(loaded_item.canonical_control, "management.ssh.version")
                self.assertEqual(loaded_item.canonical_value, "2")
                self.assertEqual(loaded_item.provider, "ollama")
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
