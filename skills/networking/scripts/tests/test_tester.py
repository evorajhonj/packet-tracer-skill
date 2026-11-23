import contextlib
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pkt_tester
import pkt_tool


FIXTURE = Path(__file__).parent / "fixtures" / "two-cloud-ipv4.xml.gz"


class TesterTest(unittest.TestCase):
    def test_legacy_file_check_does_not_run_eax_encryption(self):
        self.source.write_bytes(pkt_tool.obfuscate_stage2(pkt_tool.compress_qt(ET.tostring(self.root))))
        with patch("pkt_tool.pack_xml", side_effect=AssertionError("Legacy path should not invoke EAX")):
            report = pkt_tester.test_packet(self.source, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["source_unchanged"])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tester-test-")
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "lab.pkt"
        self.root = pkt_tool.parse_xml(gzip.decompress(FIXTURE.read_bytes()))
        self.save_packet()

    def save_packet(self):
        self.source.write_bytes(pkt_tool.pack_xml(ET.tostring(self.root, encoding="utf-8")))

    def run_main(self, arguments):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = pkt_tester.main(arguments)
        return code, json.loads(stream.getvalue())

    def test_valid_packet_is_read_only_and_reports_actual_absolute_path(self):
        before = self.source.read_bytes()
        report = pkt_tester.test_packet(self.source, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["input_path"], str(self.source.resolve()))
        self.assertEqual(self.source.read_bytes(), before)
        self.assertTrue(report["source_unchanged"])
        self.assertEqual(report["source_sha256_before"], report["source_sha256_after"])
        self.assertEqual(report["counts"]["path_checks"], 2)
        self.assertEqual(report["counts"]["checks_failed"], 0)
        self.assertFalse(report["simulation_tested"])
        self.assertFalse(report["window_title_tested"])
        self.assertIn("No Packet Tracer simulation ran", report["summary"])

    def test_unsupported_routing_remains_partial_with_modeled_paths(self):
        router = self.root.findall("NETWORK/DEVICES/DEVICE")[1]
        ET.SubElement(router.find("ENGINE/RUNNINGCONFIG"), "LINE").text = "router ospf 1"
        self.save_packet()
        code, report = self.run_main([str(self.source), "--between", "PC1", "PC2"])
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "partial")
        self.assertGreater(report["counts"]["checks_partial"], 0)
        self.assertFalse(report["simulation_tested"])

    def test_invalid_gateway_returns_failed(self):
        pc = next(device for device in self.root.findall("NETWORK/DEVICES/DEVICE") if device.findtext("ENGINE/NAME") == "PC2")
        pc.find("ENGINE/GATEWAY").text = "192.168.10.1"
        self.save_packet()
        code, report = self.run_main([str(self.source), "--between", "PC1", "PC2"])
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "failed")
        evidence = next(item for item in report["evidence"] if item["check"] == "network_audit")
        self.assertIn("host.gateway", evidence["details"]["error_codes"])

    def test_unknown_host_pair_cannot_succeed(self):
        report = pkt_tester.test_packet(self.source, [["PC1", "DoesNotExist"]])
        self.assertEqual(report["status"], "failed")

    def test_requested_pairs_are_checked_in_both_directions(self):
        report = pkt_tester.test_packet(self.source, [["PC1", "PC2"], ["PC2", "PC1"]])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"]["path_checks"], 4)

    def test_missing_direction_is_not_full_success(self):
        fake = {"status": "passed", "errors": [], "warnings": [], "paths": [{"status": "modeled"}]}
        with patch("pkt_tester.audit", return_value=fake):
            report = pkt_tester.test_packet(self.source, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "partial")

    def test_unknown_path_result_is_partial_even_if_audit_claims_passed(self):
        fake = {"status": "passed", "errors": [], "warnings": [], "paths": [{"status": "unknown"}, {"status": "modeled"}]}
        with patch("pkt_tester.audit", return_value=fake):
            report = pkt_tester.test_packet(self.source, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "partial")

    def test_corrupt_packet_does_not_change_input(self):
        self.source.write_bytes(b"not a packet file")
        before = self.source.read_bytes()
        report = pkt_tester.test_packet(self.source)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(self.source.read_bytes(), before)
        self.assertTrue(report["source_unchanged"])

    def test_missing_packet_produces_failed_summary(self):
        report = pkt_tester.test_packet(self.source.parent / "missing.pkt")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["checks_failed"], 1)
        self.assertFalse(report["simulation_tested"])

    def test_source_change_during_checks_is_detected(self):
        real_audit = pkt_tester.audit

        def change_source(root, pairs):
            self.source.write_bytes(b"external change")
            return real_audit(root, pairs)

        with patch("pkt_tester.audit", side_effect=change_source):
            report = pkt_tester.test_packet(self.source)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["source_unchanged"])
        self.assertNotEqual(report["source_sha256_before"], report["source_sha256_after"])

    def test_profiles_passwords_xml_and_exception_messages_are_excluded(self):
        private = "PROFILE_PRIVATE_61392"
        password = "PASSWORD_PRIVATE_87246"
        profile = ET.SubElement(self.root, "USERPROFILE")
        ET.SubElement(profile, "NAME").text = private
        router = self.root.findall("NETWORK/DEVICES/DEVICE")[1]
        ET.SubElement(router.find("ENGINE/RUNNINGCONFIG"), "LINE").text = "enable secret " + password
        self.save_packet()
        report = pkt_tester.test_packet(self.source)
        output = json.dumps(report)
        self.assertNotIn(private, output)
        self.assertNotIn(password, output)
        self.assertNotIn("<PACKETTRACER", output)
        with patch("pkt_tester.audit", side_effect=ValueError(password)):
            report = pkt_tester.test_packet(self.source)
        self.assertNotIn(password, json.dumps(report))

    def test_report_written_only_to_explicit_distinct_path(self):
        report_path = self.source.parent / "report.json"
        before = self.source.read_bytes()
        code, report = self.run_main([str(self.source), "--report", str(report_path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(report_path.read_text()), report)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(sorted(path.name for path in self.source.parent.iterdir()), ["lab.pkt", "report.json"])

    def test_existing_report_requires_explicit_overwrite(self):
        report_path = self.source.parent / "report.json"
        report_path.write_text("preserve me")
        code, report = self.run_main([str(self.source), "--report", str(report_path)])
        self.assertEqual(code, 1)
        self.assertEqual(report_path.read_text(), "preserve me")
        self.assertEqual(report["status"], "failed")
        code, report = self.run_main([str(self.source), "--report", str(report_path), "--overwrite"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(report_path.read_text())["status"], "passed")

    def test_report_cannot_replace_source_even_with_overwrite(self):
        before = self.source.read_bytes()
        code, report = self.run_main([str(self.source), "--report", str(self.source), "--overwrite"])
        self.assertEqual(code, 1)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(report["status"], "failed")

    def test_report_hard_link_to_source_is_rejected(self):
        alias = self.source.parent / "source-alias.json"
        try:
            alias.hardlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest("Filesystem does not support hard links")
        before = self.source.read_bytes()
        code, _ = self.run_main([str(self.source), "--report", str(alias), "--overwrite"])
        self.assertEqual(code, 1)
        self.assertEqual(self.source.read_bytes(), before)

    def test_invalid_cli_combinations_do_not_start_checks(self):
        for arguments in [["--between", "PC1", "PC2"], ["--overwrite"]]:
            with self.subTest(arguments=arguments), patch("pkt_tester.test_skill") as checks:
                code, report = self.run_main(arguments)
            self.assertEqual(code, 1)
            self.assertEqual(report["status"], "failed")
            checks.assert_not_called()

    def test_no_input_runs_all_checks_without_recursive_suite_in_this_test(self):
        suite = {"status": "passed", "tests_run": 8, "failures": 0, "errors": 0,
                 "skipped": 0, "expected_failures": 0, "unexpected_successes": 0}
        with patch("pkt_tester._run_regressions", return_value=suite) as regressions, \
                patch("pkt_tester._run_smoke", return_value={"temporary_artifacts_only": True}) as smoke:
            code, report = self.run_main([])
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"]["regression_tests_run"], 8)
        self.assertEqual(report["counts"]["checks_total"], 3)
        self.assertFalse(report["simulation_tested"])
        regressions.assert_called_once()
        smoke.assert_called_once()

    def test_regression_failure_does_not_hide_other_checks(self):
        suite = {"status": "failed", "tests_run": 8, "failures": 1, "errors": 0,
                 "skipped": 0, "expected_failures": 0, "unexpected_successes": 0}
        with patch("pkt_tester._run_regressions", return_value=suite), \
                patch("pkt_tester._run_smoke", return_value={"temporary_artifacts_only": True}):
            report = pkt_tester.test_skill()
        self.assertEqual(report["status"], "failed")
        self.assertEqual([item["status"] for item in report["evidence"]], ["failed", "passed", "passed"])

    def test_regression_runner_uses_current_python_and_sanitizes_logs(self):
        summary = {"successful": True, "tests_run": 6, "failures": 0, "errors": 0,
                   "skipped": 0, "expected_failures": 0, "unexpected_successes": 0}
        process = subprocess.CompletedProcess([], 0, stdout=json.dumps(summary), stderr="PRIVATE LOG")
        with patch("pkt_tester.subprocess.run", return_value=process) as run:
            result = pkt_tester._run_regressions()
        self.assertEqual(run.call_args.args[0][:2], [sys.executable, "-B"])
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_empty_regression_suite_cannot_succeed(self):
        summary = {"successful": True, "tests_run": 0, "failures": 0, "errors": 0,
                   "skipped": 0, "expected_failures": 0, "unexpected_successes": 0}
        with patch("pkt_tester.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(summary))):
            self.assertEqual(pkt_tester._run_regressions()["status"], "failed")

    def test_skipped_or_expected_failures_leave_partial_coverage(self):
        for field in ["skipped", "expected_failures"]:
            summary = {"successful": True, "tests_run": 6, "failures": 0, "errors": 0,
                       "skipped": 0, "expected_failures": 0, "unexpected_successes": 0}
            summary[field] = 1
            process = subprocess.CompletedProcess([], 0, stdout=json.dumps(summary))
            with self.subTest(field=field), patch("pkt_tester.subprocess.run", return_value=process):
                result = pkt_tester._run_regressions()
            self.assertEqual(result["status"], "partial")
            with patch("pkt_tester._run_regressions", return_value=result), \
                    patch("pkt_tester._run_smoke", return_value={"temporary_artifacts_only": True}):
                code, report = self.run_main([])
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "partial")

    def test_real_failure_dominates_skipped_coverage(self):
        summary = {"successful": False, "tests_run": 6, "failures": 1, "errors": 0,
                   "skipped": 1, "expected_failures": 0, "unexpected_successes": 0}
        process = subprocess.CompletedProcess([], 1, stdout=json.dumps(summary))
        with patch("pkt_tester.subprocess.run", return_value=process):
            self.assertEqual(pkt_tester._run_regressions()["status"], "failed")

    def test_real_smoke_saves_and_checks_artifacts_in_temp_only(self):
        result = pkt_tester._run_smoke()
        self.assertTrue(result["temporary_artifacts_only"])
        self.assertTrue(result["sources_unchanged"])
        self.assertEqual(result["cloud_path_checks"], 2)
        self.assertEqual(result["vlsm_allocations"], 3)

    def test_pkt_tool_cli_alias_checks_exact_packet_read_only(self):
        before = self.source.read_bytes()
        process = subprocess.run([sys.executable, "-B", str(pkt_tester.SCRIPT_DIR / "pkt_tool.py"), "test", str(self.source),
                                  "--between", "PC1", "PC2"], capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, "Alias file-check command failed")
        report = json.loads(process.stdout)
        self.assertEqual(report["input_path"], str(self.source.resolve()))
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["simulation_tested"])
        self.assertEqual(self.source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
