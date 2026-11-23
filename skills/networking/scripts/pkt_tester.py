"""Read-only packet checks or temporary file-only networking skill regression tests."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pkt_tool
from pkt_network import audit, configure, physical_ports
from pkt_plan import plan_ipv4


SCRIPT_DIR = Path(__file__).resolve().parent
EXIT_CODES = {"passed": 0, "failed": 1, "partial": 2}


def _new_report(mode, input_path=None):
    return {
        "schema_version": 1,
        "mode": mode,
        "input_path": str(input_path.resolve()) if input_path is not None else None,
        "status": "failed",
        "summary": "Checks have not finished",
        "counts": {},
        "evidence": [],
        "simulation_tested": False,
        "window_title_tested": False,
        "scope": "Offline file integrity, supported configuration consistency and helper behavior only",
    }


def _add(report, name, status, **details):
    if status not in EXIT_CODES:
        raise ValueError("Invalid tester check status")
    report["evidence"].append({"check": name, "status": status, "details": details})


def _finish(report):
    counts = Counter(entry["status"] for entry in report["evidence"])
    report["counts"].update({
        "checks_total": len(report["evidence"]),
        "checks_passed": counts["passed"],
        "checks_failed": counts["failed"],
        "checks_partial": counts["partial"],
    })
    status = "failed" if counts["failed"] else "partial" if counts["partial"] else "passed"
    report["status"] = status
    prefix = {"passed": "Offline checks passed", "partial": "Offline checks have incomplete coverage",
              "failed": "Offline checks failed"}[status]
    report["summary"] = f"{prefix}: {counts['passed']} passed, {counts['failed']} failed, {counts['partial']} partial. No Packet Tracer simulation ran."
    return report


def _failure(report, name, error):
    # Exception text can contain decrypted labels, credentials or configuration.
    _add(report, name, "failed", error_type=type(error).__name__)


def _issue_counts(entries):
    codes = Counter()
    for entry in entries:
        code = entry.get("code", "unknown")
        codes[code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9.-]*", code) else "unknown"] += 1
    return dict(sorted(codes.items()))


def test_packet(path, between=(), dns_queries=()):
    """Check an actual .pkt read-only; reports exclude decoded text and secrets."""
    source = Path(path).resolve()
    report = _new_report("packet", source)
    before = None
    try:
        before = source.read_bytes()
        report["source_sha256_before"] = hashlib.sha256(before).hexdigest()
        _add(report, "source_read", "passed", packet_bytes=len(before))
    except Exception as error:
        _failure(report, "source_read", error)
    root = None
    if before is not None:
        try:
            packet, xml, root = pkt_tool.load_packet(source)
            if packet != before:
                raise ValueError("Source changed before decoding")
            from pkt_fast_io import encode
            if pkt_tool.decrypt_pkt(encode(xml, "auto", packet)) != xml:
                raise ValueError("Round trip mismatch")
            _add(report, "container_round_trip", "passed", xml_bytes=len(xml), in_memory_only=True)
        except Exception as error:
            _failure(report, "container_round_trip", error)
        if root is not None:
            try:
                inspection = pkt_tool.inspect_packet(source)
                report["counts"]["devices"] = sum(inspection["device_counts"].values())
                report["counts"]["links"] = inspection["link_count"]
                _add(report, "inventory", "passed", devices=report["counts"]["devices"], links=inspection["link_count"])
            except Exception as error:
                _failure(report, "inventory", error)
            try:
                result = audit(root, between)
                paths = result.get("paths", [])
                status = result["status"]
                if result.get("errors") or any(entry.get("status") == "failed" for entry in paths):
                    status = "failed"
                elif any(entry.get("status") != "modeled" for entry in paths):
                    status = "partial"
                if status == "passed" and len(paths) != len(between) * 2:
                    status = "partial"
                report["counts"].update({"audit_errors": len(result.get("errors", [])),
                                         "audit_warnings": len(result.get("warnings", [])), "path_checks": len(paths)})
                _add(report, "network_audit", status,
                     error_codes=_issue_counts(result.get("errors", [])),
                     warning_codes=_issue_counts(result.get("warnings", [])),
                     path_status_counts=dict(Counter(entry.get("status", "unknown") for entry in paths)),
                     requested_host_pairs=len(between), raw_configuration_included=False)
            except Exception as error:
                _failure(report, "network_audit", error)
            eigrp_present = any((node.text or "").strip().startswith("router eigrp ")
                                for node in root.findall("NETWORK/DEVICES/DEVICE/ENGINE/RUNNINGCONFIG/LINE"))
            dns_present = any(node.findtext("ENABLED", "").strip().lower() in {"1", "true"}
                              or node.findall("NAMESERVER-DATABASE/RESOURCE-RECORD")
                              for node in root.findall("NETWORK/DEVICES/DEVICE/ENGINE/DNS_SERVER"))
            for check, present in (("eigrp_configuration", eigrp_present),
                                   ("dns_configuration", dns_present or bool(dns_queries))):
                if not present:
                    continue
                try:
                    if check == "eigrp_configuration":
                        from pkt_eigrp import audit_eigrp
                        result = audit_eigrp(root)
                    else:
                        from pkt_dns import audit_dns
                        result = audit_dns(root, dns_queries)
                    _add(report, check, result["status"],
                         error_codes=_issue_counts(result.get("errors", [])),
                         warning_codes=_issue_counts(result.get("warnings", [])),
                         configuration_only=True, runtime_tested=False)
                except Exception as error:
                    _failure(report, check, error)
        try:
            after = source.read_bytes()
            report["source_sha256_after"] = hashlib.sha256(after).hexdigest()
            report["source_unchanged"] = before == after
            _add(report, "source_unchanged", "passed" if before == after else "failed", sha256_matches=before == after)
        except Exception as error:
            report["source_unchanged"] = False
            _failure(report, "source_unchanged", error)
    return _finish(report)


def _run_regressions():
    # Test tracebacks and buffered output never enter the report: they may contain
    # fixture configuration. Run every installed test in an isolated interpreter.
    runner = """
import contextlib, io, json, sys, unittest
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    suite = unittest.defaultTestLoader.discover(sys.argv[1], pattern='test_*.py')
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
data = {'successful': result.wasSuccessful(), 'tests_run': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
        'unexpected_successes': len(result.unexpectedSuccesses)}
print(json.dumps(data))
sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)
"""
    process = subprocess.run([sys.executable, "-B", "-c", runner, str(SCRIPT_DIR / "tests")],
                             capture_output=True, text=True, timeout=300)
    try:
        result = json.loads(process.stdout)
    except (ValueError, TypeError) as error:
        raise ValueError("Regression runner did not produce a summary") from error
    keys = {"tests_run", "failures", "errors", "skipped", "expected_failures", "unexpected_successes"}
    if not isinstance(result, dict) or not keys <= result.keys() or any(type(result[key]) is not int or result[key] < 0 for key in keys):
        raise ValueError("Regression runner returned invalid counts")
    failed = (process.returncode != 0 or result.get("successful") is not True or not result["tests_run"]
              or result["failures"] or result["errors"] or result["unexpected_successes"])
    result["status"] = "failed" if failed else "partial" if result["skipped"] or result["expected_failures"] else "passed"
    return {key: result[key] for key in sorted(keys | {"status"})}


def _run_smoke():
    """Exercise actual generated and saved artifacts in an automatically removed temp directory."""
    with tempfile.TemporaryDirectory(prefix="networking-tester-") as directory:
        base = Path(directory)
        source, output, plan_path = base / "created.pkt", base / "configured.pkt", base / "plan.json"
        created = pkt_tool.create_packet(SimpleNamespace(output=source, network="192.168.50.0/24",
                                                        router="R1", switch="S1", pc="PC1", overwrite=False))
        if not created["round_trip_verified"]:
            raise AssertionError("Create round trip failed")
        inventory = pkt_tool.inspect_packet(source)
        if inventory["device_counts"] != {"Pc": 1, "Router": 1, "Switch": 1} or inventory["link_count"] != 2:
            raise AssertionError("Generated topology inventory differs")
        _, _, root = pkt_tool.load_packet(source)
        router = next(device for device in root.findall("NETWORK/DEVICES/DEVICE") if device.findtext("ENGINE/TYPE") == "Router")
        ports = [name for name, port in physical_ports(router).items() if port.findtext("IP") == "192.168.50.1"]
        if len(ports) != 1:
            raise AssertionError("Generated router interface is not uniquely identified")
        plan_path.write_text(json.dumps({
            "interfaces": [{"device": "R1", "port": ports[0], "address": "192.168.50.254/24"}],
            "hosts": {"PC1": {"address": "192.168.50.20/24", "gateway": "192.168.50.254"}},
        }), encoding="utf-8")
        original = source.read_bytes()
        args = SimpleNamespace(input=source, output=output, plan=plan_path, dry_run=True, overwrite=False)
        dry_run = configure(args)
        if output.exists() or source.read_bytes() != original or dry_run["network_audit"]["status"] != "passed":
            raise AssertionError("Configure preview changed a file or lacks coverage")
        args.dry_run = False
        configured = configure(args)
        _, _, saved_root = pkt_tool.load_packet(output)
        if source.read_bytes() != original or configured["network_audit"]["status"] != "passed" or audit(saved_root)["status"] != "passed":
            raise AssertionError("Configure saved artifact did not pass")
        devices = saved_root.findall("NETWORK/DEVICES/DEVICE")
        pc = next(device for device in devices if device.findtext("ENGINE/TYPE") == "Pc")
        if pc.findtext("ENGINE/GATEWAY") != "192.168.50.254" or not any(port.findtext("IP") == "192.168.50.20" for port in physical_ports(pc).values()):
            raise AssertionError("Saved PC configuration differs from plan")
        vlsm = plan_ipv4("192.0.2.0/24", ["Office=20", "Branch=8"], ["R1-R2"])
        if [entry["network"] for entry in vlsm["allocations"]] != ["192.0.2.0/27", "192.0.2.32/28", "192.0.2.48/30"] or vlsm["simulation_tested"]:
            raise AssertionError("VLSM smoke plan differs")
        # The bundled two-cloud fixture exercises bidirectional serial and DSL
        # modeling as a separate check from the simple generated LAN.
        cloud_source, cloud_output = base / "cloud-source.pkt", base / "cloud-fixed.pkt"
        xml = gzip.decompress((SCRIPT_DIR / "tests" / "fixtures" / "two-cloud-ipv4.xml.gz").read_bytes())
        cloud_root = pkt_tool.parse_xml(xml)
        cloud = next(device for device in cloud_root.findall("NETWORK/DEVICES/DEVICE") if device.findtext("ENGINE/NAME") == "Cloud2")
        cloud.find("ENGINE/MODEM_CONNECTIONS").clear()
        import xml.etree.ElementTree as ET
        cloud_source.write_bytes(pkt_tool.pack_xml(ET.tostring(cloud_root, encoding="utf-8")))
        plan_path.write_text(json.dumps({"clouds": {"Cloud2": {"dsl": [{"modem": "Modem4", "ethernet": "Ethernet6"}]}},
                                         "tests": [["PC1", "PC2"]]}), encoding="utf-8")
        cloud_before = cloud_source.read_bytes()
        cloud_report = configure(SimpleNamespace(input=cloud_source, output=cloud_output, plan=plan_path, dry_run=False, overwrite=False))
        packet_report = test_packet(cloud_output, [["PC1", "PC2"]])
        if cloud_report["network_audit"]["status"] != "passed" or packet_report["status"] != "passed" or cloud_source.read_bytes() != cloud_before:
            raise AssertionError("Saved cloud repair did not pass both direction checks")
        return {"created_devices": 3, "created_links": 2, "configure_preview_verified": True,
                "saved_configuration_verified": True, "sources_unchanged": True,
                "vlsm_allocations": 3, "cloud_path_checks": packet_report["counts"]["path_checks"],
                "temporary_artifacts_only": True}


def test_skill():
    """Run installed regressions, crypto and realistic temp-only smoke checks."""
    report = _new_report("skill")
    try:
        suite = _run_regressions()
        report["counts"].update({"regression_" + key: value for key, value in suite.items() if key != "status"})
        _add(report, "regression_suite", suite["status"], **{key: value for key, value in suite.items() if key != "status"})
    except Exception as error:
        _failure(report, "regression_suite", error)
    try:
        crypto = pkt_tool.self_test()
        if crypto.get("self_test") != "passed":
            raise AssertionError("Crypto self test failed")
        _add(report, "crypto", "passed", in_memory_only=True)
    except Exception as error:
        _failure(report, "crypto", error)
    try:
        _add(report, "artifact_smoke", "passed", **_run_smoke())
    except Exception as error:
        _failure(report, "artifact_smoke", error)
    return _finish(report)


def _validate_report_path(path, source=None, overwrite=False):
    target = Path(path).resolve()
    if target.suffix.lower() != ".json":
        raise ValueError("Report output must have a .json extension")
    if source is not None:
        original = Path(source).resolve()
        if target == original or (target.exists() and original.exists() and target.samefile(original)):
            raise ValueError("Report must be distinct from the input packet")
    if target.exists() and not overwrite:
        raise FileExistsError("Report already exists; use a new path or explicit --overwrite")
    if target.exists() and not target.is_file():
        raise ValueError("Report target is not a regular file")
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="Actual .pkt to inspect read-only; omit for skill regression checks")
    parser.add_argument("--between", action="append", nargs=2, default=[], metavar=("HOST_A", "HOST_B"))
    parser.add_argument("--resolve", action="append", nargs=2, default=[], metavar=("CLIENT", "DNS_NAME"))
    parser.add_argument("--expect", action="append", nargs=3, default=[], metavar=("CLIENT", "DNS_NAME", "IPV4"))
    parser.add_argument("--web", action="append", nargs=3, default=[], metavar=("CLIENT", "DNS_NAME", "SERVER"))
    parser.add_argument("--report", type=Path, help="Optional distinct JSON report path")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing report only")
    args = parser.parse_args(argv)
    report_path = None
    try:
        if (args.between or args.resolve or args.expect or args.web) and args.input is None:
            raise ValueError("Host pairs and DNS requests require an input packet")
        if args.overwrite and args.report is None:
            raise ValueError("--overwrite applies only to a report path")
        if args.report is not None:
            report_path = _validate_report_path(args.report, args.input, args.overwrite)
    except Exception as error:
        report = _new_report("packet" if args.input is not None else "skill", args.input)
        _failure(report, "arguments", error)
        print(json.dumps(_finish(report), indent=2))
        return 1
    dns_queries = [*args.resolve, *args.expect,
                   *[(client, name, None, server) for client, name, server in args.web]]
    report = test_packet(args.input, args.between, dns_queries) if args.input is not None else test_skill()
    if report_path is not None:
        try:
            # Recheck before writing; no report is ever written to the packet.
            report_path = _validate_report_path(report_path, args.input, args.overwrite)
            pkt_tool.atomic_write(report_path, (json.dumps(report, indent=2) + "\n").encode("utf-8"), overwrite=args.overwrite)
        except Exception as error:
            _failure(report, "report_write", error)
            _finish(report)
    print(json.dumps(report, indent=2))
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
