from copy import deepcopy
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pkt_tool
from pkt_network import physical_ports
from pkt_tester import test_packet


class ProtocolCliTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="protocol-cli-")
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        template = Path(pkt_tool.__file__).resolve().parent.parent / "templates" / "three-node-packet-tracer-5.xml.gz"
        self.root = pkt_tool.parse_xml(gzip.decompress(template.read_bytes()))
        self.source = self.folder / "lab.pkt"
        self.plan = self.folder / "eigrp-plan.json"
        router = self.root.find("NETWORK/DEVICES/DEVICE")
        self.router_port = next(name for name, port in physical_ports(router).items() if port.findtext("IP") == "192.168.10.1")
        self.plan.write_text(json.dumps({"routers": {"R1": {"as": 100, "networks": ["192.168.10.0/24"],
            "interfaces": [{"name": self.router_port, "passive": True}]}}}), encoding="utf-8")
        self.save()

    def save(self):
        self.source.write_bytes(pkt_tool.pack_xml(ET.tostring(self.root, encoding="utf-8")))

    def run_cli(self, *arguments):
        result = subprocess.run([sys.executable, "-B", str(Path(pkt_tool.__file__).resolve()), *map(str, arguments)],
                                text=True, capture_output=True, timeout=45)
        return result.returncode, json.loads(result.stdout) if result.stdout.strip() else None

    def add_dns_server(self):
        devices = self.root.find("NETWORK/DEVICES")
        server = deepcopy(devices[2])
        engine = server.find("ENGINE")
        engine.find("TYPE").text = "Server"
        engine.find("TYPE").set("model", "Server-PT")
        engine.find("NAME").text = "DNS1"
        for tag, value in (("DEV_ADDR", "999001"), ("MEM_ADDR", "999002")):
            server.find("WORKSPACE/LOGICAL/" + tag).text = value
        for index, mac in enumerate(server.findall(".//MACADDRESS")):
            mac.text = "0200.0000." + f"{index + 1:04x}"
        physical_ports(server)["FastEthernet"].find("IP").text = "192.168.10.2"
        for device in (devices[2], server):
            device.find("ENGINE/DNS_CLIENT/SERVER_IP").text = "192.168.10.2"
        dns = ET.SubElement(engine, "DNS_SERVER")
        ET.SubElement(dns, "ENABLED").text = "1"
        self.records = ET.SubElement(dns, "NAMESERVER-DATABASE")
        for kind, name, value, field in (("A-REC", "example.com", "192.168.10.2", "IPADDRESS"),
                                         ("CNAME", "www.example.com", "example.com", "HOSTNAME")):
            record = ET.SubElement(self.records, "RESOURCE-RECORD")
            for tag, text in (("TYPE", kind), ("NAME", name), ("TTL", "86400"), (field, value)):
                ET.SubElement(record, tag).text = text
        ET.SubElement(ET.SubElement(engine, "HTTP_SERVER"), "ENABLED").text = "1"
        devices.append(server)
        links = self.root.find("NETWORK/LINKS")
        link = deepcopy(links[1])
        cable = link.find("CABLE")
        cable.find("TO").text = "3"
        cable.findall("PORT")[0].text = "FastEthernet2/1"
        cable.find("TO_DEVICE_MEM_ADDR").text = "999001"
        links.append(link)
        self.save()

    def test_eigrp_cli_generates_reviewable_commands_without_mutating_source(self):
        before = self.source.read_bytes()
        output = self.folder / "commands.json"
        code, report = self.run_cli("eigrp", self.source, "--plan", self.plan, "--report", output)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "passed")
        self.assertIn("router eigrp 100", report["commands"]["R1"])
        self.assertEqual(json.loads(output.read_text()), report)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse(report["convergence_tested"])
        self.assertFalse(report["packet_mutated"])

    def test_invalid_eigrp_as_is_rejected_before_report_write(self):
        plan = json.loads(self.plan.read_text())
        plan["routers"]["R1"]["as"] = 0
        self.plan.write_text(json.dumps(plan))
        before = self.source.read_bytes()
        output = self.folder / "invalid.json"
        code, _ = self.run_cli("eigrp", self.source, "--plan", self.plan, "--report", output)
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())
        self.assertEqual(self.source.read_bytes(), before)

    def test_protocol_report_cannot_replace_source(self):
        before = self.source.read_bytes()
        code, _ = self.run_cli("eigrp", self.source, "--plan", self.plan, "--report", self.source, "--overwrite")
        self.assertEqual(code, 1)
        self.assertEqual(self.source.read_bytes(), before)

    def test_protocol_report_cannot_replace_plan(self):
        before = self.plan.read_bytes()
        code, _ = self.run_cli("eigrp", self.source, "--plan", self.plan, "--report", self.plan, "--overwrite")
        self.assertEqual(code, 1)
        self.assertEqual(self.plan.read_bytes(), before)

    def test_dns_cli_checks_alias_expected_ip_and_web_state(self):
        self.add_dns_server()
        before = self.source.read_bytes()
        code, report = self.run_cli("audit-dns", self.source, "--expect", "PC1", "WWW.EXAMPLE.COM.", "192.168.10.2",
                                    "--web", "PC1", "example.com", "DNS1")
        self.assertEqual(code, 0)
        self.assertEqual(report["resolutions"][0]["addresses"], ["192.168.10.2"])
        self.assertTrue(report["resolutions"][1]["web_configuration_checked"])
        self.assertFalse(report["queries_executed"])
        self.assertFalse(report["http_rendered"])
        self.assertEqual(self.source.read_bytes(), before)

    def test_dns_cli_wrong_expected_address_fails(self):
        self.add_dns_server()
        code, report = self.run_cli("audit-dns", self.source, "--expect", "PC1", "example.com", "192.168.10.99")
        self.assertEqual(code, 1)
        self.assertIn("dns.query.expected", {issue["code"] for issue in report["errors"]})

    def test_tester_alias_includes_requested_dns_check(self):
        self.add_dns_server()
        code, report = self.run_cli("test", self.source, "--expect", "PC1", "example.com", "192.168.10.2")
        self.assertEqual(code, 0)
        dns = next(item for item in report["evidence"] if item["check"] == "dns_configuration")
        self.assertEqual(dns["status"], "passed")
        self.assertTrue(report["source_unchanged"])
        self.assertFalse(report["simulation_tested"])

    def test_unmodeled_dns_recursion_is_partial_in_cli_and_tester(self):
        self.add_dns_server()
        self.records.findall("RESOURCE-RECORD")[1].find("HOSTNAME").text = "external.example.net"
        self.save()
        code, report = self.run_cli("audit-dns", self.source, "--resolve", "PC1", "www.example.com")
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "partial")
        report = test_packet(self.source, dns_queries=[["PC1", "www.example.com"]])
        self.assertEqual(report["status"], "partial")

    def test_eigrp_preflight_does_not_override_unknown_dynamic_forwarding(self):
        router = self.root.find("NETWORK/DEVICES/DEVICE")
        for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = router.find("ENGINE/" + tag)
            end = next(index for index, node in enumerate(config) if (node.text or "").strip() == "end")
            for offset, line in enumerate(("router eigrp 100", " network 192.168.10.0 0.0.0.255", " no auto-summary", " passive-interface default", "!")):
                node = ET.Element("LINE")
                node.text = line
                config.insert(end + offset, node)
        self.save()
        report = test_packet(self.source)
        self.assertEqual(report["status"], "partial")
        check = next(item for item in report["evidence"] if item["check"] == "eigrp_configuration")
        self.assertEqual(check["status"], "passed")
        self.assertFalse(report["simulation_tested"])


if __name__ == "__main__":
    unittest.main()
