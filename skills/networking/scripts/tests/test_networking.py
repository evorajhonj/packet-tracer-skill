import gzip
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pkt_tool
from pkt_network import audit, configure, physical_ports

FIXTURE = Path(__file__).parent / "fixtures" / "two-cloud-ipv4.xml.gz"


class NetworkTest(unittest.TestCase):
    def setUp(self):
        self.xml = gzip.decompress(FIXTURE.read_bytes())
        self.root = ET.fromstring(self.xml)
        self.devices = self.root.findall("NETWORK/DEVICES/DEVICE")

    def codes(self):
        return {e["code"] for e in audit(self.root, [["PC1", "PC2"]])["errors"]}

    def run_plan(self, plan, dry=False):
        with tempfile.TemporaryDirectory() as directory:
            source, output, planfile = [Path(directory) / p for p in ["input.pkt", "output.pkt", "plan.json"]]
            source.write_bytes(pkt_tool.pack_xml(self.xml))
            before = source.read_bytes()
            planfile.write_text(json.dumps(plan))
            args = SimpleNamespace(input=source, output=output, plan=planfile, overwrite=False, dry_run=dry)
            try:
                report = configure(args)
            except Exception:
                self.assertFalse(output.exists(), "Invalid plan wrote an artifact")
                self.assertEqual(source.read_bytes(), before)
                raise
            self.assertEqual(source.read_bytes(), before)
            if dry:
                self.assertFalse(output.exists())
                return report, None
            return report, pkt_tool.load_packet(output)[2]

    def test_valid_frame_relay_dsl_path_both_directions(self):
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["errors"])
        self.assertEqual([p["status"] for p in report["paths"]], ["modeled", "modeled"])
        self.assertFalse(report["simulation_tested"])

    def test_missing_cloud_mapping_is_rejected(self):
        self.devices[4].find("ENGINE/MODEM_CONNECTIONS").clear()
        self.assertIn("cloud.unmapped", self.codes())
        self.assertIn("host.gateway", self.codes())

    def test_wrong_provider_is_rejected(self):
        self.devices[4].find("ENGINE/MODEM_CONNECTION_TYPES/CONNECTION_TYPE/DSL").text = "false"
        self.assertIn("cloud.provider", self.codes())

    def test_gateway_must_exist_on_connected_lan(self):
        self.devices[5].find("ENGINE/GATEWAY").text = "192.168.20.99"
        self.assertIn("host.gateway", self.codes())

    def test_broadcast_host_ip_is_rejected(self):
        physical_ports(self.devices[0])["FastEthernet"].find("IP").text = "192.168.10.255"
        self.assertIn("ip.invalid", self.codes())

    def test_duplicate_address_is_rejected(self):
        physical_ports(self.devices[0])["FastEthernet"].find("IP").text = "192.168.10.1"
        self.assertIn("ip.duplicate", self.codes())

    def test_next_hop_must_be_adjacent(self):
        for node in self.devices[1].findall("ENGINE/RUNNINGCONFIG/LINE"):
            if (node.text or "").startswith("ip route "):
                node.text = "ip route 192.168.20.0 255.255.255.0 10.0.0.99"
        self.assertIn("route.next-hop", self.codes())

    def test_missing_return_route_is_rejected(self):
        config = self.devices[3].find("ENGINE/RUNNINGCONFIG")
        for n in list(config):
            if (n.text or "").startswith("ip route "):
                config.remove(n)
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual([p["status"] for p in report["paths"]], ["modeled", "failed"])
        self.assertIn("path.unreachable", self.codes())

    def test_frame_relay_dlci_mismatch_is_rejected(self):
        for n in self.devices[1].findall("ENGINE/RUNNINGCONFIG/LINE"):
            if "frame-relay interface-dlci 304" in (n.text or ""):
                n.text = " frame-relay interface-dlci 305"
        self.assertIn("fr.dlci", self.codes())

    def test_frame_relay_lmi_mismatch_is_rejected(self):
        physical_ports(self.devices[2])["Serial0"].find("LMITYPE").text = "eLmiAnsi"
        self.assertIn("fr.lmi", self.codes())

    def test_missing_frame_relay_mapping_is_rejected(self):
        self.devices[2].find("ENGINE/CONNECTIONS").clear()
        self.assertIn("fr.unmapped", self.codes())

    def test_cloud_plan_restores_a_missing_dsl_mapping(self):
        self.devices[4].find("ENGINE/MODEM_CONNECTIONS").clear()
        self.xml = ET.tostring(self.root, encoding="utf-8")
        report, root = self.run_plan({"clouds": {"Cloud2": {"dsl": [{"modem": "Modem4", "ethernet": "Ethernet6"}]}}, "tests": [["PC1", "PC2"]]})
        self.assertEqual(report["network_audit"]["status"], "passed")
        self.assertEqual([p["status"] for p in report["network_audit"]["paths"]], ["modeled", "modeled"])

    def test_zero_dce_clock_is_rejected(self):
        physical_ports(self.devices[2])["Serial0"].find("CLOCKRATE").text = "0"
        self.assertIn("serial.clock", self.codes())

    def test_connected_shutdown_interface_is_rejected(self):
        physical_ports(self.devices[3])["FastEthernet1/0"].find("POWER").text = "false"
        self.assertIn("link.shutdown", self.codes())

    def test_copper_pin_roles_require_correct_cable(self):
        self.root.find("NETWORK/LINKS/LINK/CABLE/TYPE").text = "eStraightThrough"
        self.assertIn("link.copper", self.codes())

    def test_xml_and_router_config_must_agree(self):
        physical_ports(self.devices[1])["FastEthernet0/0"].find("IP").text = "192.168.10.2"
        self.assertIn("interface.state", self.codes())

    def test_unsupported_wireless_is_not_reported_as_fully_checked(self):
        config = self.devices[1].find("ENGINE/RUNNINGCONFIG")
        ET.SubElement(config, "LINE").text = "router ospf 1"
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["simulation_tested"])

    def test_configure_readdresses_both_lans_and_routes(self):
        plan = {
            "interfaces": [
                {"device": "R1", "port": "FastEthernet0/0", "address": "192.168.30.1/24"},
                {"device": "R2", "port": "FastEthernet1/0", "address": "192.168.40.1/24"},
            ],
            "hosts": {
                "PC1": {"address": "192.168.30.10/24", "gateway": "192.168.30.1"},
                "PC2": {"address": "192.168.40.10/24", "gateway": "192.168.40.1"},
            },
            "routes": {
                "R1": [{"network": "192.168.40.0/24", "next_hop": "10.0.0.2"}],
                "R2": [{"network": "192.168.30.0/24", "next_hop": "10.0.0.1"}],
            },
            "tests": [["PC1", "PC2"]],
        }
        report, root = self.run_plan(plan)
        self.assertEqual(report["network_audit"]["status"], "passed")
        self.assertEqual([p["status"] for p in report["network_audit"]["paths"]], ["modeled", "modeled"])
        self.assertTrue(report["round_trip_verified"])
        new = root.findall("NETWORK/DEVICES/DEVICE")
        self.assertEqual(new[0].findtext("ENGINE/GATEWAY"), "192.168.30.1")
        self.assertEqual(physical_ports(new[3])["FastEthernet1/0"].findtext("IP"), "192.168.40.1")
        for i in [2, 4, 6]:
            self.assertEqual(ET.tostring(new[i]), ET.tostring(self.devices[i]))
        self.assertEqual(ET.tostring(root.find("NETWORK/LINKS")), ET.tostring(self.root.find("NETWORK/LINKS")))

    def test_invalid_gateway_never_writes_output(self):
        with self.assertRaises(ValueError):
            self.run_plan({"hosts": {"PC1": {"address": "192.168.10.10/24", "gateway": "192.168.20.1"}}})

    def test_unknown_interface_never_writes_output(self):
        with self.assertRaises(ValueError):
            self.run_plan({"interfaces": [{"device": "R1", "port": "GigabitEthernet9/9", "address": "10.2.0.1/30"}]})

    def test_clock_on_dte_never_writes_output(self):
        with self.assertRaises(ValueError):
            self.run_plan({"clocks": [{"device": "R1", "port": "Serial2/0", "rate": 64000}], "tests": [["PC1", "PC2"]]})

    def test_only_target_dce_clock_changes(self):
        report, root = self.run_plan({"clocks": [{"device": "Cloud1", "port": "Serial0", "rate": 56000}], "tests": [["PC1", "PC2"]]})
        cloud = root.findall("NETWORK/DEVICES/DEVICE")[2]
        self.assertEqual(physical_ports(cloud)["Serial0"].findtext("CLOCKRATE"), "56000")
        self.assertEqual(physical_ports(cloud)["Serial1"].findtext("CLOCKRATE"), "64000")
        self.assertEqual(report["network_audit"]["status"], "passed")

    def test_dry_run_does_not_write(self):
        report, root = self.run_plan({"hosts": {"PC1": {"address": "192.168.10.11/24", "gateway": "192.168.10.1"}}, "tests": [["PC1", "PC2"]]}, dry=True)
        self.assertTrue(report["dry_run"])
        self.assertIsNone(root)

    def test_plan_without_return_route_is_not_saved(self):
        with self.assertRaises(ValueError):
            self.run_plan({"routes": {"R2": []}, "tests": [["PC1", "PC2"]]})

    def test_multi_subnet_configuration_requires_path_tests(self):
        with self.assertRaises(ValueError):
            self.run_plan({"hosts": {"PC1": {"address": "192.168.10.11/24", "gateway": "192.168.10.1"}}})

    def test_legacy_sample_decode_roundtrip(self):
        legacy = pkt_tool.obfuscate_stage2(pkt_tool.compress_qt(self.xml))
        self.assertEqual(pkt_tool.decrypt_pkt(legacy), self.xml)
        self.assertEqual(pkt_tool.decrypt_pkt(pkt_tool.pack_xml(self.xml)), self.xml)

    def test_empty_xml_is_not_a_network(self):
        self.assertEqual(audit(ET.fromstring("<PACKETTRACER5/>"))["status"], "failed")

    def test_configure_uses_actual_router_name_r3(self):
        self.devices[3].find("ENGINE/NAME").text = "R3"
        self.xml = ET.tostring(self.root, encoding="utf-8")
        report, root = self.run_plan({"interfaces": [{"device": "R3", "port": "FastEthernet1/0", "address": "192.168.20.1/24"}], "tests": [["PC1", "PC2"]]})
        self.assertEqual(report["network_audit"]["status"], "passed")
        self.assertIn("R3", report["network_audit"]["paths"][0]["routers_and_hosts"])

    def test_supported_cable_mapping_path(self):
        cloud = self.devices[4]
        physical_ports(cloud)["Modem4"].find("POWER").text = "false"
        physical_ports(cloud)["Coaxial7"].find("POWER").text = "true"
        cloud.find("ENGINE/MODEM_CONNECTION_TYPES/CONNECTION_TYPE/DSL").text = "false"
        cloud.find("ENGINE/MODEM_CONNECTIONS/CONNECTION/PORT1").text = "Coaxial7"
        modem = self.devices[6]
        modem.find("ENGINE/TYPE").text = "CableModem"
        physical_ports(modem)["Port 0"].find("TYPE").text = "eCopperCoaxial"
        link = self.root.findall("NETWORK/LINKS/LINK")[4]
        link.find("TYPE").text = "eCoaxial"
        link.find("CABLE/PORT").text = "Coaxial7"
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "passed")
        self.assertEqual([p["status"] for p in report["paths"]], ["modeled", "modeled"])

    def test_connected_router_port_requires_ip(self):
        config = self.devices[1].find("ENGINE/RUNNINGCONFIG")
        for n in list(config):
            if "ip address 192.168.10.1" in (n.text or ""):
                config.remove(n)
        self.assertIn("interface.address", self.codes())

    def route_lines(self, device, line):
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            container = self.devices[device].find("ENGINE/" + tag)
            for node in list(container):
                if (node.text or "").strip().startswith("ip route "):
                    container.remove(node)
            for command in line:
                ET.SubElement(container, "LINE").text = command

    def test_disabled_routing_blocks_transit(self):
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            ET.SubElement(self.devices[1].find("ENGINE/" + tag), "LINE").text = "no ip routing"
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "failed")
        self.assertEqual([p["status"] for p in report["paths"]], ["failed", "failed"])
        self.assertIn("router.routing-disabled", self.codes())

    def test_ad255_route_does_not_forward(self):
        self.route_lines(1, ["ip route 192.168.20.0 255.255.255.0 10.0.0.2 255"])
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["paths"][0]["status"], "failed")
        route = next(r for r in report["routes"] if r["device"] == "R1")
        self.assertFalse(route["distance_usable"])

    def test_lower_ad_is_selected_within_same_prefix(self):
        self.route_lines(1, [
            "ip route 192.168.20.0 255.255.255.0 192.168.10.10 200",
            "ip route 192.168.20.0 255.255.255.0 10.0.0.2 1",
        ])
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["paths"][0]["routers_and_hosts"], ["PC1", "R1", "R2", "PC2"])

    def test_longer_prefix_wins_over_lower_ad_default_route(self):
        self.route_lines(1, [
            "ip route 0.0.0.0 0.0.0.0 192.168.10.10 1",
            "ip route 192.168.20.0 255.255.255.0 10.0.0.2 200",
        ])
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["paths"][0]["status"], "modeled")

    def test_unknown_route_options_are_not_silently_activated(self):
        self.route_lines(1, ["ip route 192.168.20.0 255.255.255.0 10.0.0.2 track 1"])
        report = audit(self.root, [["PC1", "PC2"]])
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["paths"][0]["status"], "unknown")

    def test_missing_startup_route_is_partial_and_not_saved(self):
        container = self.devices[1].find("ENGINE/STARTUPCONFIG")
        for n in list(container):
            if (n.text or "").strip().startswith("ip route "):
                container.remove(n)
        self.assertEqual(audit(self.root)["status"], "partial")
        self.xml = ET.tostring(self.root, encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_plan({"hosts": {"PC1": {"address": "192.168.10.11/24", "gateway": "192.168.10.1"}}, "tests": [["PC1", "PC2"]]})

    def test_shut_down_switch_port_is_not_bridged(self):
        template = Path(__file__).resolve().parents[2] / "templates/three-node-packet-tracer-5.xml.gz"
        root = ET.fromstring(gzip.decompress(template.read_bytes()))
        switch = root.findall("NETWORK/DEVICES/DEVICE")[1]
        config = switch.find("ENGINE/RUNNINGCONFIG")
        for command in ["interface FastEthernet0/1", " shutdown", "!"]:
            ET.SubElement(config, "LINE").text = command
        report = audit(root)
        self.assertEqual(report["status"], "failed")
        self.assertIn("link.shutdown", {e["code"] for e in report["errors"]})

    def test_invalid_address_ranges_are_rejected(self):
        from pkt_network import address
        for value, mask in [("127.0.0.10", "255.255.255.0"), ("0.1.2.10", "255.255.255.0"), ("255.255.255.255", "255.255.255.255")]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                address(value, mask)

    def test_create_rejects_loopback_network_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "invalid.pkt"
            args = SimpleNamespace(network="127.0.0.0/24", router="R1", switch="S1", pc="PC1", output=out, overwrite=False)
            with self.assertRaises(ValueError):
                pkt_tool.create_packet(args)
            self.assertFalse(out.exists())

    def test_host_special_prefix_requires_supported_context(self):
        host = physical_ports(self.devices[0])["FastEthernet"]
        host.find("IP").text = "192.168.10.10"
        host.find("SUBNET").text = "255.255.255.254"
        self.assertIn("ip.host-prefix", self.codes())

    def test_explicit_route_distance_is_saved_in_both_configs(self):
        report, root = self.run_plan({"routes": {"R1": [{"network": "192.168.20.0/24", "next_hop": "10.0.0.2", "distance": 10}]}, "tests": [["PC1", "PC2"]]})
        self.assertEqual(report["network_audit"]["status"], "passed")
        router = root.findall("NETWORK/DEVICES/DEVICE")[1]
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            self.assertIn("ip route 192.168.20.0 255.255.255.0 10.0.0.2 10", [n.text for n in router.findall("ENGINE/" + tag + "/LINE")])


if __name__ == "__main__":
    unittest.main()
