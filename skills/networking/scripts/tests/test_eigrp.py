import copy
import gzip
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pkt_eigrp import audit_eigrp, plan_eigrp
from pkt_network import physical_ports


FIXTURE = Path(__file__).parent / "fixtures" / "two-cloud-ipv4.xml.gz"


class EigrpTest(unittest.TestCase):
    def setUp(self):
        original = ET.fromstring(gzip.decompress(FIXTURE.read_bytes()))
        originals = original.findall("NETWORK/DEVICES/DEVICE")
        self.root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
        self.devices = [copy.deepcopy(originals[1]), copy.deepcopy(originals[3])]
        assignments = [
            {"FastEthernet0/0": "192.0.2.1/24", "FastEthernet1/0": "10.0.0.1/30"},
            {"FastEthernet0/0": "10.0.0.2/30", "FastEthernet1/0": "198.51.100.1/24"},
        ]
        import ipaddress as ip
        for index, (device, ports) in enumerate(zip(self.devices, assignments)):
            device.find("ENGINE/NAME").text = "R" + str(index + 1)
            device.find("ENGINE/POWER").text = "true"
            for name, value in ports.items():
                addr = ip.IPv4Interface(value)
                physical = physical_ports(device)[name]
                physical.find("IP").text = str(addr.ip)
                physical.find("SUBNET").text = str(addr.network.netmask)
                physical.find("POWER").text = "true"
            for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
                config = device.find("ENGINE/" + tag)
                config.clear()
                for name, value in ports.items():
                    addr = ip.IPv4Interface(value)
                    for line in ["interface " + name, f" ip address {addr.ip} {addr.network.netmask}", " no shutdown", "!"]:
                        ET.SubElement(config, "LINE").text = line
                ET.SubElement(config, "LINE").text = "ip route 203.0.113.0 255.255.255.0 10.0.0.2"
                ET.SubElement(config, "LINE").text = "end"
            self.root.find("NETWORK/DEVICES").append(device)
        link = ET.SubElement(self.root.find("NETWORK/LINKS"), "LINK")
        ET.SubElement(link, "TYPE").text = "eCopper"
        cable = ET.SubElement(link, "CABLE")
        for tag, value in [("FROM", "0"), ("TO", "1"),
                           ("FROM_DEVICE_MEM_ADDR", self.devices[0].findtext("WORKSPACE/LOGICAL/DEV_ADDR")),
                           ("TO_DEVICE_MEM_ADDR", self.devices[1].findtext("WORKSPACE/LOGICAL/DEV_ADDR")),
                           ("PORT", "FastEthernet1/0"), ("PORT", "FastEthernet0/0"), ("TYPE", "eCrossOver")]:
            ET.SubElement(cable, tag).text = value
        self.plan = {"routers": {
            "R1": {"as": 100, "networks": ["192.0.2.0/24", {"address": "10.0.0.0", "wildcard": "0.0.0.3"}],
                   "interfaces": [{"name": "FastEthernet0/0", "passive": True}, {"name": "FastEthernet1/0", "passive": False}]},
            "R2": {"as": 100, "networks": ["10.0.0.0/30", "198.51.100.0/24"],
                   "interfaces": [{"name": "FastEthernet0/0", "passive": False}, {"name": "FastEthernet1/0", "passive": True}]},
        }}

    def add_process(self, index, asn=100, body=None, tags=("RUNNINGCONFIG", "STARTUPCONFIG")):
        if body is None:
            body = (["network 10.0.0.0 0.0.0.3", "network 192.0.2.0 0.0.0.255", "no auto-summary",
                     "passive-interface default", "no passive-interface FastEthernet1/0"] if index == 0 else
                    ["network 10.0.0.0 0.0.0.3", "network 198.51.100.0 0.0.0.255", "no auto-summary",
                     "passive-interface default", "no passive-interface FastEthernet0/0"])
        for tag in tags:
            config = self.devices[index].find("ENGINE/" + tag)
            end = len(config) - 1
            for offset, line in enumerate([f"router eigrp {asn}"] + [" " + line for line in body] + ["!"]):
                node = ET.Element("LINE")
                node.text = line
                config.insert(end + offset, node)

    def codes(self, report, warnings=False):
        return {entry["code"] for entry in report["warnings" if warnings else "errors"]}

    def serial_transit(self, encapsulation=None):
        for index, name in enumerate(["FastEthernet1/0", "FastEthernet0/0"]):
            old, serial = physical_ports(self.devices[index])[name], physical_ports(self.devices[index])["Serial2/0"]
            for field in ["IP", "SUBNET"]:
                serial.find(field).text = old.findtext(field)
                old.find(field).text = "0.0.0.0"
            old.find("POWER").text = "false"
            serial.find("POWER").text = "true"
            serial.find("CLOCKRATE").text = "64000" if index == 0 else "0"
            for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
                config = self.devices[index].find("ENGINE/" + tag)
                for position, node in enumerate(list(config)):
                    if node.text == "interface " + name:
                        node.text = "interface Serial2/0"
                        if encapsulation:
                            extra = ET.Element("LINE")
                            extra.text = " encapsulation " + encapsulation
                            config.insert(position + 1, extra)
                        break
            for interface in self.plan["routers"]["R" + str(index + 1)]["interfaces"]:
                if interface["name"] == name:
                    interface["name"] = "Serial2/0"
        link = self.root.find("NETWORK/LINKS/LINK")
        link.find("TYPE").text = "eSerial"
        cable = link.find("CABLE")
        for node in cable.findall("PORT"):
            node.text = "Serial2/0"
        cable.find("TYPE").text = "eDCE"
        ET.SubElement(cable, "DCEDEV").text = "0"
        ET.SubElement(cable, "DCEPORT").text = "Serial2/0"
        return cable

    def assert_rejected_link(self, report, code):
        self.assertEqual(report["status"], "failed")
        self.assertIn(code, self.codes(report))
        self.assertEqual(report["commands"], {})
        self.assertFalse(any(item["supported_link_path_found"] for item in report["neighbor_expectations"]))
        self.assertFalse(report["simulation_tested"])
        self.assertFalse(report["convergence_tested"])

    def test_plan_outputs_complete_classic_cli_without_mutation(self):
        before = ET.tostring(self.root)
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(ET.tostring(self.root), before)
        self.assertEqual(set(report["commands"]), {"R1", "R2"})
        self.assertIn("router eigrp 100", report["commands"]["R1"])
        self.assertIn("network 10.0.0.0 0.0.0.3", report["commands"]["R1"])
        self.assertIn("passive-interface default", report["commands"]["R1"])
        self.assertIn("no passive-interface FastEthernet1/0", report["commands"]["R1"])
        self.assertEqual(report["commands"]["R1"][-1], "copy running-config startup-config")
        self.assertIn("show ip eigrp neighbors", report["verification_commands"]["R1"])
        self.assertFalse(report["packet_mutated"])
        self.assertFalse(report["simulation_tested"])
        self.assertFalse(report["convergence_tested"])
        self.assertFalse(report["learned_routes_modeled"])
        self.assertTrue(report["neighbor_expectations"][0]["supported_link_path_found"])
        self.assertFalse(report["neighbor_expectations"][0]["neighbor_established"])
        self.assertFalse(any("ip route" in command for commands in report["commands"].values() for command in commands))

    def test_as_range_and_integer_type(self):
        for value in [0, -1, 65536, True, "100", 1.0]:
            plan = copy.deepcopy(self.plan)
            plan["routers"]["R1"]["as"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                plan_eigrp(self.root, plan)
        for value in [1, 65535]:
            plan = copy.deepcopy(self.plan)
            for entry in plan["routers"].values():
                entry["as"] = value
            self.assertEqual(plan_eigrp(self.root, plan)["status"], "passed")

    def test_invalid_and_noncontiguous_wildcard(self):
        for value in ["0.0.255.0", "bad", "256.0.0.0", "255.255.255.0"]:
            plan = copy.deepcopy(self.plan)
            plan["routers"]["R1"]["networks"][1]["wildcard"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                plan_eigrp(self.root, plan)

    def test_host_wildcard_selects_actual_interface(self):
        self.plan["routers"]["R1"]["networks"][1] = {"address": "10.0.0.1", "wildcard": "0.0.0.0"}
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "passed")
        self.assertIn("network 10.0.0.1 0.0.0.0", report["commands"]["R1"])

    def test_unknown_model_port_or_undeclared_selection_cannot_be_invented(self):
        for mutate in [lambda plan: plan["routers"]["R1"]["interfaces"][0].update(name="GigabitEthernet0/0"),
                       lambda plan: plan["routers"]["R1"]["interfaces"].pop(0),
                       lambda plan: plan["routers"]["R1"]["networks"].append("203.0.113.0/24")]:
            plan = copy.deepcopy(self.plan)
            mutate(plan)
            with self.assertRaises(ValueError):
                plan_eigrp(self.root, plan)

    def test_duplicate_declarations_and_networks(self):
        for field in ["interfaces", "networks"]:
            plan = copy.deepcopy(self.plan)
            plan["routers"]["R1"][field].append(copy.deepcopy(plan["routers"]["R1"][field][0]))
            with self.subTest(field=field), self.assertRaises(ValueError):
                plan_eigrp(self.root, plan)

    def test_linked_transit_as_k_and_passive_mistakes_are_failed(self):
        for field, value, code in [("as", 200, "eigrp.peer-as"), ("k_values", [2, 0, 1, 0, 0], "eigrp.peer-k")]:
            plan = copy.deepcopy(self.plan)
            plan["routers"]["R2"][field] = value
            report = plan_eigrp(self.root, plan)
            self.assertEqual(report["status"], "failed")
            self.assertIn(code, self.codes(report))
            self.assertEqual(report["commands"], {})
        self.plan["routers"]["R2"]["interfaces"][0]["passive"] = True
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "failed")
        self.assertIn("eigrp.passive-transit", self.codes(report))

    def test_disconnected_same_subnet_is_only_a_potential_peer(self):
        self.root.find("NETWORK/LINKS").clear()
        self.plan["routers"]["R2"]["as"] = 200
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["errors"])
        self.assertEqual(report["neighbor_expectations"][0]["status"], "potential_unverified")
        self.assertFalse(report["neighbor_expectations"][0]["supported_link_path_found"])

    def test_disabled_selected_interface_is_rejected(self):
        physical_ports(self.devices[0])["FastEthernet1/0"].find("POWER").text = "false"
        with self.assertRaisesRegex(ValueError, "disabled"):
            plan_eigrp(self.root, self.plan)

    def test_global_no_ip_routing_fails_preflight_without_commands(self):
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            config = self.devices[0].find("ENGINE/" + tag)
            node = ET.Element("LINE")
            node.text = "no ip routing"
            config.insert(0, node)
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "failed")
        self.assertIn("eigrp.ip-routing-disabled", self.codes(report))
        self.assertEqual(report["commands"], {})

    def test_running_shutdown_prevents_supported_router_link(self):
        self.add_process(0)
        self.add_process(1)
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            config = self.devices[0].find("ENGINE/" + tag)
            for position, node in enumerate(list(config)):
                if node.text == "interface FastEthernet1/0":
                    shutdown = ET.Element("LINE")
                    shutdown.text = " shutdown"
                    config.insert(position + 1, shutdown)
                    break
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "failed")
        self.assertIn("eigrp.interface-disabled", self.codes(report))
        self.assertFalse(any(item["supported_link_path_found"] for item in report["neighbor_expectations"]))

    def test_untagged_switch_bridge_honors_running_shutdown(self):
        template = ET.fromstring(gzip.decompress((Path(__file__).resolve().parents[2] / "templates" / "three-node-packet-tracer-5.xml.gz").read_bytes()))
        switch = copy.deepcopy(next(device for device in template.findall("NETWORK/DEVICES/DEVICE") if device.findtext("ENGINE/TYPE") == "Switch"))
        switch.find("ENGINE/NAME").text = "S1"
        switch.find("ENGINE/POWER").text = "true"
        port_names = list(physical_ports(switch))[:2]
        for port in physical_ports(switch).values():
            port.find("POWER").text = "true"
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            config = switch.find("ENGINE/" + tag)
            config.clear()
            for name in port_names:
                for line in ["interface " + name, " no shutdown", "!"]:
                    ET.SubElement(config, "LINE").text = line
        self.root.find("NETWORK/DEVICES").append(switch)
        links = self.root.find("NETWORK/LINKS")
        links.clear()
        all_devices = self.root.findall("NETWORK/DEVICES/DEVICE")
        for a, b, pa, pb in [(0, 2, "FastEthernet1/0", port_names[0]), (2, 1, port_names[1], "FastEthernet0/0")]:
            link = ET.SubElement(links, "LINK")
            ET.SubElement(link, "TYPE").text = "eCopper"
            cable = ET.SubElement(link, "CABLE")
            for tag, value in [("FROM", str(a)), ("TO", str(b)),
                               ("FROM_DEVICE_MEM_ADDR", all_devices[a].findtext("WORKSPACE/LOGICAL/DEV_ADDR")),
                               ("TO_DEVICE_MEM_ADDR", all_devices[b].findtext("WORKSPACE/LOGICAL/DEV_ADDR")),
                               ("PORT", pa), ("PORT", pb), ("TYPE", "eStraightThrough")]:
                ET.SubElement(cable, tag).text = value
        self.assertEqual(plan_eigrp(self.root, self.plan)["status"], "passed")
        config = switch.find("ENGINE/RUNNINGCONFIG")
        for index, node in enumerate(list(config)):
            if node.text == "interface " + port_names[1]:
                shutdown = ET.Element("LINE")
                shutdown.text = " shutdown"
                config.insert(index + 1, shutdown)
                break
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(any(item["supported_link_path_found"] for item in report["neighbor_expectations"]))

    def test_unsupported_copper_cable_type_is_partial(self):
        self.root.find("NETWORK/LINKS/LINK/CABLE/TYPE").text = "eUnknown"
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "partial")
        self.assertIn("eigrp.unsupported-media", self.codes(report, warnings=True))

    def test_missing_or_stale_cable_identity_cannot_support_adjacency(self):
        for tag, value in [("FROM_DEVICE_MEM_ADDR", None), ("TO_DEVICE_MEM_ADDR", "stale")]:
            with self.subTest(tag=tag):
                self.setUp()
                cable = self.root.find("NETWORK/LINKS/LINK/CABLE")
                if value is None:
                    cable.remove(cable.find(tag))
                else:
                    cable.find(tag).text = value
                before = ET.tostring(self.root)
                self.assert_rejected_link(plan_eigrp(self.root, self.plan), "eigrp.link-identity")
                self.assertEqual(ET.tostring(self.root), before)

    def test_wrong_known_copper_type_is_failed_for_actual_pin_roles(self):
        self.root.find("NETWORK/LINKS/LINK/CABLE/TYPE").text = "eStraightThrough"
        self.assert_rejected_link(plan_eigrp(self.root, self.plan), "eigrp.link-copper")

    def test_duplicate_cable_endpoint_does_not_leave_first_link_supported(self):
        links = self.root.find("NETWORK/LINKS")
        links.append(copy.deepcopy(links.find("LINK")))
        self.assert_rejected_link(plan_eigrp(self.root, self.plan), "eigrp.link-occupied")

    def test_serial_hdlc_and_ppp_candidates_require_valid_saved_clocking(self):
        for encapsulation in [None, "ppp"]:
            with self.subTest(encapsulation=encapsulation):
                self.setUp()
                self.serial_transit(encapsulation)
                before = ET.tostring(self.root)
                report = plan_eigrp(self.root, self.plan)
                self.assertEqual(report["status"], "passed")
                self.assertTrue(report["neighbor_expectations"][0]["supported_link_path_found"])
                self.assertFalse(report["neighbor_expectations"][0]["neighbor_established"])
                self.assertFalse(report["simulation_tested"])
                self.assertEqual(ET.tostring(self.root), before)

    def test_serial_missing_or_wrong_dce_endpoint_is_failed(self):
        for tag, value in [("DCEDEV", None), ("DCEDEV", "3"), ("DCEPORT", "FastEthernet0/0")]:
            with self.subTest(tag=tag, value=value):
                self.setUp()
                cable = self.serial_transit()
                if value is None:
                    cable.remove(cable.find(tag))
                else:
                    cable.find(tag).text = value
                self.assert_rejected_link(plan_eigrp(self.root, self.plan), "eigrp.serial-dce")

    def test_serial_missing_or_invalid_dce_clock_is_failed(self):
        for value in [None, "0", "-1", "bad"]:
            with self.subTest(value=value):
                self.setUp()
                self.serial_transit()
                port = physical_ports(self.devices[0])["Serial2/0"]
                if value is None:
                    port.remove(port.find("CLOCKRATE"))
                else:
                    port.find("CLOCKRATE").text = value
                self.assert_rejected_link(plan_eigrp(self.root, self.plan), "eigrp.serial-clock")

    def test_serial_encapsulation_mismatch_is_failed(self):
        self.serial_transit()
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            config = self.devices[0].find("ENGINE/" + tag)
            for position, node in enumerate(list(config)):
                if node.text == "interface Serial2/0":
                    extra = ET.Element("LINE")
                    extra.text = " encapsulation ppp"
                    config.insert(position + 1, extra)
                    break
        self.assert_rejected_link(plan_eigrp(self.root, self.plan), "eigrp.serial-encapsulation")

    def test_other_existing_as_leaves_migration_coverage_partial(self):
        self.add_process(0, asn=200)
        report = plan_eigrp(self.root, self.plan)
        self.assertEqual(report["status"], "partial")
        self.assertIn("eigrp.multiple-processes", self.codes(report, warnings=True))

    def test_existing_target_process_requires_explicit_replacement(self):
        self.add_process(0)
        before = ET.tostring(self.root)
        with self.assertRaisesRegex(ValueError, "replace_process"):
            plan_eigrp(self.root, self.plan)
        self.plan["routers"]["R1"]["replace_process"] = True
        report = plan_eigrp(self.root, self.plan)
        self.assertIn("no router eigrp 100", report["commands"]["R1"])
        self.assertEqual(ET.tostring(self.root), before)

    def test_invalid_k_values_and_passive_flag(self):
        for value in [[1, 0, 1], [1, 0, 1, 0, 256], [True, 0, 1, 0, 0]]:
            plan = copy.deepcopy(self.plan)
            plan["routers"]["R1"]["k_values"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                plan_eigrp(self.root, plan)
        self.plan["routers"]["R1"]["interfaces"][0]["passive"] = "true"
        with self.assertRaises(ValueError):
            plan_eigrp(self.root, self.plan)

    def test_audit_classic_configuration_and_saved_consistency(self):
        self.add_process(0)
        self.add_process(1)
        before = ET.tostring(self.root)
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(ET.tostring(self.root), before)
        self.assertEqual(report["routers"]["R1"][0]["k_values"], [1, 0, 1, 0, 0])
        self.assertFalse(report["convergence_tested"])
        self.assertEqual(len(report["neighbor_expectations"]), 1)

    def test_running_startup_eigrp_drift_is_partial(self):
        self.add_process(0, tags=("RUNNINGCONFIG",))
        self.add_process(1)
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "partial")
        self.assertIn("eigrp.startup", self.codes(report, warnings=True))

    def test_audit_classful_network_selection(self):
        self.add_process(0, body=["network 10.0.0.0", "network 192.0.2.0", "no auto-summary", "passive-interface FastEthernet0/0"])
        self.add_process(1)
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["routers"]["R1"][0]["memberships"]), 2)

    def test_saved_noncontiguous_wildcard_is_unsupported_not_invalid(self):
        self.add_process(0, body=["network 10.0.0.0 0.0.255.0", "no auto-summary"])
        self.add_process(1)
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["errors"])
        self.assertIn("eigrp.unsupported-selection", self.codes(report, warnings=True))

    def test_audit_as_and_k_errors(self):
        self.add_process(0)
        self.add_process(1, asn=200)
        report = audit_eigrp(self.root)
        self.assertIn("eigrp.peer-as", self.codes(report))
        self.assertEqual(report["status"], "failed")

    def test_audit_passive_transit_is_failed(self):
        self.add_process(0)
        self.add_process(1, body=["network 10.0.0.0 0.0.0.3", "no auto-summary", "passive-interface default"])
        report = audit_eigrp(self.root)
        self.assertIn("eigrp.passive-transit", self.codes(report))

    def test_named_mode_redistribution_and_auto_summary_are_partial(self):
        for asn, body in [("FABRIC", ["address-family ipv4 autonomous-system 100"]),
                          (100, ["network 10.0.0.0 0.0.0.3", "no auto-summary", "redistribute static"]),
                          (100, ["network 10.0.0.0 0.0.0.3", "auto-summary"])]:
            with self.subTest(asn=asn, body=body):
                self.setUp()
                self.add_process(0, asn=asn, body=body)
                self.add_process(1)
                report = audit_eigrp(self.root)
                self.assertEqual(report["status"], "partial")
                self.assertFalse(report["simulation_tested"])

    def test_multiple_process_audit_is_partial_without_cross_as_false_failure(self):
        self.add_process(0)
        self.add_process(0, asn=200)
        self.add_process(1)
        self.add_process(1, asn=200)
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["errors"])
        self.assertIn("eigrp.multiple-processes", self.codes(report, warnings=True))

    def test_invalid_saved_process_and_unknown_passive_are_failed(self):
        self.add_process(0, asn=65536)
        self.assertIn("eigrp.as", self.codes(audit_eigrp(self.root)))
        self.setUp()
        self.add_process(0, body=["network 10.0.0.0 0.0.0.3", "no auto-summary", "passive-interface GigabitEthernet9/0"])
        self.add_process(1)
        self.assertIn("eigrp.passive-interface", self.codes(audit_eigrp(self.root)))

    def test_unsupported_model_remains_partial_in_audit(self):
        self.add_process(0)
        self.add_process(1)
        self.devices[0].find("ENGINE/TYPE").set("model", "1841")
        report = audit_eigrp(self.root)
        self.assertEqual(report["status"], "partial")
        self.assertIn("eigrp.unsupported-model", self.codes(report, warnings=True))


if __name__ == "__main__":
    unittest.main()
