"""Direct-file behavior and failure controls; no desktop automation."""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pkt_tool
from pkt_build import build, build_root
from pkt_build_schema import TEMPLATE
from pkt_fast_io import is_legacy
from pkt_network import physical_ports
from pkt_rewrite import rewrite, transform

CHAIN = TEMPLATE.parent / "copper-chain.json"


class FastBuildTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads(CHAIN.read_text())

    def root(self):
        return build_root(self.plan)[0]

    def test_actual_four_device_chain_and_both_paths(self):
        root, report = build_root(self.plan)
        self.assertEqual(len(root.findall("NETWORK/DEVICES/DEVICE")), 4)
        self.assertEqual(len(root.findall("NETWORK/LINKS/LINK")), 3)
        self.assertEqual([path["status"] for path in report["paths"]], ["modeled", "modeled"])

    def test_unique_mac_and_chassis_identities(self):
        root = self.root()
        macs = [node.text for node in root.findall(".//PORT/MACADDRESS")]
        chassis = [node.text for node in root.findall("NETWORK/DEVICES/DEVICE/ENGINE/BUILD_IN_ADDR")]
        self.assertEqual(len(macs), len(set(macs)))
        self.assertEqual(len(chassis), len(set(chassis)))

    def test_unused_router_ports_shutdown_and_configs_match(self):
        for device in self.root().findall("NETWORK/DEVICES/DEVICE"):
            if device.findtext("ENGINE/TYPE") != "Router":
                continue
            running = [node.text for node in device.findall("ENGINE/RUNNINGCONFIG/LINE")]
            self.assertEqual(running, [node.text for node in device.findall("ENGINE/STARTUPCONFIG/LINE")])
            self.assertEqual(physical_ports(device)["Serial2/0"].findtext("POWER"), "false")
            self.assertIn(" shutdown", running)

    def test_correct_crossover_and_no_fabricated_history(self):
        root = self.root()
        self.assertTrue(all(link.findtext("CABLE/TYPE") == "eCrossOver" for link in root.findall("NETWORK/LINKS/LINK")))
        self.assertFalse(root.findall("USER_PROFILE/*"))
        for device in root.findall("NETWORK/DEVICES/DEVICE"):
            if device.findtext("ENGINE/TYPE") == "Pc":
                self.assertFalse(device.findall(".//FILE[@class='CFile']"))
        self.assertFalse(root.findall(".//DHCP_CLIENT/PORT_DATA_MAP/PORT_DATA_ENTRY"))

    def test_minimal_physical_layout_and_names(self):
        root = self.root()
        names = [node.findtext("NAME") for node in root.findall("PHYSICALWORKSPACE/.//NODE")]
        self.assertEqual(names.count("Rack"), 1)
        self.assertEqual(names.count("Table"), 1)
        for spec in self.plan["devices"]:
            self.assertEqual(names.count(spec["name"]), 1)

    def test_dynamic_process_text_preserved_not_simulated(self):
        self.plan["tests"] = []
        for spec in self.plan["devices"]:
            if spec["kind"] == "Router":
                spec.pop("routes")
                spec["routing"] = {"eigrp 300": ["network 10.0.0.0 0.0.0.3", "no auto-summary"]}
        root, report = build_root(self.plan)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(len(root.findall(".//RUNNINGCONFIG/LINE[.='router eigrp 300']")), 2)
        self.assertFalse(report["simulation_tested"])

    def test_switch_ports_and_straight_cables(self):
        self.plan = {"devices":[
            {"name":"R1","kind":"Router","interfaces":{"FastEthernet0/0":"192.168.5.1/24"}},
            {"name":"S1","kind":"Switch"},
            {"name":"PC1","kind":"Pc","interfaces":{"FastEthernet":"192.168.5.10/24"},"gateway":"192.168.5.1"}],
            "links":[{"from":["R1","FastEthernet0/0"],"to":["S1","FastEthernet0/1"]},
                     {"from":["S1","FastEthernet1/1"],"to":["PC1","FastEthernet"]}]}
        root, report = build_root(self.plan)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(all(link.findtext("CABLE/TYPE") == "eStraightThrough" for link in root.findall("NETWORK/LINKS/LINK")))

    def test_three_router_four_pc_eigrp_ospf_lab(self):
        self.plan = {"devices":[
            {"name":"R1","kind":"Router","interfaces":{"FastEthernet0/0":"10.30.10.1/24","FastEthernet1/0":"172.20.10.1/24"},"routing":{"eigrp 300":["network 10.30.10.0 0.0.0.255","network 172.20.10.0 0.0.0.255","passive-interface FastEthernet0/0","no auto-summary"]}},
            {"name":"R2","kind":"Router","interfaces":{"FastEthernet0/0":"172.20.10.2/24","FastEthernet1/0":"172.20.20.1/24","FastEthernet5/0":"10.30.20.1/24","FastEthernet6/0":"10.30.30.1/24"},"routing":{"eigrp 300":["network 172.20.10.0 0.0.0.255","network 10.30.20.0 0.0.0.255","network 10.30.30.0 0.0.0.255","passive-interface FastEthernet5/0","passive-interface FastEthernet6/0","redistribute ospf 1 metric 10000 100 255 1 1500","no auto-summary"],"ospf 1":["router-id 172.20.20.1","network 172.20.20.0 0.0.0.255 area 1","redistribute eigrp 300 subnets"]}},
            {"name":"R3","kind":"Router","interfaces":{"FastEthernet0/0":"10.30.40.1/24","FastEthernet1/0":"172.20.20.2/24"},"routing":{"ospf 1":["router-id 172.20.20.2","network 172.20.20.0 0.0.0.255 area 1","network 10.30.40.0 0.0.0.255 area 1","passive-interface FastEthernet0/0"]}},
            *[{"name":"PC"+str(index),"kind":"Pc","interfaces":{"FastEthernet":f"10.30.{index * 10}.2/24"},"gateway":f"10.30.{index * 10}.1"} for index in range(1,5)]],
            "links":[{"from":["R1","FastEthernet1/0"],"to":["R2","FastEthernet0/0"]},
                     {"from":["R2","FastEthernet1/0"],"to":["R3","FastEthernet1/0"]},
                     *[{"from":[router,port],"to":["PC"+str(index),"FastEthernet"]} for index,router,port in ((1,"R1","FastEthernet0/0"),(2,"R2","FastEthernet5/0"),(3,"R2","FastEthernet6/0"),(4,"R3","FastEthernet0/0"))]]}
        root, report = build_root(self.plan)
        self.assertEqual(len(root.findall("NETWORK/DEVICES/DEVICE")), 7)
        self.assertEqual(len(root.findall("NETWORK/LINKS/LINK")), 6)
        self.assertEqual(report["status"], "partial")
        right = root.findall("NETWORK/DEVICES/DEVICE")[2]
        lines = [node.text for node in right.findall("ENGINE/RUNNINGCONFIG/LINE")]
        self.assertIn("router ospf 1", lines)
        self.assertFalse(any(line.startswith("router eigrp ") for line in lines))

    def test_invalid_coordinates_refused(self):
        self.plan["devices"][0]["x"] = float("nan")
        with self.assertRaises(ValueError):
            self.root()

    def test_unknown_port_refused(self):
        self.plan["devices"][1]["interfaces"]["GigabitEthernet0/0"] = "172.16.0.1/24"
        with self.assertRaises(ValueError):
            self.root()

    def test_unsupported_cloud_refused_instead_of_replaced(self):
        self.plan["devices"][1]["kind"] = "Cloud"
        with self.assertRaisesRegex(ValueError, "specimens"):
            self.root()

    def test_duplicate_endpoint_refused(self):
        self.plan["links"].append(deepcopy(self.plan["links"][0]))
        with self.assertRaises(ValueError):
            self.root()

    def test_duplicate_device_name_refused(self):
        self.plan["devices"][1]["name"] = "PC1"
        with self.assertRaises(ValueError):
            self.root()

    def test_broadcast_address_refused(self):
        self.plan["devices"][0]["interfaces"]["FastEthernet"] = "192.168.10.255/24"
        with self.assertRaises(ValueError):
            self.root()

    def test_bad_gateway_refused(self):
        self.plan["devices"][0]["gateway"] = "192.168.10.99"
        with self.assertRaises(ValueError):
            self.root()

    def test_missing_return_route_refused(self):
        self.plan["devices"][2]["routes"] = []
        with self.assertRaises(ValueError):
            self.root()

    def test_routing_context_injection_refused(self):
        self.plan["devices"][1]["routing"] = {"eigrp 300": ["end"]}
        with self.assertRaises(ValueError):
            self.root()

    def test_build_writes_and_reopens_without_subprocess_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            output = Path(directory) / "lab.pkt"
            plan.write_text(json.dumps(self.plan))
            args = SimpleNamespace(plan=plan, output=output, container="auto", overwrite=False, dry_run=False)
            with patch("subprocess.Popen", side_effect=AssertionError("No app launch allowed")), patch("socket.socket", side_effect=AssertionError("No network allowed")):
                report = build(args)
            self.assertTrue(is_legacy(output.read_bytes()))
            self.assertTrue(report["round_trip_verified"])
            self.assertFalse(report["simulation_tested"])
            with self.assertRaises(FileExistsError):
                build(args)

    def test_dry_run_and_plan_alias_never_write(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            output = Path(directory) / "lab.pkt"
            plan.write_text(json.dumps(self.plan))
            args = SimpleNamespace(plan=plan, output=output, container="auto", overwrite=False, dry_run=True)
            self.assertEqual(build(args)["status"], "preview")
            self.assertFalse(output.exists())
            args.output = plan
            with self.assertRaises(ValueError):
                build(args)
            args.output = TEMPLATE
            args.overwrite = True
            with self.assertRaises(ValueError):
                build(args)


class FastRewriteTests(unittest.TestCase):
    def setUp(self):
        self.xml = gzip.decompress(TEMPLATE.read_bytes())
        self.plan = {"prefixes": [{"old": "192.168.10", "new": "10.30.10", "expect": 4}]}
        self.plan["prefixes"][0]["expect"] = sum(match.group(1) == b"192.168.10" for match in pkt_tool.PREFIX_RE.finditer(self.xml))

    def test_all_fields_updated_with_unrelated_bytes_preserved(self):
        edited, changed = transform(self.xml, self.plan)
        self.assertEqual(changed, self.plan["prefixes"][0]["expect"])
        restored, _ = pkt_tool.replace_ip_prefix(edited, "10.30.10", "192.168.10", changed)
        self.assertEqual(restored, self.xml)

    def test_prefix_swaps_are_simultaneous(self):
        plan = {"prefixes": [{"old":"10.0.1","new":"10.0.2","expect":1}, {"old":"10.0.2","new":"10.0.1","expect":1}]}
        edited, changed = transform(b"<r>10.0.1.1 10.0.2.2</r>", plan)
        self.assertEqual(edited, b"<r>10.0.2.1 10.0.1.2</r>")

    def test_as_literals_leave_metric_100_untouched(self):
        xml = b"<r>router eigrp 100;redistribute eigrp 100;metric 10000 100 255 1 1500</r>"
        plan = {"literals":[{"old":"router eigrp 100","new":"router eigrp 300","expect":1}, {"old":"redistribute eigrp 100","new":"redistribute eigrp 300","expect":1}]}
        edited, _ = transform(xml, plan)
        self.assertIn(b"router eigrp 300", edited)
        self.assertIn(b"metric 10000 100 255 1 1500", edited)

    def test_wrong_count_refused(self):
        self.plan["prefixes"][0]["expect"] += 1
        with self.assertRaises(ValueError):
            transform(self.xml, self.plan)

    def test_duplicate_destination_refused(self):
        self.plan["prefixes"].append({"old":"10.0.0","new":"10.30.10","expect":1})
        with self.assertRaises(ValueError):
            transform(self.xml, self.plan)

    def test_existing_destination_refused(self):
        with self.assertRaises(ValueError):
            transform(self.xml + b"10.30.10.1", self.plan)

    def test_unknown_plan_field_and_boolean_guard_refused(self):
        for plan in ({"bad":[]}, {"literals":[{"old":"a","new":"b","expect":True}]}):
            with self.assertRaises(ValueError):
                transform(self.xml, plan)

    def test_empty_noop_plan_refused(self):
        with self.assertRaises(ValueError):
            transform(self.xml, {})

    def invoke(self, directory, legacy=True, dry=False, mutate=None):
        source, output, plan = [Path(directory) / name for name in ("source.pkt", "new.pkt", "plan.json")]
        packet = pkt_tool.obfuscate_stage2(pkt_tool.compress_qt(self.xml)) if legacy else pkt_tool.pack_xml(self.xml)
        source.write_bytes(packet)
        plan.write_text(json.dumps(self.plan))
        args = SimpleNamespace(input=source, output=output, plan=plan, container="auto", overwrite=False, dry_run=dry)
        if mutate:
            mutate(args)
        report = rewrite(args)
        self.assertEqual(source.read_bytes(), packet)
        return report, source, output

    def test_preserves_legacy_and_actual_source(self):
        with tempfile.TemporaryDirectory() as directory:
            report, source, output = self.invoke(directory)
            self.assertTrue(is_legacy(output.read_bytes()))
            self.assertTrue(report["source_unchanged"])

    def test_preserves_eax(self):
        with tempfile.TemporaryDirectory() as directory:
            report, source, output = self.invoke(directory, legacy=False)
            self.assertFalse(is_legacy(output.read_bytes()))
            self.assertEqual(report["container"], "eax")

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            report, source, output = self.invoke(directory, dry=True)
            self.assertFalse(output.exists())

    def test_source_and_plan_alias_refused_even_overwrite(self):
        for key in ("input", "plan"):
            with tempfile.TemporaryDirectory() as directory:
                def mutate(args):
                    args.output = getattr(args, key)
                    args.overwrite = True
                with self.assertRaises(ValueError):
                    self.invoke(directory, mutate=mutate)

    def test_changed_source_hash_refused(self):
        self.plan["expect_input_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.invoke(directory)
            self.assertFalse((Path(directory) / "new.pkt").exists())

    def test_cli_parser_and_lazy_import_routes(self):
        parser = pkt_tool.build_parser()
        args = parser.parse_args(["rewrite", "a.pkt", "b.pkt", "--plan", "c.json"])
        self.assertEqual(args.container, "auto")
        self.assertEqual(args.command, "rewrite")
        self.assertEqual(parser.parse_args(["build", "a.pkt", "--plan", "c.json"]).command, "build")


if __name__ == "__main__":
    unittest.main()
