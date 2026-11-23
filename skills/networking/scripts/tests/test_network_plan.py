import ipaddress as ip
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pkt_plan import plan_ipv4


class NetworkPlanTest(unittest.TestCase):
    def test_largest_first_and_exact_ranges(self):
        result = plan_ipv4("192.168.10.0/24", ["small=2", "large=20", "medium=8"], ["R1-R2"])
        entries = result["allocations"]
        self.assertEqual([entry["name"] for entry in entries], ["large", "medium", "small", "R1-R2"])
        self.assertEqual([entry["network"] for entry in entries], [
            "192.168.10.0/27", "192.168.10.32/28", "192.168.10.48/29", "192.168.10.56/30",
        ])
        self.assertEqual(entries[0]["subnet_mask"], "255.255.255.224")
        self.assertEqual(entries[0]["gateway"], "192.168.10.1")
        self.assertEqual(entries[0]["pc_range"], {"first": "192.168.10.2", "last": "192.168.10.21"})
        self.assertEqual(entries[0]["usable_range"], {"first": "192.168.10.1", "last": "192.168.10.30"})
        self.assertEqual(entries[-1]["router_addresses"], ["192.168.10.57", "192.168.10.58"])
        self.assertEqual(result["allocated_addresses"], 60)
        self.assertEqual(result["remaining_addresses"], 196)
        self.assertFalse(result["simulation_tested"])

    def test_one_pc_reserves_a_separate_gateway(self):
        entry = plan_ipv4("10.1.0.0/30", ["LAN=1"], [])["allocations"][0]
        self.assertEqual(entry["network"], "10.1.0.0/30")
        self.assertEqual(entry["gateway"], "10.1.0.1")
        self.assertEqual(entry["pc_range"], {"first": "10.1.0.2", "last": "10.1.0.2"})
        self.assertEqual(entry["usable_capacity"], 2)

    def test_power_of_two_capacity_boundary(self):
        exact = plan_ipv4("10.1.0.0/24", ["LAN=5"], [])["allocations"][0]
        larger = plan_ipv4("10.1.0.0/24", ["LAN=6"], [])["allocations"][0]
        self.assertEqual(exact["prefix_length"], 29)
        self.assertEqual(larger["prefix_length"], 28)

    def test_ties_are_stable_across_request_order(self):
        first = plan_ipv4("10.1.0.0/24", ["B=1", "A=1"], ["D", "C"])
        second = plan_ipv4("10.1.0.0/24", ["A=1", "B=1"], ["C", "D"])
        self.assertEqual(first, second)
        self.assertEqual([entry["name"] for entry in first["allocations"]], ["A", "B", "C", "D"])

    def test_allocations_are_aligned_disjoint_and_within_base(self):
        result = plan_ipv4("172.16.4.0/23", ["A=100", "B=50", "C=20", "D=4"], ["X", "Y", "Z"])
        base = ip.IPv4Network(result["base_network"])
        nets = [ip.IPv4Network(entry["network"], strict=True) for entry in result["allocations"]]
        self.assertTrue(all(net.subnet_of(base) for net in nets))
        self.assertFalse(any(a.overlaps(b) for index, a in enumerate(nets) for b in nets[index + 1:]))
        for entry in result["allocations"]:
            if entry["kind"] == "lan":
                self.assertNotEqual(entry["gateway"], entry["pc_range"]["first"])
                self.assertLessEqual(ip.IPv4Address(entry["pc_range"]["last"]),
                                     ip.IPv4Address(entry["usable_range"]["last"]))

    def test_full_base_can_be_used_exactly(self):
        result = plan_ipv4("192.0.2.0/29", ["A=1"], ["B"])
        self.assertEqual(result["remaining_addresses"], 0)
        self.assertEqual(result["allocations"][-1]["network"], "192.0.2.4/30")

    def test_insufficient_space_rejects_individual_and_combined_requests(self):
        for base, lans, transits in [
            ("192.0.2.0/30", ["A=2"], []),
            ("192.0.2.0/30", ["A=1"], ["B"]),
            ("192.0.2.0/31", [], ["B"]),
        ]:
            with self.subTest(base=base, lans=lans):
                with self.assertRaisesRegex(ValueError, "Insufficient space"):
                    plan_ipv4(base, lans, transits)

    def test_forbidden_ranges_include_partially_overlapping_bases(self):
        for base in ["0.1.0.0/24", "127.10.0.0/24", "224.0.0.0/24", "240.0.0.0/24",
                     "255.255.255.252/30", "126.0.0.0/7", "192.0.0.0/2", "0.0.0.0/0"]:
            with self.subTest(base=base):
                with self.assertRaisesRegex(ValueError, "overlaps"):
                    plan_ipv4(base, ["A=1"], [])

    def test_private_public_and_documentation_bases_are_allowed(self):
        for base in ["10.1.0.0/24", "172.16.10.0/24", "192.168.1.0/24",
                     "8.8.8.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]:
            with self.subTest(base=base):
                self.assertEqual(plan_ipv4(base, ["LAN=1"], [])["base_network"], base)

    def test_invalid_base(self):
        for base in ["192.0.2.1/24", "192.0.2.0", "::/64", "bad", None]:
            with self.subTest(base=base):
                with self.assertRaises(ValueError):
                    plan_ipv4(base, ["A=1"], [])

    def test_invalid_pc_counts_and_lan_syntax(self):
        for request in ["A=0", "A=-1", "A=+1", "A=1.0", "A=", "A=true", "A=8589934592",
                        "=1", "A", "A=1=2", "A\nB=1", None]:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    plan_ipv4("192.0.2.0/24", [request], [])

    def test_duplicate_names_rejected_across_kinds_and_case(self):
        for lans, transits in [(["A=1", "a=2"], []), (["A=1"], ["A"]), ([], ["A", " a "])]:
            with self.subTest(lans=lans, transits=transits):
                with self.assertRaisesRegex(ValueError, "Duplicate"):
                    plan_ipv4("192.0.2.0/24", lans, transits)

    def test_invalid_transit_name(self):
        for request in ["", " ", "A=2", "A\tB", None]:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    plan_ipv4("192.0.2.0/24", [], [request])

    def test_empty_and_wrong_request_types_rejected(self):
        for lans, transits in [([], []), (("A=1",), []), ([], "A"), (None, [])]:
            with self.subTest(lans=lans, transits=transits):
                with self.assertRaises(ValueError):
                    plan_ipv4("192.0.2.0/24", lans, transits)

    def test_no_mutation_or_file_operations(self):
        lans, transits = ["B=8", "A=2"], ["R1-R2"]
        before = (list(lans), list(transits))
        with patch("builtins.open", side_effect=AssertionError("Planning must not open files")):
            result = plan_ipv4("192.0.2.0/24", lans, transits)
        self.assertEqual((lans, transits), before)
        self.assertFalse(result["simulation_tested"])


if __name__ == "__main__":
    unittest.main()
