from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vlsm import allocate


class VlsmTests(unittest.TestCase):
    def test_aligned_exact_fit_out_of_order(self):
        rows = allocate("10.0.0.0/24", ["wan=2", "staff=126", "lab=62", "guest=30", "ops=14", "iot=6", "wan2=1"])
        self.assertEqual([str(n) for _, n in rows], ["10.0.0.0/25", "10.0.0.128/26", "10.0.0.192/27", "10.0.0.224/28", "10.0.0.240/29", "10.0.0.248/30", "10.0.0.252/30"])

    def test_one_more_host_doubles_subnet(self):
        self.assertEqual(allocate("10.0.0.0/24", ["staff=31"])[0][1].prefixlen, 26)

    def test_rejects_invalid_plans(self):
        for block, requests in [("10.0.0.0/27", ["a=30","b=1"]), ("10.0.0.1/24", ["a=1"]), ("10.0.0.0/24", ["a=1","a=2"]), ("10.0.0.0/24", ["a=0"]), ("10.0.0.0/24", ["a=-2"])]:
            with self.subTest(block=block, requests=requests), self.assertRaises(ValueError):
                allocate(block, requests)
