import json
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pkt_dns import audit_dns


def node(parent, name, value):
    ET.SubElement(parent, name).text = value


def device(parent, kind, name, address):
    d = ET.SubElement(parent, "DEVICE")
    e = ET.SubElement(d, "ENGINE")
    node(e, "TYPE", kind)
    node(e, "NAME", name)
    node(e, "POWER", "true")
    module = ET.SubElement(ET.SubElement(ET.SubElement(e, "MODULE"), "SLOT"), "MODULE")
    p = ET.SubElement(module, "PORT")
    for tag, value in [("TYPE", "eCopperFastEthernet"), ("POWER", "true"), ("IP", address), ("SUBNET", "255.255.255.0")]:
        node(p, tag, value)
    return d


class DnsTest(unittest.TestCase):
    def setUp(self):
        self.root = ET.fromstring("<PACKETTRACER5><VERSION>5.3.3.0019</VERSION><NETWORK><DEVICES/></NETWORK></PACKETTRACER5>")
        ds = self.root.find("NETWORK/DEVICES")
        self.pc = device(ds, "Pc", "PC1", "192.168.10.10")
        node(ET.SubElement(self.pc.find("ENGINE"), "DNS_CLIENT"), "SERVER_IP", "192.168.10.2")
        self.dns = device(ds, "Server", "DNS1", "192.168.10.2")
        service = ET.SubElement(self.dns.find("ENGINE"), "DNS_SERVER")
        node(service, "ENABLED", "1")
        self.table = ET.SubElement(service, "NAMESERVER-DATABASE")
        self.web = device(ds, "Server", "WEB1", "192.168.10.3")
        node(ET.SubElement(self.web.find("ENGINE"), "HTTP_SERVER"), "ENABLED", "1")
        self.add("A-REC", "example.com", "192.168.10.3")
        self.add("CNAME", "www.example.com", "example.com")

    def add(self, kind, name, value, table=None):
        row = ET.SubElement(self.table if table is None else table, "RESOURCE-RECORD")
        node(row, "TYPE", kind)
        node(row, "NAME", name)
        node(row, "TTL", "86400")
        node(row, "IPADDRESS" if kind == "A-REC" else "HOSTNAME", value)
        return row

    def check(self, query=None):
        return audit_dns(self.root, [query or ("PC1", "www.example.com", "192.168.10.3")])

    def codes(self, report, kind="errors"):
        return {row["code"] for row in report[kind]}

    def test_saved_a_and_alias_resolve_without_query_or_mutation(self):
        before = ET.tostring(self.root)
        report = self.check()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["resolutions"][0]["addresses"], ["192.168.10.3"])
        self.assertEqual(report["resolutions"][0]["alias_chain"], ["www.example.com", "example.com"])
        self.assertEqual(ET.tostring(self.root), before)
        for field in ["simulation_tested", "queries_executed", "path_tested", "path_modeled", "http_rendered"]:
            self.assertFalse(report[field])

    def test_case_and_root_dot_match(self):
        self.table[0].find("NAME").text = "EXAMPLE.COM."
        self.table[1].find("HOSTNAME").text = "Example.Com."
        self.assertEqual(self.check(("PC1", "WWW.EXAMPLE.COM.", "192.168.10.3"))["status"], "passed")

    def test_a_query_without_expected_address_is_modeled(self):
        report = self.check(("PC1", "example.com"))
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["resolutions"][0]["status"], "modeled")

    def test_alias_loop_is_rejected_even_without_requested_query(self):
        self.add("CNAME", "a.example.com", "b.example.com")
        self.add("CNAME", "b.example.com", "a.example.com")
        self.assertIn("dns.alias.loop", self.codes(audit_dns(self.root)))
        report = self.check(("PC1", "a.example.com"))
        self.assertEqual(report["resolutions"][0]["status"], "failed")

    def test_self_alias_loop_is_rejected(self):
        self.add("CNAME", "self.example.com", "SELF.EXAMPLE.COM.")
        self.assertIn("dns.alias.loop", self.codes(audit_dns(self.root)))

    def test_alias_and_address_same_owner_conflict(self):
        self.add("A-REC", "www.example.com", "192.168.10.3")
        self.assertIn("dns.record.conflict", self.codes(self.check()))

    def test_two_different_alias_targets_conflict(self):
        self.add("CNAME", "WWW.EXAMPLE.COM.", "other.example.com")
        self.assertIn("dns.record.conflict", self.codes(self.check()))

    def test_duplicate_equivalent_record_is_partial(self):
        self.add("A-REC", "EXAMPLE.COM.", "192.168.10.3")
        report = self.check()
        self.assertEqual(report["status"], "partial")
        self.assertIn("dns.record.duplicate", self.codes(report, "warnings"))

    def test_multiple_a_answers_are_not_incorrectly_rejected_as_invalid_dns(self):
        self.add("A-REC", "example.com", "192.168.10.4")
        report = self.check()
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["errors"])
        self.assertEqual(report["resolutions"][0]["addresses"], ["192.168.10.3", "192.168.10.4"])

    def test_disabled_selected_server_fails(self):
        self.dns.find("ENGINE/DNS_SERVER/ENABLED").text = "0"
        self.assertIn("dns.server.disabled", self.codes(self.check()))

    def test_unused_disabled_empty_server_is_benign(self):
        service = ET.SubElement(self.web.find("ENGINE"), "DNS_SERVER")
        node(service, "ENABLED", "0")
        ET.SubElement(service, "NAMESERVER-DATABASE")
        self.assertEqual(self.check()["status"], "passed")

    def test_disabled_stored_records_without_client_intent_remain_partial(self):
        self.dns.find("ENGINE/DNS_SERVER/ENABLED").text = "0"
        self.pc.find("ENGINE/DNS_CLIENT/SERVER_IP").text = "0.0.0.0"
        report = audit_dns(self.root)
        self.assertEqual(report["status"], "partial")
        self.assertIn("dns.server.inactive-records", self.codes(report, "warnings"))

    def test_enabled_server_without_supported_interface_remains_partial(self):
        self.pc.find("ENGINE/DNS_CLIENT/SERVER_IP").text = "0.0.0.0"
        self.dns.find("ENGINE/MODULE/SLOT/MODULE/PORT/IP").text = "0.0.0.0"
        report = audit_dns(self.root)
        self.assertEqual(report["status"], "partial")
        self.assertIn("dns.server.interface", self.codes(report, "warnings"))

    def test_wrong_client_dns_points_to_known_non_dns_device(self):
        self.pc.find("ENGINE/DNS_CLIENT/SERVER_IP").text = "192.168.10.3"
        self.assertIn("dns.client.server", self.codes(self.check()))

    def test_external_resolver_is_partial_instead_of_guessed_invalid(self):
        self.pc.find("ENGINE/DNS_CLIENT/SERVER_IP").text = "192.0.2.53"
        report = self.check()
        self.assertEqual(report["status"], "partial")
        self.assertIn("dns.client.external", self.codes(report, "warnings"))

    def test_unspecified_ipv6_dns_sentinel_is_unconfigured_not_partial(self):
        value = ET.SubElement(self.pc.find("ENGINE/DNS_CLIENT"), "SERVER_IPV6")
        for sentinel in ["", "::", "0:0:0:0:0:0:0:0"]:
            with self.subTest(sentinel=sentinel):
                value.text = sentinel
                self.assertEqual(self.check()["status"], "passed")

    def test_actual_ipv6_dns_setting_remains_partial(self):
        node(self.pc.find("ENGINE/DNS_CLIENT"), "SERVER_IPV6", "2001:db8::53")
        report = self.check()
        self.assertEqual(report["status"], "partial")
        self.assertIn("dns.unsupported.ipv6", self.codes(report, "warnings"))

    def test_malformed_ipv6_dns_address_fails(self):
        node(self.pc.find("ENGINE/DNS_CLIENT"), "SERVER_IPV6", "not-ipv6")
        self.assertIn("dns.client.ipv6", self.codes(self.check()))

    def test_unset_client_dns_fails_explicit_query(self):
        self.pc.find("ENGINE/DNS_CLIENT/SERVER_IP").text = "0.0.0.0"
        self.assertIn("dns.client.setting", self.codes(self.check()))

    def test_invalid_unicast_a_address_fails(self):
        for value in ["not-an-ip", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"]:
            with self.subTest(value=value):
                self.table[0].find("IPADDRESS").text = value
                self.assertIn("dns.record.address", self.codes(self.check()))

    def test_external_a_record_is_valid_without_assuming_a_local_device(self):
        self.table[0].find("IPADDRESS").text = "192.0.2.10"
        report = self.check(("PC1", "example.com", "192.0.2.10"))
        self.assertEqual(report["status"], "passed")

    def test_expected_ip_mismatch_fails(self):
        self.assertIn("dns.query.expected", self.codes(self.check(("PC1", "example.com", "192.168.10.4"))))

    def test_other_server_records_are_never_combined_for_alias_resolution(self):
        self.table.remove(self.table[0])
        service = ET.SubElement(self.web.find("ENGINE"), "DNS_SERVER")
        node(service, "ENABLED", "1")
        other = ET.SubElement(service, "NAMESERVER-DATABASE")
        self.add("A-REC", "example.com", "192.168.10.3", other)
        report = self.check()
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["resolutions"][0]["addresses"], [])

    def test_ns_soa_aaaa_or_unknown_type_is_partial(self):
        for kind in ["NS", "SOA", "AAAA", "unknown"]:
            with self.subTest(kind=kind):
                other = self.add(kind, "delegation.example.com", "192.0.2.1")
                self.assertEqual(self.check()["status"], "partial")
                self.table.remove(other)

    def test_unsupported_root_zone_record_is_partial_not_incorrectly_invalid(self):
        self.add("NS", ".", "ns.example.com")
        report = self.check()
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["errors"])

    def test_wildcard_or_international_owner_requires_separate_validation(self):
        for owner in ["*.example.com", "café.example.com"]:
            with self.subTest(owner=owner):
                record = self.add("A-REC", owner, "192.0.2.1")
                report = self.check()
                self.assertEqual(report["status"], "partial")
                self.assertFalse(report["errors"])
                self.table.remove(record)

    def test_invalid_record_ttl_fails(self):
        self.table[0].find("TTL").text = "-1"
        self.assertIn("dns.record.ttl", self.codes(self.check()))

    def test_selected_server_powered_off_fails(self):
        self.dns.find("ENGINE/POWER").text = "false"
        self.assertIn("dns.server.power", self.codes(self.check()))

    def test_duplicate_dns_server_ip_is_ambiguous(self):
        self.web.find("ENGINE/MODULE/SLOT/MODULE/PORT/IP").text = "192.168.10.2"
        self.assertIn("dns.server.ambiguous", self.codes(self.check()))

    def test_intended_web_target_checks_ip_and_http_only(self):
        report = self.check(("PC1", "www.example.com", None, "WEB1"))
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["resolutions"][0]["web_configuration_checked"])
        self.assertFalse(report["http_rendered"])
        self.web.find("ENGINE/HTTP_SERVER/ENABLED").text = "0"
        self.assertIn("dns.web.service", self.codes(self.check(("PC1", "www.example.com", None, "WEB1"))))

    def test_intended_web_target_wrong_ip_fails(self):
        self.web.find("ENGINE/MODULE/SLOT/MODULE/PORT/IP").text = "192.168.10.4"
        self.assertIn("dns.web.address", self.codes(self.check(("PC1", "www.example.com", None, "WEB1"))))

    def test_raw_profile_password_and_html_are_not_returned(self):
        node(ET.SubElement(self.root, "USER_PROFILE"), "NAME", "PRIVATE_PROFILE_91234")
        node(self.web.find("ENGINE/HTTP_SERVER"), "PASSWORD", "PRIVATE_PASSWORD_87654")
        node(ET.SubElement(self.web.find("ENGINE"), "HTML_TAB"), "HTML_CODE", "PRIVATE_HTML_17263")
        text = json.dumps(self.check())
        for private in ["PRIVATE_PROFILE_91234", "PRIVATE_PASSWORD_87654", "PRIVATE_HTML_17263", "<PACKETTRACER"]:
            self.assertNotIn(private, text)

    def test_malformed_query_or_unknown_client_cannot_pass(self):
        for query in [("missing", "example.com"), ("PC1", "bad..example.com"), ("PC1",), ("PC1", "example.com", "broken")]:
            with self.subTest(query=query):
                self.assertEqual(self.check(query)["status"], "failed")

    def test_empty_layout_fails(self):
        self.assertEqual(audit_dns(ET.fromstring("<PACKETTRACER5/>"))["status"], "failed")


if __name__ == "__main__":
    unittest.main()
