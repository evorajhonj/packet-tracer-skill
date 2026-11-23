#!/usr/bin/env python3
"""Create, inspect, and safely edit Cisco Packet Tracer .pkt files offline."""

from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
import zlib

from Decipher.eax import EAX
from Decipher.pt_crypto import decrypt_pkt as decrypt_eax_pkt
from Decipher.twofish import Twofish


IPV4_RE = re.compile(rb"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
PREFIX_RE = re.compile(rb"(?<![0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?![0-9.])")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compress_qt(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + zlib.compress(data)


def obfuscate_stage2(data: bytes) -> bytes:
    length = len(data)
    return bytes(byte ^ ((length - index) & 0xFF) for index, byte in enumerate(data))


def obfuscate_stage1(data: bytes) -> bytes:
    length = len(data)
    output = bytearray(length)
    for index, byte in enumerate(data):
        output[length - 1 - index] = byte ^ ((length - index * length) & 0xFF)
    return bytes(output)


def encrypt_pkt(data: bytes) -> bytes:
    cipher = Twofish(bytes([137]) * 16)
    ciphertext, tag = EAX(cipher.encrypt).encrypt(
        nonce=bytes([16]) * 16,
        plaintext=data,
    )
    return ciphertext + tag


def pack_xml(xml: bytes) -> bytes:
    return obfuscate_stage1(encrypt_pkt(obfuscate_stage2(compress_qt(xml))))


def decrypt_pkt(packet: bytes) -> bytes:
    # Installed PT5 samples use decreasing XOR + Qt compression, without EAX.
    legacy = obfuscate_stage2(packet)
    if len(legacy) > 6 and legacy[4:6] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
        xml = zlib.decompress(legacy[4:])
        if len(xml) != struct.unpack(">I", legacy[:4])[0]:
            raise ValueError("Legacy packet decompressed size mismatch")
        parse_xml(xml)
        return xml
    return decrypt_eax_pkt(packet)


def parse_xml(xml: bytes) -> ET.Element:
    return ET.fromstring(xml)


def load_packet(path: Path) -> tuple[bytes, bytes, ET.Element]:
    packet = path.read_bytes()
    xml = decrypt_pkt(packet)
    return packet, xml, parse_xml(xml)


def prefix(value: str) -> str:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() or not 0 <= int(part) <= 255 for part in parts):
        raise ValueError(f"IPv4 prefix must contain three octets: {value}")
    return value


def inspect_packet(path: Path) -> dict:
    packet, xml, root = load_packet(path)
    devices = root.findall("./NETWORK/DEVICES/DEVICE")
    links = root.findall("./NETWORK/LINKS/LINK")
    device_types = Counter()
    device_names = []
    for device in devices:
        engine = device.find("ENGINE")
        if engine is None:
            continue
        device_types[engine.findtext("TYPE", "Unknown")] += 1
        device_names.append(engine.findtext("NAME", ""))

    dns_records = {
        record.findtext("NAME", ""): record.findtext("IPADDRESS", "")
        for record in root.findall(".//RESOURCE-RECORD")
        if record.findtext("NAME")
    }
    clock_rates = Counter(
        node.text for node in root.iter("CLOCKRATE") if node.text
    )
    link_types = Counter(link.findtext("TYPE", "Unknown") for link in links)
    ip_prefix_counts = Counter(
        match.group(1).decode() for match in PREFIX_RE.finditer(xml)
    )
    dce_ports = []
    topology_links = []
    for link in links:
        cable = link.find("CABLE")
        if cable is not None:
            endpoints = cable.findall("PORT")
            from_index = int(cable.findtext("FROM", "-1"))
            to_index = int(cable.findtext("TO", "-1"))
            topology_links.append(
                {
                    "type": link.findtext("TYPE", ""),
                    "from": device_names[from_index] if 0 <= from_index < len(device_names) else "",
                    "from_port": endpoints[0].text if len(endpoints) > 0 else "",
                    "to": device_names[to_index] if 0 <= to_index < len(device_names) else "",
                    "to_port": endpoints[1].text if len(endpoints) > 1 else "",
                }
            )
        if link.findtext("TYPE") != "eSerial":
            continue
        if cable is None or cable.findtext("DCEDEV") is None:
            continue
        device_index = int(cable.findtext("DCEDEV", "-1"))
        name = ""
        if 0 <= device_index < len(devices):
            name = devices[device_index].findtext("ENGINE/NAME", "")
        dce_ports.append(
            {
                "device_index": device_index,
                "device": name,
                "port": cable.findtext("DCEPORT", ""),
            }
        )

    return {
        "path": str(path.resolve()),
        "packet_bytes": len(packet),
        "xml_bytes": len(xml),
        "sha256": sha256(packet),
        "packet_tracer_version": root.findtext("VERSION", ""),
        "device_counts": dict(sorted(device_types.items())),
        "device_names": device_names,
        "link_count": len(links),
        "link_type_counts": dict(sorted(link_types.items())),
        "links": topology_links,
        "dns_records": dict(sorted(dns_records.items())),
        "clock_rates": dict(sorted(clock_rates.items())),
        "dce_ports": dce_ports,
        "ip_prefix_counts": dict(sorted(ip_prefix_counts.items())),
        "ipv4_reference_count": len(IPV4_RE.findall(xml)),
    }


def count_xml_values(path: Path, values: list[str]) -> dict:
    _, xml, _ = load_packet(path)
    return {value: xml.count(value.encode()) for value in values}


def require_count(kind: str, actual: int, expected: int | None) -> None:
    if expected is None:
        raise ValueError(f"{kind} edit requires its --expect-*-count guard")
    if actual != expected:
        raise ValueError(f"{kind} matched {actual} values; expected {expected}")


def replace_ip_prefix(xml: bytes, old: str, new: str, expected: int | None) -> tuple[bytes, int]:
    old = prefix(old)
    new = prefix(new)
    pattern = re.compile(
        rb"(?<![0-9.])" + re.escape(old.encode()) + rb"\.(\d{1,3})(?![0-9.])"
    )
    matches = list(pattern.finditer(xml))
    require_count("IP prefix", len(matches), expected)
    updated = pattern.sub(lambda match: new.encode() + b"." + match.group(1), xml)
    if pattern.search(updated):
        raise ValueError(f"Old IP prefix remains after edit: {old}")
    return updated, len(matches)


def replace_literal(
    xml: bytes,
    old: str,
    new: str,
    expected: int | None,
    kind: str,
) -> tuple[bytes, int]:
    old_bytes = old.encode()
    matches = xml.count(old_bytes)
    require_count(kind, matches, expected)
    return xml.replace(old_bytes, new.encode()), matches


def replace_heading(xml: bytes, old: str, new: str, expected: int | None) -> tuple[bytes, int]:
    variants = (
        (f"&lt;b>{old}&lt;/b>".encode(), f"&lt;b>{new}&lt;/b>".encode()),
        (f"&lt;b&gt;{old}&lt;/b&gt;".encode(), f"&lt;b&gt;{new}&lt;/b&gt;".encode()),
    )
    matches = sum(xml.count(before) for before, _ in variants)
    require_count("heading", matches, expected)
    for before, after in variants:
        xml = xml.replace(before, after)
    return xml, matches


def replace_dce_clock(
    xml: bytes,
    old: str,
    new: str,
    expected: int | None,
) -> tuple[bytes, int]:
    old_tag = f"<CLOCKRATE>{old}</CLOCKRATE>".encode()
    new_tag = f"<CLOCKRATE>{new}</CLOCKRATE>".encode()
    matches = xml.count(old_tag)
    require_count("clock rate", matches, expected)
    root = parse_xml(xml)
    dce_count = sum(
        1
        for link in root.findall(".//LINK")
        if link.findtext("TYPE") == "eSerial"
        and link.findtext("CABLE/DCEDEV") is not None
    )
    if matches != dce_count:
        raise ValueError(
            f"Clock value {old} appears {matches} times but topology has {dce_count} DCE links; refusing broad replacement"
        )
    return xml.replace(old_tag, new_tag), matches


def atomic_write(path: Path, data: bytes, overwrite: bool = False) -> None:
    path = path.resolve()
    if path.exists() and not overwrite:
        raise FileExistsError(f"Output exists; choose another path or pass --overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as temporary:
            temporary.write(data)
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def edit_packet(args: argparse.Namespace) -> dict:
    source = args.input.resolve()
    output = args.output.resolve()
    if source == output:
        raise ValueError("Input and output must be different paths")
    packet, original_xml, _ = load_packet(source)
    source_hash = sha256(packet)
    xml = original_xml
    changes = {}

    if args.ip_prefix:
        xml, changes["ip_prefix"] = replace_ip_prefix(
            xml, args.ip_prefix[0], args.ip_prefix[1], args.expect_ip_count
        )
    if args.domain:
        xml, changes["domain"] = replace_literal(
            xml, args.domain[0], args.domain[1], args.expect_domain_count, "domain"
        )
    if args.heading:
        xml, changes["heading"] = replace_heading(
            xml, args.heading[0], args.heading[1], args.expect_heading_count
        )
    if args.clock_rate:
        xml, changes["clock_rate"] = replace_dce_clock(
            xml, args.clock_rate[0], args.clock_rate[1], args.expect_clock_count
        )
    if not changes:
        raise ValueError("No edit requested")

    parse_xml(xml)
    packed = pack_xml(xml)
    if decrypt_pkt(packed) != xml:
        raise AssertionError("In-memory decrypt round trip did not reproduce edited XML")
    if sha256(source.read_bytes()) != source_hash:
        raise AssertionError("Source file changed during edit")
    atomic_write(output, packed, overwrite=args.overwrite)
    if decrypt_pkt(output.read_bytes()) != xml:
        raise AssertionError("Saved output did not reopen to the edited XML")
    return {
        "input": str(source),
        "output": str(output),
        "input_sha256": source_hash,
        "output_sha256": sha256(output.read_bytes()),
        "changes": changes,
        "round_trip_verified": True,
        "source_unchanged": sha256(source.read_bytes()) == source_hash,
    }


def decode_packet(input_path: Path, output_path: Path, overwrite: bool) -> dict:
    packet, xml, _ = load_packet(input_path)
    atomic_write(output_path, xml, overwrite=overwrite)
    return {
        "input": str(input_path.resolve()),
        "output": str(output_path.resolve()),
        "input_sha256": sha256(packet),
        "xml_bytes": len(xml),
    }


def encode_packet(input_path: Path, output_path: Path, overwrite: bool) -> dict:
    xml = input_path.read_bytes()
    parse_xml(xml)
    packet = pack_xml(xml)
    if decrypt_pkt(packet) != xml:
        raise AssertionError("In-memory decrypt round trip did not reproduce source XML")
    atomic_write(output_path, packet, overwrite=overwrite)
    if decrypt_pkt(output_path.read_bytes()) != xml:
        raise AssertionError("Saved packet did not reopen to source XML")
    return {
        "input": str(input_path.resolve()),
        "output": str(output_path.resolve()),
        "xml_bytes": len(xml),
        "round_trip_verified": True,
    }


def device_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", value):
        raise ValueError(
            "Device names must be 1-32 characters using letters, numbers, dot, underscore, or hyphen"
        )
    return value


def create_packet(args: argparse.Namespace) -> dict:
    network = ipaddress.ip_network(args.network, strict=True)
    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported")
    if network.prefixlen > 30:
        raise ValueError("Network must provide at least two usable IPv4 addresses")

    router_ip = network.network_address + 1
    preferred_pc_ip = network.network_address + 10
    pc_ip = preferred_pc_ip if preferred_pc_ip < network.broadcast_address else network.broadcast_address - 1
    if pc_ip == router_ip:
        raise ValueError("Network must provide separate router and PC addresses")

    template_path = (
        Path(__file__).resolve().parent.parent
        / "templates"
        / "three-node-packet-tracer-5.xml.gz"
    )
    xml = gzip.decompress(template_path.read_bytes())
    root = parse_xml(xml)

    requested_names = {
        "Router": device_name(args.router),
        "Switch": device_name(args.switch),
        "Pc": device_name(args.pc),
    }
    if len(set(requested_names.values())) != 3:
        raise ValueError("Router, switch, and PC names must be unique")
    default_names = {"Router": "R1", "Switch": "S1", "Pc": "PC1"}
    for packet_device in root.findall("./NETWORK/DEVICES/DEVICE"):
        engine = packet_device.find("ENGINE")
        if engine is None:
            continue
        device_type = engine.findtext("TYPE", "")
        if device_type not in requested_names:
            continue
        old_name = default_names[device_type]
        new_name = requested_names[device_type]
        engine.find("NAME").text = new_name
        sys_name = engine.find("SYS_NAME")
        if sys_name is not None:
            sys_name.text = new_name
        physical = packet_device.find("WORKSPACE/PHYSICAL")
        if physical is not None and physical.text:
            parts = physical.text.split(",")
            parts[-1] = new_name
            physical.text = ",".join(parts)
        for line in engine.findall("RUNNINGCONFIG/LINE") + engine.findall("STARTUPCONFIG/LINE"):
            if line.text:
                line.text = line.text.replace(old_name, new_name)

    for physical_node in root.findall(".//PHYSICALWORKSPACE//NODE"):
        node_name = physical_node.find("NAME")
        if node_name is None or node_name.text is None:
            continue
        for device_type, old_name in default_names.items():
            if node_name.text == old_name:
                node_name.text = requested_names[device_type]

    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    replacements = {
        b"192.168.10.10": str(pc_ip).encode(),
        b"192.168.10.1": str(router_ip).encode(),
        b"255.255.255.0": str(network.netmask).encode(),
    }
    for old, new in replacements.items():
        xml = xml.replace(old, new)

    from pkt_network import audit
    network_report = audit(parse_xml(xml))
    if network_report["errors"]:
        raise ValueError("Created topology failed audit: " + json.dumps(network_report["errors"]))
    packet = pack_xml(xml)
    if decrypt_pkt(packet) != xml:
        raise AssertionError("In-memory decrypt round trip did not reproduce created XML")
    atomic_write(args.output, packet, overwrite=args.overwrite)
    if decrypt_pkt(args.output.read_bytes()) != xml:
        raise AssertionError("Saved packet did not reopen to the created XML")

    return {
        "output": str(args.output.resolve()),
        "created_from_scratch": True,
        "input_packet": None,
        "packet_tracer_version": root.findtext("VERSION", ""),
        "device_names": [requested_names["Router"], requested_names["Switch"], requested_names["Pc"]],
        "addresses": {
            "network": str(network),
            "router": str(router_ip),
            "pc": str(pc_ip),
            "subnet_mask": str(network.netmask),
            "pc_gateway": str(router_ip),
        },
        "links": 2,
        "round_trip_verified": True,
        "sha256": sha256(args.output.read_bytes()),
        "network_audit": network_report,
    }


def self_test() -> dict:
    xml = b"<?xml version='1.0'?><PACKETTRACER5><VERSION>self-test</VERSION></PACKETTRACER5>"
    packet = pack_xml(xml)
    assert decrypt_pkt(packet) == xml
    return {"self_test": "passed", "packet_bytes": len(packet)}


def dns_query_arguments(args):
    return [*args.resolve, *args.expect,
            *[(client, name, None, server) for client, name, server in args.web]]


def protocol_report(args):
    source = args.input.resolve()
    original, _, root = load_packet(source)
    if args.command == "eigrp":
        from pkt_eigrp import plan_eigrp
        plan = json.loads(args.plan.read_text(encoding="utf-8-sig"))
        report = plan_eigrp(root, plan)
    elif args.command == "audit-eigrp":
        from pkt_eigrp import audit_eigrp
        report = audit_eigrp(root)
    else:
        from pkt_dns import audit_dns
        report = audit_dns(root, dns_query_arguments(args))
    after = source.read_bytes()
    if original != after:
        raise ValueError("Input changed during the read-only protocol check")
    report.update({"input_path": str(source), "source_unchanged": True,
                   "source_sha256_before": sha256(original), "source_sha256_after": sha256(after)})
    if report.get("status") not in {"passed", "failed", "partial"}:
        raise ValueError("Protocol helper did not return a valid status")
    if args.overwrite and args.report is None:
        raise ValueError("--overwrite applies only to an explicit report path")
    if args.report is not None:
        from pkt_tester import _validate_report_path
        target = _validate_report_path(args.report, source, args.overwrite)
        if args.command == "eigrp":
            plan_path = args.plan.resolve()
            if target == plan_path or (target.exists() and target.samefile(plan_path)):
                raise ValueError("Report must be distinct from the configuration plan")
        atomic_write(target, (json.dumps(report, indent=2) + "\n").encode("utf-8"), overwrite=args.overwrite)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, help_text in (("build", "build an explicit copper topology directly from bundled specimens"),
                               ("rewrite", "batch guarded IP/text edits in one pass, preserving the container")):
        fast_parser = subparsers.add_parser(command, help=help_text)
        if command == "rewrite":
            fast_parser.add_argument("input", type=Path)
        fast_parser.add_argument("output", type=Path)
        fast_parser.add_argument("--plan", required=True, type=Path)
        fast_parser.add_argument("--container", choices=("auto", "legacy", "eax"), default="auto")
        fast_parser.add_argument("--dry-run", action="store_true")
        fast_parser.add_argument("--overwrite", action="store_true")

    plan_parser = subparsers.add_parser("plan", help="allocate nonoverlapping IPv4 LAN and /30 transit subnets")
    plan_parser.add_argument("--base", required=True, help="Aligned IPv4 base network in CIDR form")
    plan_parser.add_argument("--lan", action="append", default=[], metavar="NAME=PC_COUNT")
    plan_parser.add_argument("--transit", action="append", default=[], metavar="NAME")
    plan_parser.add_argument("--json", action="store_true")

    test_parser = subparsers.add_parser("test", help="test the skill or check one packet offline with a JSON report")
    test_parser.add_argument("input", nargs="?", type=Path)
    test_parser.add_argument("--between", nargs=2, action="append", default=[], metavar=("SOURCE", "DESTINATION"))
    test_parser.add_argument("--resolve", nargs=2, action="append", default=[], metavar=("CLIENT", "DNS_NAME"))
    test_parser.add_argument("--expect", nargs=3, action="append", default=[], metavar=("CLIENT", "DNS_NAME", "IPV4"))
    test_parser.add_argument("--web", nargs=3, action="append", default=[], metavar=("CLIENT", "DNS_NAME", "SERVER"))
    test_parser.add_argument("--report", type=Path)
    test_parser.add_argument("--overwrite", action="store_true")

    for command, help_text in (
        ("eigrp", "generate classic IPv4 EIGRP CLI after configuration preflight; no packet is modified"),
        ("audit-eigrp", "check saved classic EIGRP configuration; no convergence is simulated"),
        ("audit-dns", "check saved DNS A/CNAME configuration; no queries are sent"),
    ):
        protocol_parser = subparsers.add_parser(command, help=help_text)
        protocol_parser.add_argument("input", type=Path)
        protocol_parser.add_argument("--report", type=Path)
        protocol_parser.add_argument("--overwrite", action="store_true")
        protocol_parser.add_argument("--json", action="store_true")
        if command == "eigrp":
            protocol_parser.add_argument("--plan", required=True, type=Path)
        if command == "audit-dns":
            protocol_parser.add_argument("--resolve", nargs=2, action="append", default=[], metavar=("CLIENT", "DNS_NAME"))
            protocol_parser.add_argument("--expect", nargs=3, action="append", default=[], metavar=("CLIENT", "DNS_NAME", "IPV4"))
            protocol_parser.add_argument("--web", nargs=3, action="append", default=[], metavar=("CLIENT", "DNS_NAME", "SERVER"))

    inspect_parser = subparsers.add_parser("inspect", help="summarize a .pkt without modifying it")
    inspect_parser.add_argument("input", type=Path)
    inspect_parser.add_argument("--json", action="store_true")

    audit_parser = subparsers.add_parser("audit", help="check cables, IPv4, routing and cloud mappings offline")
    audit_parser.add_argument("input", type=Path)
    audit_parser.add_argument("--between", nargs=2, action="append", default=[], metavar=("SOURCE", "DESTINATION"))
    audit_parser.add_argument("--json", action="store_true")

    configure_parser = subparsers.add_parser("configure", help="apply an explicit JSON configuration plan after audit")
    configure_parser.add_argument("input", type=Path)
    configure_parser.add_argument("output", type=Path)
    configure_parser.add_argument("--plan", required=True, type=Path)
    configure_parser.add_argument("--dry-run", action="store_true")
    configure_parser.add_argument("--overwrite", action="store_true")

    edit_parser = subparsers.add_parser("edit", help="apply guarded edits and verify a new .pkt")
    edit_parser.add_argument("input", type=Path)
    edit_parser.add_argument("output", type=Path)
    edit_parser.add_argument("--ip-prefix", nargs=2, metavar=("OLD", "NEW"))
    edit_parser.add_argument("--expect-ip-count", type=int)
    edit_parser.add_argument("--domain", nargs=2, metavar=("OLD", "NEW"))
    edit_parser.add_argument("--expect-domain-count", type=int)
    edit_parser.add_argument("--heading", nargs=2, metavar=("OLD", "NEW"))
    edit_parser.add_argument("--expect-heading-count", type=int)
    edit_parser.add_argument("--clock-rate", nargs=2, metavar=("OLD", "NEW"))
    edit_parser.add_argument("--expect-clock-count", type=int)
    edit_parser.add_argument("--overwrite", action="store_true")

    count_parser = subparsers.add_parser("count", help="count exact strings in decoded XML")
    count_parser.add_argument("input", type=Path)
    count_parser.add_argument("values", nargs="+")

    decode_parser = subparsers.add_parser("decode", help="decrypt a .pkt to XML")
    decode_parser.add_argument("input", type=Path)
    decode_parser.add_argument("output", type=Path)
    decode_parser.add_argument("--overwrite", action="store_true")

    encode_parser = subparsers.add_parser("encode", help="encrypt XML to a verified .pkt")
    encode_parser.add_argument("input", type=Path)
    encode_parser.add_argument("output", type=Path)
    encode_parser.add_argument("--overwrite", action="store_true")

    create_parser = subparsers.add_parser(
        "create", help="create a router-switch-PC topology without an input .pkt"
    )
    create_parser.add_argument("output", type=Path)
    create_parser.add_argument("--network", required=True, help="IPv4 network in CIDR form")
    create_parser.add_argument("--router", default="R1")
    create_parser.add_argument("--switch", default="S1")
    create_parser.add_argument("--pc", default="PC1")
    create_parser.add_argument("--overwrite", action="store_true")

    subparsers.add_parser("self-test", help="run an in-memory crypto round trip")
    return parser


def print_human(report: dict) -> None:
    print(json.dumps(report, indent=2, sort_keys=True))


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "test":
            from pkt_tester import main as tester_main
            tester_args = [str(args.input)] if args.input is not None else []
            for pair in args.between:
                tester_args.extend(["--between", *pair])
            for option in ("resolve", "expect", "web"):
                for query in getattr(args, option):
                    tester_args.extend(["--" + option, *query])
            if args.report is not None:
                tester_args.extend(["--report", str(args.report)])
            if args.overwrite:
                tester_args.append("--overwrite")
            return tester_main(tester_args)
        elif args.command in {"eigrp", "audit-eigrp", "audit-dns"}:
            report = protocol_report(args)
            print(json.dumps(report, indent=2, sort_keys=True))
            return {"passed": 0, "failed": 1, "partial": 2}[report["status"]]
        elif args.command == "inspect":
            report = inspect_packet(args.input)
        elif args.command == "plan":
            from pkt_plan import plan_ipv4
            report = plan_ipv4(args.base, args.lan, args.transit)
        elif args.command == "audit":
            from pkt_network import audit
            report = audit(load_packet(args.input)[2], args.between)
            report["path"] = str(args.input.resolve())
            print(json.dumps(report, indent=2, sort_keys=True))
            return 2 if report["errors"] else 0
        elif args.command == "configure":
            from pkt_network import configure
            report = configure(args)
        elif args.command == "count":
            report = count_xml_values(args.input, args.values)
        elif args.command == "edit":
            report = edit_packet(args)
        elif args.command == "decode":
            report = decode_packet(args.input, args.output, args.overwrite)
        elif args.command == "encode":
            report = encode_packet(args.input, args.output, args.overwrite)
        elif args.command == "build":
            from pkt_build import build
            report = build(args)
        elif args.command == "rewrite":
            from pkt_rewrite import rewrite
            report = rewrite(args)
        elif args.command == "create":
            report = create_packet(args)
        else:
            report = self_test()
        if getattr(args, "json", False) or args.command != "inspect":
            print(json.dumps(report, sort_keys=True))
        else:
            print_human(report)
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1 if args.command in {"eigrp", "audit-eigrp", "audit-dns"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
