"""Build declared PT5 copper topologies directly; never launch Packet Tracer."""
import ipaddress
import math
import re
import time
import xml.etree.ElementTree as ET

import pkt_tool
from pkt_build_schema import (CLUSTER, PORT_BASE, STRIDE, TEMPLATE, clone_device, physical_layout, prototype_root)
from pkt_fast_io import encode, read_plan, require_distinct, write_verified
from pkt_network import audit, physical_ports, put


def connect(root: ET.Element, devices: list[ET.Element], links: list[dict]) -> None:
    by_name = {node.findtext("ENGINE/NAME"): index for index, node in enumerate(devices)}
    occupied = set()
    for entry in links:
        if not isinstance(entry, dict) or set(entry) != {"from", "to"}:
            raise ValueError("Link requires from/to [device, actual_port] endpoints")
        endpoints = [entry[key] for key in ("from", "to")]
        if any(not isinstance(endpoint, list) or len(endpoint) != 2 for endpoint in endpoints):
            raise ValueError("Link endpoint must be [device, actual_port]")
        if endpoints[0][0] == endpoints[1][0]:
            raise ValueError("Self-links are not supported")
        port_nodes, indexes, ordinals = [], [], []
        for name, port_name in endpoints:
            if name not in by_name or (name, port_name) in occupied:
                raise ValueError("Unknown device or already-connected port")
            index = by_name[name]
            ports = physical_ports(devices[index])
            if port_name not in ports or ports[port_name].findtext("TYPE") not in {"eCopperFastEthernet", "eCopperEthernet"}:
                raise ValueError(f"Unknown/unsupported copper port {name}/{port_name}")
            if devices[index].findtext("ENGINE/TYPE") != "Switch" and not ports[port_name].findtext("IP"):
                raise ValueError("Connected router/PC copper ports must have explicit addresses")
            occupied.add((name, port_name))
            put(ports[port_name], "POWER", "true")
            port_nodes.append(ports[port_name])
            indexes.append(index)
            ordinals.append(list(ports).index(port_name))
        link = ET.SubElement(root.find("NETWORK/LINKS"), "LINK")
        put(link, "TYPE", "eCopper")
        cable = ET.SubElement(link, "CABLE")
        fields = [("LENGTH", 0), ("FROM", indexes[0]), ("PORT", endpoints[0][1]),
                  ("TO", indexes[1]), ("PORT", endpoints[1][1])]
        for direction, index, ordinal in zip(("FROM", "TO"), indexes, ordinals):
            fields += [(direction + "_DEVICE_MEM_ADDR", devices[index].findtext("WORKSPACE/LOGICAL/DEV_ADDR")),
                       (direction + "_PORT_MEM_ADDR", PORT_BASE + index * STRIDE + ordinal)]
        fields.append(("TYPE", "eStraightThrough" if port_nodes[0].findtext("PINS") != port_nodes[1].findtext("PINS") else "eCrossOver"))
        for key, value in fields:
            ET.SubElement(cable, key).text = str(value)


def save_config(device: ET.Element, spec: dict) -> None:
    if spec["kind"] == "Pc":
        if spec.get("routing") or spec.get("routes"):
            raise ValueError("Pc cannot contain router configuration")
        return
    lines = ["version 12.2", "hostname " + spec["name"], "!"]
    for name, port in physical_ports(device).items():
        lines += ["interface " + name]
        if spec["kind"] == "Router":
            lines += [f" ip address {port.findtext('IP')} {port.findtext('SUBNET')}" if port.findtext("IP") else " no ip address"]
        lines += [" no shutdown" if port.findtext("POWER") == "true" else " shutdown", "!"]
    routing = spec.get("routing", {})
    if not isinstance(routing, dict) or spec["kind"] == "Switch" and (routing or spec.get("routes")):
        raise ValueError("routing must be a router-only process-to-commands object")
    for process, commands in routing.items():
        if not isinstance(process, str) or not re.fullmatch(r"(?:eigrp|ospf|bgp) [1-9][0-9]{0,4}|rip", process):
            raise ValueError("Process must be classic eigrp/ospf/bgp NUMBER or rip")
        if process != "rip" and int(process.split()[1]) > 65535:
            raise ValueError("Routing process number exceeds supported classic range")
        if not isinstance(commands, list):
            raise ValueError("Routing commands must be a list")
        lines.append("router " + process)
        for command in commands:
            if not isinstance(command, str) or not command.strip() or any(c in command for c in "\r\n"):
                raise ValueError("Each routing command must be one nonempty line")
            if command.strip().split()[0] in {"interface", "router", "end", "exit", "copy", "write", "configure", "hostname"}:
                raise ValueError("CLI context/save commands are not routing subcommands")
            lines.append(" " + command.strip())
        lines.append("!")
    for route in spec.get("routes", []):
        if not isinstance(route, dict) or set(route) != {"network", "next_hop"}:
            raise ValueError("Static route requires only network and next_hop")
        network = ipaddress.IPv4Network(route["network"], strict=True)
        lines.append(f"ip route {network.network_address} {network.netmask} {ipaddress.IPv4Address(route['next_hop'])}")
    lines.append("end")
    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
        container = device.find("ENGINE/" + tag)
        if container is None:
            raise ValueError("Specimen lacks saved configuration fields")
        container.clear()
        for line in lines:
            ET.SubElement(container, "LINE").text = line


def build_root(plan: dict) -> tuple[ET.Element, dict]:
    if set(plan) - {"devices", "links", "tests", "notes"}:
        raise ValueError("Unknown build plan field")
    specs, links = plan.get("devices"), plan.get("links")
    if not isinstance(specs, list) or not specs or not isinstance(links, list) or not links:
        raise ValueError("Build requires nonempty device and link lists")
    names = []
    root, prototypes = prototype_root()
    devices = []
    for index, spec in enumerate(specs):
        if not isinstance(spec, dict) or set(spec) - {"name", "kind", "interfaces", "gateway", "x", "y", "routing", "routes"}:
            raise ValueError("Unknown device plan field")
        if spec.get("kind") not in {"Router", "Switch", "Pc"}:
            raise ValueError("Builder supports inspected Router-PT, Switch-PT and PC-PT only; other media require compatible specimens")
        name = pkt_tool.device_name(spec.get("name", ""))
        for key in ("x", "y"):
            if key in spec and (type(spec[key]) not in {int, float} or not math.isfinite(spec[key])):
                raise ValueError("Coordinates must be finite numbers")
        if name in names:
            raise ValueError("Device names must be unique")
        names.append(name)
        devices.append(clone_device(prototypes[spec["kind"]], spec, index))
    root.find("NETWORK/DEVICES").extend(devices)
    put(root.find("NETWORK"), "DESCRIPTION", "Direct file-only topology; saved configuration, not runtime-tested")
    connect(root, devices, links)
    for device, spec in zip(devices, specs):
        save_config(device, spec)
    physical_layout(root, specs)
    for index, note in enumerate(plan.get("notes", [])):
        if not isinstance(note, dict) or set(note) != {"x", "y", "text"} or not isinstance(note["text"], str):
            raise ValueError("Note requires x, y and text")
        if any(type(note[key]) not in {int, float} or not math.isfinite(note[key]) for key in ("x", "y")):
            raise ValueError("Note coordinates must be finite numbers")
        node = ET.SubElement(root.find("PHYSICALWORKSPACE/NOTES"), "NOTE")
        for key, value in (("X", note["x"]), ("Y", note["y"]), ("Z", 40000 + index),
                           ("TEXT", note["text"]), ("NOTECLUSTERID", CLUSTER)):
            put(node, key, value)
    checked = audit(root, plan.get("tests", []))
    if checked["errors"] or any(path.get("status") == "failed" for path in checked["paths"]):
        raise ValueError("Build failed physical/address/path audit: " + str(checked["errors"]) + str(checked["paths"]))
    return root, checked


def build(args) -> dict:
    started = time.perf_counter()
    require_distinct(args.output, args.plan, TEMPLATE)
    plan = read_plan(args.plan)
    root, checked = build_root(plan)
    report = {"status": "preview" if args.dry_run else "saved", "devices": len(plan["devices"]),
              "links": len(plan["links"]), "configuration_audit": checked,
              "routing_validation": "Explicit supplied process text only; no IOS parser/DUAL/OSPF/BGP execution",
              "simulation_tested": False, "convergence_tested": False}
    if not args.dry_run:
        xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        report.update(write_verified(args.output, encode(xml, args.container), xml, args.overwrite))
    report["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return report
