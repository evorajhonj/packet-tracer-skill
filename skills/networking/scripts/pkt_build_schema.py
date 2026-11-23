"""Clone inspected PT5 Router/Switch/Pc specimens with fresh identities."""
from copy import deepcopy
import gzip
import ipaddress
from pathlib import Path
import xml.etree.ElementTree as ET

import pkt_tool
from pkt_network import physical_ports, put, address

TEMPLATE = Path(__file__).resolve().parent.parent / "templates/three-node-packet-tracer-5.xml.gz"
CLUSTER = "1-1"
STRIDE = 100
MAC_BASE = 0x020000020000
DEVICE_BASE = 610000000
LOGICAL_BASE = 620000000
PORT_BASE = 630000000


def clear_activity(root: ET.Element) -> None:
    for path in ("LINES", "RECTANGLES", "ELLIPSES", "CEPS", "SCRIPT_MODULE", "USER_PROFILE", "MULTIUSER",
                 "OPTIONS/RECENT_FILES", "OPTIONS/MULTIUSER/MU_PEERS", "GEOVIEW_GRAPHICSITEMS"):
        node = root.find(path)
        if node is not None:
            node.clear()
    for node in root.findall(".//MU_PASSWORD"):
        node.text = ""
    notes = root.find("PHYSICALWORKSPACE/NOTES")
    if notes is not None:
        notes.clear()


def prototype_root() -> tuple[ET.Element, dict[str, ET.Element]]:
    root = pkt_tool.parse_xml(gzip.decompress(TEMPLATE.read_bytes()))
    prototypes = {node.findtext("ENGINE/TYPE"): deepcopy(node) for node in root.findall("NETWORK/DEVICES/DEVICE")}
    clear_activity(root)
    root.find("NETWORK/DEVICES").clear()
    root.find("NETWORK/LINKS").clear()
    return root, prototypes


def clone_device(prototype: ET.Element, spec: dict, index: int) -> ET.Element:
    device = deepcopy(prototype)
    engine = device.find("ENGINE")
    name = pkt_tool.device_name(spec["name"])
    for key in ("NAME", "SYS_NAME", "DESCRIPTION"):
        if engine.find(key) is not None:
            put(engine, key, name)
    put(engine, "POWER", "true")
    if engine.find("BUILD_IN_ADDR") is not None:
        value = f"{MAC_BASE + index * STRIDE + STRIDE - 1:012X}"
        put(engine, "BUILD_IN_ADDR", ".".join(value[n:n + 4] for n in (0, 4, 8)))
    logical = device.find("WORKSPACE/LOGICAL")
    for key, value in (("X", spec.get("x", 160 + index * 180)), ("Y", spec.get("y", 240)),
                       ("MEM_ADDR", LOGICAL_BASE + index), ("DEV_ADDR", DEVICE_BASE + index), ("DEVCLUSTERID", CLUSTER)):
        put(logical, key, value)
    shelf = "Table" if spec["kind"] == "Pc" else "Rack"
    put(device, "WORKSPACE/PHYSICAL", f"Intercity,Home City,Corporate Office,Main Wiring Closet,{shelf},{name}")
    for ordinal, port in enumerate(device.findall("ENGINE/MODULE//PORT")):
        mac = f"{MAC_BASE + index * STRIDE + ordinal:012X}"
        for key in ("MACADDRESS", "BIA"):
            if port.find(key) is not None:
                put(port, key, ".".join(mac[n:n + 4] for n in (0, 4, 8)))
        for key in ("IP", "SUBNET", "DESCRIPTION", "IPV6_LINK_LOCAL", "IPV6_DEFAULT_LINK_LOCAL"):
            if port.find(key) is not None:
                put(port, key, "")
        put(port, "POWER", "false")
    configure_addresses(device, spec)
    for node in device.iter():
        if any(key in node.tag.upper() for key in ("PASSWORD", "SECRET")):
            node.text = ""
    for key in ("SYS_CONTACT", "SYS_LOCATION"):
        if engine.find(key) is not None:
            put(engine, key, "")
    return device


def configure_addresses(device: ET.Element, spec: dict) -> None:
    ports = physical_ports(device)
    interfaces = spec.get("interfaces", {})
    if not isinstance(interfaces, dict):
        raise ValueError("interfaces must map actual port names to IPv4/CIDR strings")
    for name, cidr in interfaces.items():
        if name not in ports or ports[name].findtext("TYPE") not in {"eCopperFastEthernet", "eCopperEthernet"}:
            raise ValueError(f"Unknown/unsupported copper port: {name}")
        if spec["kind"] == "Switch":
            raise ValueError("Switch L3/SVI configuration is outside the copper builder")
        interface = ipaddress.IPv4Interface(cidr)
        address(str(interface.ip), str(interface.network.netmask))
        for key, value in (("IP", interface.ip), ("SUBNET", interface.network.netmask), ("POWER", "true")):
            put(ports[name], key, value)
    if spec["kind"] == "Pc":
        if set(interfaces) != {"FastEthernet"} or not spec.get("gateway"):
            raise ValueError("Pc requires FastEthernet address and gateway")
        put(device.find("ENGINE"), "GATEWAY", ipaddress.IPv4Address(spec["gateway"]))
        put(device.find("ENGINE/DNS_CLIENT"), "SERVER_IP", "0.0.0.0")
        device.find("ENGINE/DHCP_CLIENT/PORT_DATA_MAP").clear()
        for parent in device.findall("ENGINE/FILE_MANAGER//FILES"):
            for leaf in list(parent):
                if leaf.tag == "FILE" and leaf.get("class") == "CFile":
                    parent.remove(leaf)


def physical_layout(root: ET.Element, specs: list[dict]) -> None:
    workspace = root.find("PHYSICALWORKSPACE")
    nodes = workspace.findall(".//NODE")
    device_leaf = deepcopy(next(node for node in nodes if node.findtext("TYPE") == "6"))
    scopes = {name: next(node for node in nodes if node.findtext("NAME") == name)
              for name in ("Intercity", "Home City", "Corporate Office", "Main Wiring Closet", "Rack", "Table")}
    hierarchy = (("Intercity", ("Home City",)), ("Home City", ("Corporate Office",)),
                 ("Corporate Office", ("Main Wiring Closet",)), ("Main Wiring Closet", ("Rack", "Table")),
                 ("Rack", ()), ("Table", ()))
    for name, children in hierarchy:
        scopes[name].find("CHILDREN").clear()
        scopes[name].find("CHILDREN").extend(scopes[child] for child in children)
    put(workspace, "HOMERACK", "Intercity,Home City,Corporate Office,Main Wiring Closet")
    for index, spec in enumerate(specs):
        leaf = deepcopy(device_leaf)
        put(leaf, "NAME", spec["name"])
        put(leaf, "X", index * 75)
        put(leaf, "Y", 0)
        leaf.find("CHILDREN").clear()
        scopes["Table" if spec["kind"] == "Pc" else "Rack"].find("CHILDREN").append(leaf)
