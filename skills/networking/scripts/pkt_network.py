"""Conservative offline IPv4 checks and explicit configuration for PT5 labs.

This models untagged Ethernet, static routing, direct serial, Frame Relay PVCs,
and DSL/cable bridging. It never sends packets or proves runtime connectivity.
"""
from collections import defaultdict
from dataclasses import dataclass
import ipaddress as ip
import json
import xml.etree.ElementTree as ET


PREFIXES = {
    "eCopperEthernet": "Ethernet", "eCopperFastEthernet": "FastEthernet",
    "eFiberFastEthernet": "FastEthernet", "eCopperGigabitEthernet": "GigabitEthernet",
    "eFiberGigabitEthernet": "GigabitEthernet", "eSerial": "Serial",
    "eModem": "Modem", "eCopperCoaxial": "Coaxial",
}
HOSTS = {"Pc", "Server", "Laptop", "Printer"}
MODEMS = {"DslModem", "CableModem"}


def put(parent, tag, value):
    node = parent.find(tag)
    if node is None:
        node = ET.SubElement(parent, tag)
    node.text = str(value)


def blocks(device, tag="RUNNINGCONFIG"):
    result, current = {}, None
    for node in device.findall("ENGINE/" + tag + "/LINE"):
        line = (node.text or "").strip()
        if line.startswith("interface "):
            current = line.split()[1]
            result[current] = []
        elif line == "!" or line == "end" or (line and not (node.text or "").startswith(" ")):
            current = None
        elif current:
            result[current].append(line)
    return result


def physical_ports(device):
    kind = device.findtext("ENGINE/TYPE")
    model = device.find("ENGINE/TYPE").get("model", "")
    if kind in {"Router", "Switch"} and model not in {"Router-PT", "Switch-PT"}:
        return {}  # Fixed/nested chassis numbering must be supplied by a known schema.
    result = {}
    for slot, node in enumerate(device.findall("ENGINE/MODULE/SLOT")):
        port = node.find("MODULE/PORT")
        if port is None:
            continue
        prefix = PREFIXES.get(port.findtext("TYPE"))
        if not prefix:
            continue
        if kind == "Router":
            name = f"{prefix}{slot}/0"
        elif kind == "Switch":
            name = f"{prefix}{slot}/1"
        elif kind == "Cloud":
            name = f"{prefix}{slot}"
        elif kind in MODEMS:
            name = f"Port {slot}"
        elif kind in HOSTS:
            name = prefix
        else:
            continue
        result[name] = port
    return result


def address(value, mask):
    addr = ip.IPv4Interface(f"{value}/{mask}")
    if addr.network.prefixlen < 31 and addr.ip in {addr.network.network_address, addr.network.broadcast_address}:
        raise ValueError("IP is a network or broadcast address")
    if addr.ip.is_multicast or addr.ip.is_unspecified or addr.ip.is_loopback or int(addr.ip) >> 24 == 0 or int(addr.ip) >= int(ip.IPv4Address("240.0.0.0")):
        raise ValueError("IP is not a unicast host address")
    return addr


@dataclass
class Interface:
    device: int
    name: str
    address: ip.IPv4Interface
    enabled: bool
    dlci: str = ""

    @property
    def key(self):
        return self.device, self.name


class Components:
    def __init__(self):
        self.parents = {}

    def find(self, key):
        self.parents.setdefault(key, key)
        if self.parents[key] != key:
            self.parents[key] = self.find(self.parents[key])
        return self.parents[key]

    def join(self, a, b):
        self.parents[self.find(a)] = self.find(b)

    def same(self, a, b):
        return self.find(a) == self.find(b)


def audit(root, between=()):
    errors, warnings = [], []

    def issue(code, message, warning=False):
        target = warnings if warning else errors
        item = {"code": code, "message": message}
        if item not in target:
            target.append(item)

    devices = root.findall("NETWORK/DEVICES/DEVICE")
    if not devices:
        issue("network.empty", "No supported NETWORK/DEVICES layout found")
    names = [d.findtext("ENGINE/NAME", "") for d in devices]
    kinds = [d.findtext("ENGINE/TYPE", "") for d in devices]
    ports = [physical_ports(d) for d in devices]
    config = [blocks(d) for d in devices]
    graph = Components()
    interfaces, routes, neighbors = [], defaultdict(list), {}
    routing_enabled = {}
    uncertain = False
    saved_drift = False
    for tag in ["NAME", "WORKSPACE/LOGICAL/DEV_ADDR", "WORKSPACE/LOGICAL/MEM_ADDR"]:
        values = names if tag == "NAME" else [d.findtext(tag, "") for d in devices]
        if len(values) != len(set(values)) or "" in values:
            issue("device.identity", f"Missing or duplicate device {tag}")
    macs = [n.text for d in devices for n in d.findall(".//MACADDRESS") if n.text]
    if len(macs) != len(set(macs)):
        issue("device.mac", "Duplicate physical MAC addresses")

    for i, d in enumerate(devices):
        if not ports[i]:
            issue("unsupported.device", f"{names[i]}: interface schema is not supported; inspect its actual model", True)
            uncertain = True
        if kinds[i] == "Router":
            lines = [n.text.strip() for n in d.findall("ENGINE/RUNNINGCONFIG/LINE") if n.text]
            saved_lines = [n.text.strip() for n in d.findall("ENGINE/STARTUPCONFIG/LINE") if n.text]
            def forwarding_enabled(commands):
                flags = [s for s in commands if s in {"ip routing", "no ip routing"}]
                return not flags or flags[-1] == "ip routing"
            routing_enabled[i] = forwarding_enabled(lines)
            if not routing_enabled[i]:
                issue("router.routing-disabled", f"{names[i]}: no ip routing disables transit forwarding")
            if forwarding_enabled(lines) != forwarding_enabled(saved_lines) or sorted(s for s in lines if s.startswith("ip route ")) != sorted(s for s in saved_lines if s.startswith("ip route ")):
                issue("config.startup-routes", f"{names[i]}: static routes or routing state differ between running and startup config", True)
                saved_drift = True
            if any(s.startswith(("router ", "ip policy", "ip vrf", "vrf forwarding ", "ip access-group", "ip nat ", "ip verify ", "ppp authentication ", "ppp chap ", "ppp pap ", "encapsulation dot1Q ", "ip unnumbered ")) or s.startswith("ip address ") and s.endswith(" secondary") for s in lines):
                issue("unsupported.routing", f"{names[i]}: dynamic routing, VRF, NAT, policy, PPP authentication or special interfaces need separate checks", True)
                uncertain = True
            for name, commands in config[i].items():
                parent = name.split(".")[0]
                if parent not in ports[i]:
                    issue("unsupported.interface", f"{names[i]} {name}: no known physical port", True)
                    uncertain = True
                    continue
                physical = ports[i][parent]
                enabled = d.findtext("ENGINE/POWER") != "false" and physical.findtext("POWER") != "false" and "shutdown" not in commands and "shutdown" not in config[i].get(parent, [])
                ipv4 = next((s.split()[2:4] for s in commands if s.startswith("ip address ") and len(s.split()) >= 4), None)
                if ipv4:
                    try:
                        addr = address(*ipv4)
                        dlci = next((s.split()[2] for s in commands if s.startswith("frame-relay interface-dlci ")), "")
                        interfaces.append(Interface(i, name, addr, enabled, dlci))
                        if "." not in name and (physical.findtext("IP", "") != str(addr.ip) or physical.findtext("SUBNET", "") != str(addr.network.netmask)):
                            issue("interface.state", f"{names[i]} {name}: XML IP/mask differs from running configuration")
                    except (ValueError, IndexError) as error:
                        issue("ip.invalid", f"{names[i]} {name}: {error}")
            startup = blocks(d, "STARTUPCONFIG")
            for name, commands in config[i].items():
                significant = lambda ls: [s for s in ls if s.startswith(("ip address ", "encapsulation ", "frame-relay interface-dlci ")) or s == "shutdown"]
                if significant(commands) != significant(startup.get(name, [])):
                    issue("config.startup", f"{names[i]} {name}: saved startup configuration differs", True)
                    saved_drift = True
            for line in lines:
                if not line.startswith("ip route "):
                    continue
                pieces = line.split()
                try:
                    network = ip.IPv4Network(f"{pieces[2]}/{pieces[3]}", strict=True)
                    next_hop = ip.IPv4Address(pieces[4])
                    if len(pieces) not in {5, 6} or (len(pieces) == 6 and not pieces[5].isdigit()):
                        raise ValueError("Route options require separate validation")
                    distance = int(pieces[5]) if len(pieces) == 6 else 1
                    if not 1 <= distance <= 255:
                        raise ValueError("Invalid administrative distance")
                    routes[i].append((network, next_hop, distance))
                except (ValueError, IndexError):
                    issue("unsupported.route", f"{names[i]}: unsupported/invalid route: {line}", True)
                    uncertain = True
        elif kinds[i] in HOSTS:
            for name, physical in ports[i].items():
                value = physical.findtext("IP", "")
                if not value or value == "0.0.0.0":
                    issue("host.address", f"{names[i]} {name}: no static IPv4 address; DHCP is not modeled", True)
                    uncertain = True
                    continue
                try:
                    interfaces.append(Interface(i, name, address(value, physical.findtext("SUBNET", "")), d.findtext("ENGINE/POWER") != "false" and physical.findtext("POWER") != "false"))
                except ValueError as error:
                    issue("ip.invalid", f"{names[i]} {name}: {error}")

    used, serial_links = set(), []
    for link in root.findall("NETWORK/LINKS/LINK"):
        cable = link.find("CABLE")
        if cable is None:
            issue("unsupported.link", "Non-cable link needs separate inspection", True)
            uncertain = True
            continue
        try:
            a, b = int(cable.findtext("FROM")), int(cable.findtext("TO"))
            pa, pb = [p.text for p in cable.findall("PORT")]
            if not 0 <= a < len(devices) or not 0 <= b < len(devices):
                raise ValueError("Endpoint index outside device list")
        except (ValueError, TypeError):
            issue("link.endpoint", "Invalid cable endpoint indexes/port count")
            continue
        label = f"{names[a]} {pa} -> {names[b]} {pb}"
        keys = [(a, pa), (b, pb)]
        for key in keys:
            if key in used:
                issue("link.occupied", f"{label}: port is connected more than once")
            used.add(key)
        valid = True
        for idx, name, direction in [(a, pa, "FROM"), (b, pb, "TO")]:
            if cable.findtext(direction + "_DEVICE_MEM_ADDR") != devices[idx].findtext("WORKSPACE/LOGICAL/DEV_ADDR"):
                issue("link.identity", f"{label}: stale {direction} device reference")
                valid = False
            if name not in ports[idx]:
                issue("link.port", f"{label}: {names[idx]} has no supported port {name}", not bool(ports[idx]))
                if not ports[idx]:
                    uncertain = True
                valid = False
            elif ports[idx][name].findtext("POWER") == "false" or devices[idx].findtext("ENGINE/POWER") == "false":
                issue("link.shutdown", f"{label}: connected device/port is powered off")
                valid = False
            elif kinds[idx] in {"Router", "Switch"} and "shutdown" in config[idx].get(name, []):
                issue("link.shutdown", f"{label}: connected interface is administratively shut down")
                valid = False
        if not valid:
            continue
        neighbors[(a, pa)] = (b, pb)
        neighbors[(b, pb)] = (a, pa)
        media = link.findtext("TYPE")
        types = [ports[idx][name].findtext("TYPE", "") for idx, name in keys]
        compatible = {
            "eCopper": all(t.startswith("eCopper") and "Ethernet" in t for t in types),
            "eFiber": all(t.startswith("eFiber") and "Ethernet" in t for t in types),
            "eSerial": types == ["eSerial", "eSerial"],
            "ePhoneLine": types == ["eModem", "eModem"],
            "eCoaxial": types == ["eCopperCoaxial", "eCopperCoaxial"],
        }
        if media not in compatible:
            issue("unsupported.link", f"{label}: {media} is not modeled", True)
            uncertain = True
            continue
        if not compatible[media]:
            issue("link.media", f"{label}: {media} does not match endpoint port types")
            continue
        if media == "eCopper":
            # Older modular PT devices have fixed pin roles; auto-MDI-X is not assumed.
            straight = ports[a][pa].findtext("PINS") != ports[b][pb].findtext("PINS")
            expected = "eStraightThrough" if straight else "eCrossOver"
            if cable.findtext("TYPE") != expected:
                issue("link.copper", f"{label}: use {expected} for these fixed port pin roles")
        if media == "eSerial":
            try:
                dce = int(cable.findtext("DCEDEV"))
                dce_port = cable.findtext("DCEPORT")
                if (dce, dce_port) not in keys:
                    raise ValueError()
                if int(ports[dce][dce_port].findtext("CLOCKRATE", "0")) <= 0:
                    issue("serial.clock", f"{label}: DCE clock rate must be positive")
            except (ValueError, TypeError):
                issue("serial.dce", f"{label}: DCE endpoint is missing or invalid")
            serial_links.append(keys)
            if "Cloud" in {kinds[a], kinds[b]}:
                continue  # PVCs join DLCI-specific logical interfaces, not all serial ports.
            enc = [next((c.split()[1] for c in config[i].get(p, []) if c.startswith("encapsulation ")), "hdlc") for i, p in keys]
            if enc[0] != enc[1]:
                issue("serial.encapsulation", f"{label}: serial encapsulation differs")
                continue
            if "frame-relay" in enc:
                issue("unsupported.serial", f"{label}: direct Frame Relay needs switch-specific configuration", True)
                uncertain = True
                continue
        graph.join(*keys)

    for i, d in enumerate(devices):
        if kinds[i] in MODEMS or kinds[i] == "Switch":
            if kinds[i] == "Switch":
                commands = [n.text.strip() for n in d.findall("ENGINE/RUNNINGCONFIG/LINE") if n.text]
                if any(s.startswith(("switchport access vlan ", "switchport mode trunk", "switchport trunk ")) and s != "switchport access vlan 1" for s in commands):
                    issue("unsupported.vlan", f"{names[i]}: VLAN/trunk forwarding is not modeled", True)
                    uncertain = True
                    continue
            live = [(i, p) for p, n in ports[i].items() if n.findtext("POWER") != "false" and "shutdown" not in config[i].get(p, [])]
            for key in live[1:]:
                graph.join(live[0], key)
        if kinds[i] != "Cloud":
            continue
        mapped = set()
        for mapping in d.findall("ENGINE/MODEM_CONNECTIONS/CONNECTION"):
            p, q = mapping.findtext("PORT1"), mapping.findtext("PORT2")
            if p not in ports[i] or q not in ports[i]:
                issue("cloud.port", f"{names[i]}: mapping references missing ports {p}, {q}")
                continue
            mapped.update([p, q])
            pt, qt = ports[i][p].findtext("TYPE"), ports[i][q].findtext("TYPE")
            if pt not in {"eModem", "eCopperCoaxial"} or qt != "eCopperEthernet":
                issue("cloud.mapping", f"{names[i]}: use modem/Ethernet for DSL or coaxial/Ethernet for cable")
                continue
            provider = next((n.findtext("DSL") for n in d.findall("ENGINE/MODEM_CONNECTION_TYPES/CONNECTION_TYPE") if n.findtext("PORT") == q), "true")
            if provider != ("true" if pt == "eModem" else "false"):
                issue("cloud.provider", f"{names[i]} {q}: provider network does not match {p}")
                continue
            if any(ports[i][n].findtext("POWER") == "false" for n in [p, q]):
                issue("cloud.shutdown", f"{names[i]}: mapped port is powered off")
                continue
            graph.join((i, p), (i, q))
        for p in ports[i]:
            if (i, p) in used and ports[i][p].findtext("TYPE") in {"eCopperEthernet", "eModem", "eCopperCoaxial"} and p not in mapped:
                issue("cloud.unmapped", f"{names[i]} {p}: no DSL/cable forwarding mapping; two Ethernet links alone cannot bridge")
        serial_mapped = set()
        for connection in d.findall("ENGINE/CONNECTIONS/CONNECTION"):
            cloud_ports = [n.text for n in connection.findall("PORT")]
            dlcis = [n.text for n in connection.findall("DLCI")]
            labels = [n.text for n in connection.findall("SUBLINK")]
            if len(cloud_ports) != 2 or len(dlcis) != 2 or len(labels) != 2:
                issue("fr.mapping", f"{names[i]}: incomplete Frame Relay connection")
                continue
            serial_mapped.update(cloud_ports)
            endpoints = []
            for p, dlci, label in zip(cloud_ports, dlcis, labels):
                cp = ports[i].get(p)
                peer = neighbors.get((i, p))
                sublinks = [] if cp is None else cp.findall("SUBLINKS/SUBLINK")
                if not any(n.findtext("DLCI") == dlci and n.findtext("NAME") == label for n in sublinks):
                    issue("fr.dlci", f"{names[i]} {p}: mapping does not match configured sublink {dlci}/{label}")
                if peer is None or kinds[peer[0]] != "Router":
                    issue("fr.peer", f"{names[i]} {p}: no supported connected router")
                    continue
                router, rp = peer
                if "encapsulation frame-relay" not in config[router].get(rp, []):
                    issue("fr.encapsulation", f"{names[router]} {rp}: needs Frame Relay encapsulation")
                hits = [n for n in interfaces if n.device == router and n.name.split(".")[0] == rp and n.dlci == dlci and n.enabled]
                if len(hits) != 1:
                    issue("fr.dlci", f"{names[router]} {rp}: needs one enabled IP subinterface for DLCI {dlci}")
                else:
                    endpoints.append(hits[0].key)
                lmi = next((s.split()[2].lower() for s in config[router].get(rp, []) if s.startswith("frame-relay lmi-type ")), "cisco")
                cloud_lmi = "" if cp is None else cp.findtext("LMITYPE", "eLmiCisco").replace("eLmi", "").lower()
                if lmi != cloud_lmi:
                    issue("fr.lmi", f"{names[router]} {rp}: LMI {lmi} differs from {names[i]} {p} ({cloud_lmi})")
            if len(endpoints) == 2:
                graph.join(*endpoints)
        for p, n in ports[i].items():
            if n.findtext("TYPE") == "eSerial" and (i, p) in used and p not in serial_mapped:
                issue("fr.unmapped", f"{names[i]} {p}: connected serial port has no Frame Relay PVC mapping")

    active = [n for n in interfaces if n.enabled]
    for n in interfaces:
        if n.address.ip.is_link_local:
            issue("unsupported.link-local", f"{names[n.device]} {n.name}: link-local IPv4 is not modeled for routed paths", True)
            uncertain = True
        if kinds[n.device] in HOSTS and n.address.network.prefixlen >= 31:
            issue("ip.host-prefix", f"{names[n.device]}: /31 and /32 are not ordinary host LAN prefixes")
        if kinds[n.device] == "Router" and n.address.network.prefixlen >= 31:
            parent = n.name.split(".")[0]
            peer = neighbors.get((n.device, parent))
            direct_router_link = peer is not None and kinds[peer[0]] == "Router"
            header = next((x.text.strip() for x in devices[n.device].findall("ENGINE/RUNNINGCONFIG/LINE") if x.text and x.text.strip().startswith("interface " + n.name + " ")), "")
            if n.address.network.prefixlen == 32 or not (direct_router_link or n.dlci and "point-to-point" in header):
                issue("unsupported.ip-prefix", f"{names[n.device]} {n.name}: special prefix needs a verified point-to-point/loopback design", True)
                uncertain = True
    if not interfaces:
        issue("unsupported.addressing", "No modeled IPv4 interfaces; only wiring can be inspected", True)
        uncertain = True
    for i, name in used:
        if kinds[i] == "Router" and ports[i].get(name) is not None and not any(n.device == i and n.name.split(".")[0] == name for n in interfaces):
            issue("interface.address", f"{names[i]} {name}: connected routed port has no modeled IPv4 address/subinterface")
    for pos, a in enumerate(active):
        for b in active[pos + 1:]:
            if a.address.ip == b.address.ip:
                issue("ip.duplicate", f"{names[a.device]} {a.name} and {names[b.device]} {b.name} share {a.address.ip}")
            if a.device == b.device and a.address.network.overlaps(b.address.network):
                issue("ip.overlap", f"{names[a.device]}: {a.name} and {b.name} use overlapping subnets")
            elif graph.same(a.key, b.key) and a.address.network != b.address.network:
                issue("ip.link-subnet", f"{names[a.device]} {a.name} and {names[b.device]} {b.name} share a link but disagree on subnet")

    def adjacent(interface, next_hop):
        return [n for n in active if n.address.ip == next_hop and n.device != interface.device and graph.same(interface.key, n.key) and n.address.ip in interface.address.network and interface.address.ip in n.address.network]

    for router, entries in routes.items():
        local = [n for n in active if n.device == router]
        grouped = defaultdict(list)
        for network, next_hop, distance in entries:
            if distance == 255:
                issue("route.inactive", f"{names[router]} route {network}: AD 255 is never installed", True)
                continue
            grouped[network].append((distance, next_hop))
            if not any(adjacent(n, next_hop) for n in local):
                if not any(next_hop in n.address.network for n in local) and any(next_hop in other for other, _, ad in entries if other != network and ad < 255):
                    issue("unsupported.route-recursion", f"{names[router]} route {network}: next hop needs recursive route resolution", True)
                    uncertain = True
                else:
                    issue("route.next-hop", f"{names[router]} route {network}: next hop {next_hop} is not an enabled adjacent IP")
        if any(len({hop for ad, hop in candidates if ad == min(x[0] for x in candidates)}) > 1 for candidates in grouped.values()):
            issue("unsupported.ecmp", f"{names[router]}: multiple static next hops for a prefix require runtime checks", True)
            uncertain = True
    for n in active:
        if kinds[n.device] not in HOSTS:
            continue
        gateway = devices[n.device].findtext("ENGINE/GATEWAY", "")
        try:
            gateway = ip.IPv4Address(gateway)
            if gateway.is_unspecified:
                raise ValueError()
        except ValueError:
            issue("host.gateway", f"{names[n.device]}: no IPv4 gateway; remote networks need one", True)
            continue
        peers = adjacent(n, gateway)
        if not any(kinds[p.device] == "Router" for p in peers):
            issue("host.gateway", f"{names[n.device]}: gateway {gateway} is not an enabled router on its LAN")

    def trace(source, destination):
        source_ip = next((n for n in active if n.device == source), None)
        dest_ip = next((n for n in active if n.device == destination), None)
        path = [names[source]]
        if source_ip is None or dest_ip is None:
            return False, path, "Source or destination has no enabled modeled IPv4 interface"
        if kinds[source] not in HOSTS or kinds[destination] not in HOSTS:
            return False, path, "Named path checks require two hosts"
        if dest_ip.address.ip in source_ip.address.network:
            return graph.same(source_ip.key, dest_ip.key), path + [names[destination]], "Host LAN forwarding"
        try:
            gateway = ip.IPv4Address(devices[source].findtext("ENGINE/GATEWAY", ""))
        except ValueError:
            return False, path, "Missing host gateway"
        peers = [n for n in adjacent(source_ip, gateway) if kinds[n.device] == "Router"]
        if len(peers) != 1:
            return False, path, "Gateway is not uniquely reachable"
        router, seen = peers[0].device, set()
        while router not in seen:
            seen.add(router)
            path.append(names[router])
            if not routing_enabled.get(router, False):
                return False, path, "Router IPv4 forwarding is disabled"
            local = [n for n in active if n.device == router]
            connected = [n for n in local if dest_ip.address.ip in n.address.network]
            candidates = [(n.address.network.prefixlen, 0, "connected", n) for n in connected]
            candidates += [(net.prefixlen, ad, "static", hop) for net, hop, ad in routes[router] if dest_ip.address.ip in net and ad < 255 and any(adjacent(n, hop) for n in local)]
            if not candidates:
                return False, path, "No modeled route to destination"
            _, _, kind, chosen = max(candidates, key=lambda item: (item[0], -item[1]))
            if kind == "connected":
                return graph.same(chosen.key, dest_ip.key), path + [names[destination]], "Connected destination LAN"
            peers = [p for n in local for p in adjacent(n, chosen) if kinds[p.device] == "Router"]
            if len(peers) != 1:
                return False, path, "Static next hop is not uniquely reachable"
            router = peers[0].device
        return False, path, "Static routing loop"

    paths = []
    for pair in between:
        if len(pair) != 2 or any(n not in names for n in pair):
            issue("path.device", f"Unknown source/destination pair {pair}")
            continue
        for source, dest in [pair, list(reversed(pair))]:
            success, path, reason = trace(names.index(source), names.index(dest))
            status = "modeled" if success else "unknown" if uncertain else "failed"
            paths.append({"source": source, "destination": dest, "status": status, "routers_and_hosts": path, "reason": reason})
            if status == "failed":
                issue("path.unreachable", f"{source} -> {dest}: {reason}")
    return {
        "status": "failed" if errors else "partial" if uncertain or saved_drift else "passed",
        "errors": errors, "warnings": warnings,
        "interfaces": [{"device": names[n.device], "interface": n.name, "address": str(n.address), "enabled": n.enabled, "dlci": n.dlci} for n in interfaces],
        "paths": paths, "simulation_tested": False,
        "routes": [{"device": names[i], "network": str(net), "next_hop": str(hop), "distance": ad, "distance_usable": ad < 255} for i, entries in routes.items() for net, hop, ad in entries],
        "scope": "Offline IPv4/static-routing and supported layer-2 consistency only",
    }


def edit_interface_config(device, name, addr=None, enabled=True, clock=None):
    for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
        container = device.find("ENGINE/" + tag)
        if container is None:
            raise ValueError(f"Router has no {tag}")
        nodes = list(container)
        start = next((i for i, n in enumerate(nodes) if (n.text or "").strip().startswith("interface ") and (n.text or "").split()[1] == name), None)
        commands = []
        if start is not None:
            stop = start + 1
            while stop < len(nodes) and (nodes[stop].text or "").startswith(" "):
                commands.append(nodes[stop].text.strip())
                stop += 1
            for n in nodes[start:stop]:
                container.remove(n)
        else:
            start = next((i for i, n in enumerate(nodes) if (n.text or "").strip() == "end"), len(nodes))
        commands = [s for s in commands if s not in {"shutdown", "no shutdown"} and not (addr is not None and s.startswith(("ip address ", "no ip address"))) and not (clock is not None and s.startswith("clock rate "))]
        if addr is not None:
            commands.append(f"ip address {addr.ip} {addr.network.netmask}")
        commands.append("no shutdown" if enabled else "shutdown")
        if clock is not None:
            commands.append(f"clock rate {clock}")
        for offset, line in enumerate(["interface " + name] + [" " + s for s in commands] + ["!"]):
            node = ET.Element("LINE")
            node.text = line
            container.insert(start + offset, node)


def configure(args):
    import pkt_tool
    source, output = args.input.resolve(), args.output.resolve()
    if source == output:
        raise ValueError("Configure requires a distinct output path; original is preserved")
    original, _, root = pkt_tool.load_packet(source)
    plan = json.loads(args.plan.read_text(encoding="utf-8-sig"))
    if not isinstance(plan, dict) or set(plan) - {"interfaces", "hosts", "routes", "clouds", "clocks", "tests"}:
        raise ValueError("Plan must contain only interfaces, hosts, routes, clouds, clocks, tests")
    devices = root.findall("NETWORK/DEVICES/DEVICE")
    index = {d.findtext("ENGINE/NAME"): i for i, d in enumerate(devices)}
    if len(index) != len(devices):
        raise ValueError("Device names must be unique")
    changes = []

    def target(name):
        if name not in index:
            raise ValueError(f"Unknown device {name}")
        return devices[index[name]]

    for entry in plan.get("interfaces", []):
        if set(entry) - {"device", "port", "address", "enabled"}:
            raise ValueError("Unsupported interface plan field")
        d = target(entry["device"])
        if d.findtext("ENGINE/TYPE") != "Router":
            raise ValueError("Use hosts section for PC addresses")
        name = entry["port"]
        physical = physical_ports(d).get(name.split(".")[0])
        if physical is None:
            raise ValueError(f"{entry['device']}: unknown port {name}")
        if "." in name and name not in blocks(d):
            raise ValueError("Creating subinterfaces needs a validated template; configure only existing ones")
        if not isinstance(entry.get("enabled", True), bool):
            raise ValueError("enabled must be true or false")
        addr = ip.IPv4Interface(entry["address"])
        address(str(addr.ip), str(addr.network.netmask))
        edit_interface_config(d, name, addr, entry.get("enabled", True))
        if "." not in name:
            put(physical, "IP", addr.ip)
            put(physical, "SUBNET", addr.network.netmask)
            put(physical, "POWER", str(entry.get("enabled", True)).lower())
        elif entry.get("enabled", True):
            put(physical, "POWER", "true")
            edit_interface_config(d, name.split(".")[0], enabled=True)
        changes.append(f"{entry['device']} {name} = {addr}")

    for name, entry in plan.get("hosts", {}).items():
        if set(entry) - {"port", "address", "gateway", "dns"}:
            raise ValueError("Unsupported host plan field")
        d = target(name)
        if d.findtext("ENGINE/TYPE") not in HOSTS:
            raise ValueError(f"{name} is not a supported host")
        p = physical_ports(d).get(entry.get("port", "FastEthernet"))
        if p is None:
            raise ValueError(f"{name}: unknown host port")
        addr = ip.IPv4Interface(entry["address"])
        address(str(addr.ip), str(addr.network.netmask))
        gateway = ip.IPv4Address(entry["gateway"])
        if gateway not in addr.network or gateway == addr.ip:
            raise ValueError(f"{name}: gateway must be a different host IP in the host subnet")
        put(p, "IP", addr.ip)
        put(p, "SUBNET", addr.network.netmask)
        put(p, "POWER", "true")
        put(d.find("ENGINE"), "GATEWAY", gateway)
        if "dns" in entry:
            dns = d.find("ENGINE/DNS_CLIENT")
            if dns is None:
                raise ValueError(f"{name}: no DNS client node")
            put(dns, "SERVER_IP", ip.IPv4Address(entry["dns"]))
        changes.append(f"{name} = {addr}, gateway {gateway}")

    for name, entries in plan.get("routes", {}).items():
        d = target(name)
        if d.findtext("ENGINE/TYPE") != "Router":
            raise ValueError(f"{name} is not a router")
        lines = []
        for entry in entries:
            if not {"network", "next_hop"} <= set(entry) or set(entry) - {"network", "next_hop", "distance"}:
                raise ValueError("Static route requires network, next_hop and optional distance")
            net = ip.IPv4Network(entry["network"], strict=True)
            hop = ip.IPv4Address(entry["next_hop"])
            distance = entry.get("distance", 1)
            if type(distance) is not int or not 1 <= distance <= 255:
                raise ValueError("Static route distance must be an integer from 1 through 255")
            suffix = "" if distance == 1 else f" {distance}"
            lines.append(f"ip route {net.network_address} {net.netmask} {hop}{suffix}")
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG"]:
            c = d.find("ENGINE/" + tag)
            for n in list(c):
                if (n.text or "").strip().startswith("ip route "):
                    c.remove(n)
            pos = next((i for i, n in enumerate(c) if (n.text or "").strip() in {"end"} or (n.text or "").strip().startswith("line ")), len(c))
            for offset, line in enumerate(lines):
                node = ET.Element("LINE")
                node.text = line
                c.insert(pos + offset, node)
        changes.append(f"{name}: replace IPv4 static routes with {len(lines)} entries")

    for name, entry in plan.get("clouds", {}).items():
        if set(entry) != {"dsl"}:
            raise ValueError("Cloud configuration currently supports dsl mappings only")
        d = target(name)
        if d.findtext("ENGINE/TYPE") != "Cloud":
            raise ValueError(f"{name} is not a Cloud")
        ports = physical_ports(d)
        for mapping in entry["dsl"]:
            if set(mapping) != {"modem", "ethernet"}:
                raise ValueError("DSL mapping requires modem and ethernet")
            modem, ethernet = mapping["modem"], mapping["ethernet"]
            if modem not in ports or ethernet not in ports or ports[modem].findtext("TYPE") != "eModem" or ports[ethernet].findtext("TYPE") != "eCopperEthernet":
                raise ValueError(f"{name}: invalid DSL port pair")
            for p in [modem, ethernet]:
                put(ports[p], "POWER", "true")
            c = d.find("ENGINE/MODEM_CONNECTIONS")
            if c is None:
                raise ValueError(f"{name}: no modem connection container")
            for node in list(c):
                if node.findtext("PORT1") == modem:
                    c.remove(node)
            connection = ET.SubElement(c, "CONNECTION")
            put(connection, "PORT1", modem)
            put(connection, "PORT2", ethernet)
            c = d.find("ENGINE/MODEM_CONNECTION_TYPES")
            if c is None:
                raise ValueError(f"{name}: no provider network container")
            for node in list(c):
                if node.findtext("PORT") == ethernet:
                    c.remove(node)
            provider = ET.SubElement(c, "CONNECTION_TYPE")
            put(provider, "PORT", ethernet)
            put(provider, "DSL", "true")
            changes.append(f"{name}: DSL {modem} -> {ethernet}")

    for entry in plan.get("clocks", []):
        if set(entry) != {"device", "port", "rate"}:
            raise ValueError("Clock entry requires device, port and rate")
        d = target(entry["device"])
        p = physical_ports(d).get(entry["port"])
        idx = index[entry["device"]]
        if p is None or p.findtext("TYPE") != "eSerial":
            raise ValueError("Clock target must be an existing serial port")
        if not any(l.findtext("TYPE") == "eSerial" and l.findtext("CABLE/DCEDEV") == str(idx) and l.findtext("CABLE/DCEPORT") == entry["port"] for l in root.findall("NETWORK/LINKS/LINK")):
            raise ValueError(f"{entry['device']} {entry['port']} is not the DCE endpoint")
        if type(entry["rate"]) is not int or entry["rate"] not in {1200, 2400, 4800, 9600, 19200, 38400, 56000, 64000, 72000, 125000, 128000, 148000, 250000, 500000, 800000, 1000000, 1300000, 2000000, 4000000}:
            raise ValueError("Use a supported integer clock rate")
        put(p, "CLOCKRATE", entry["rate"])
        if d.findtext("ENGINE/TYPE") == "Router":
            edit_interface_config(d, entry["port"], enabled=p.findtext("POWER") != "false", clock=entry["rate"])
        changes.append(f"{entry['device']} {entry['port']}: DCE clock {entry['rate']}")

    if not changes:
        raise ValueError("Plan contains no configuration changes")
    host_subnets = {str(ip.IPv4Interface(p.findtext("IP") + "/" + (p.findtext("SUBNET") or "")).network)
                    for d in devices if d.findtext("ENGINE/TYPE") in HOSTS
                    for p in physical_ports(d).values() if p.findtext("IP") not in {None, "", "0.0.0.0"}}
    if len(host_subnets) > 1 and not plan.get("tests"):
        raise ValueError("A plan spanning host subnets requires tests: [[source_host, destination_host]]")
    report = audit(root, plan.get("tests", []))
    if report["errors"] or report["status"] == "partial":
        raise ValueError("Refusing unverified configuration: " + json.dumps(report))
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    packed = pkt_tool.pack_xml(xml)
    if pkt_tool.decrypt_pkt(packed) != xml:
        raise ValueError("Packet round trip failed")
    if source.read_bytes() != original:
        raise ValueError("Source changed during configuration")
    if not args.dry_run:
        pkt_tool.atomic_write(output, packed, overwrite=args.overwrite)
        if pkt_tool.decrypt_pkt(output.read_bytes()) != xml:
            raise ValueError("Saved output round trip failed")
    return {"input": str(source), "output": str(output), "dry_run": args.dry_run, "changes": changes, "source_unchanged": source.read_bytes() == original, "round_trip_verified": True, "network_audit": report, "simulation_tested": False}
