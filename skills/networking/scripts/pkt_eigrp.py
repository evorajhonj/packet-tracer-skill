"""Classic IPv4 EIGRP CLI planning and configuration-only preflight.

No packets are mutated and no DUAL, neighbor establishment or learned routes
are simulated. Interface schemas remain the conservative pkt_network subset.
"""
import ipaddress as ip
import re
from collections import Counter

from pkt_network import Components, address, blocks, physical_ports


DEFAULT_K = [1, 0, 1, 0, 0]
VERIFICATION = ["show ip protocols", "show ip eigrp interfaces", "show ip eigrp neighbors",
                "show ip eigrp topology", "show ip route eigrp", "show ip interface brief",
                "show running-config", "show startup-config"]


def _report():
    return {"status": "partial", "errors": [], "warnings": [], "routers": {},
            "neighbor_expectations": [], "simulation_tested": False,
            "convergence_tested": False, "learned_routes_modeled": False,
            "scope": "Classic IPv4 EIGRP configuration preflight only; no dynamic forwarding or DUAL simulation"}


def _issue(report, code, message, warning=False):
    entry = {"code": code, "message": message}
    target = report["warnings" if warning else "errors"]
    if entry not in target:
        target.append(entry)


def _finish(report):
    report["status"] = "failed" if report["errors"] else "partial" if report["warnings"] else "passed"
    if report["errors"] and "commands" in report:
        report["commands"] = {}
    return report


def _as(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Classic EIGRP AS must be an integer from 1 through 65535")
    return value


def _k_values(values):
    if not isinstance(values, list) or len(values) != 5 or any(type(value) is not int or not 0 <= value <= 255 for value in values):
        raise ValueError("EIGRP k_values must contain five integers from 0 through 255")
    return list(values)


def _selection(value):
    if isinstance(value, str):
        if "/" not in value:
            raise ValueError("Plan network strings require an explicit CIDR prefix")
        network = ip.IPv4Network(value, strict=True)
        return str(network.network_address), str(network.hostmask)
    if not isinstance(value, dict) or set(value) != {"address", "wildcard"}:
        raise ValueError("Network selection requires CIDR or {address, wildcard}")
    addr, wild = ip.IPv4Address(value["address"]), ip.IPv4Address(value["wildcard"])
    number = int(wild)
    if number & (number + 1):
        raise ValueError("Only contiguous inverse-subnet wildcard masks are supported")
    return str(ip.IPv4Address(int(addr) & (0xffffffff ^ number))), str(wild)


def _matches(addr, selection):
    network, wildcard = map(ip.IPv4Address, selection)
    mask = 0xffffffff ^ int(wildcard)
    return int(addr) & mask == int(network) & mask


def _network_line(tokens):
    if len(tokens) == 3:
        return _selection({"address": tokens[1], "wildcard": tokens[2]})
    if len(tokens) == 2:
        value = ip.IPv4Address(tokens[1])
        octet = int(value) >> 24
        if octet >= 224:
            raise ValueError("Classful EIGRP network is not unicast")
        prefix = 8 if octet < 128 else 16 if octet < 192 else 24
        network = ip.IPv4Network(f"{value}/{prefix}", strict=False)
        return str(network.network_address), str(network.hostmask)
    raise ValueError("Unsupported EIGRP network statement")


def _processes(device, tag, report, router):
    raw, current = [], None
    for node in device.findall("ENGINE/" + tag + "/LINE"):
        original = node.text or ""
        line = original.strip()
        if line.startswith("router eigrp "):
            current = {"header": line, "lines": []}
            raw.append(current)
        elif not line or line in {"!", "end"} or not original.startswith(" "):
            current = None
        elif current is not None:
            current["lines"].append(line)
    result = {}
    for item in raw:
        try:
            tokens = item["header"].split()
            if len(tokens) != 3 or not tokens[2].isdigit():
                _issue(report, "eigrp.unsupported-mode", f"{router}: named EIGRP or address-family mode is outside coverage", True)
                continue
            asn = _as(int(tokens[2]))
        except ValueError as error:
            _issue(report, "eigrp.as", f"{router}: {error}")
            continue
        if asn in result:
            _issue(report, "eigrp.duplicate-process", f"{router}: duplicate classic AS {asn}")
            continue
        process = {"as": asn, "networks": [], "k_values": list(DEFAULT_K),
                   "passive_default": False, "passive_overrides": {}, "auto_summary": None}
        for line in item["lines"]:
            tokens = line.split()
            try:
                if line.startswith("network "):
                    process["networks"].append(_network_line(tokens))
                elif line.startswith("metric weights "):
                    if len(tokens) != 8 or tokens[2] != "0":
                        raise ValueError("Only classic ToS 0 and K1 through K5 are covered")
                    process["k_values"] = _k_values([int(value) for value in tokens[3:]])
                elif line == "no metric weights":
                    process["k_values"] = list(DEFAULT_K)
                elif line in {"auto-summary", "no auto-summary"}:
                    process["auto_summary"] = line == "auto-summary"
                elif line.startswith(("passive-interface ", "no passive-interface ")):
                    passive = not line.startswith("no ")
                    value = "".join(tokens[1:] if passive else tokens[2:])
                    if value == "default":
                        process["passive_default"] = passive
                    elif re.fullmatch(r"(?:Ethernet|FastEthernet|GigabitEthernet|Serial)\d+/\d+(?:\.\d+)?", value):
                        process["passive_overrides"][value] = passive
                    else:
                        _issue(report, "eigrp.unsupported-passive", f"{router}: passive interface syntax is outside known physical schemas", True)
                elif line in {"eigrp log-neighbor-changes", "no eigrp log-neighbor-changes", "exit"}:
                    continue
                else:
                    _issue(report, "eigrp.unsupported-command", f"{router}: an EIGRP process feature needs separate runtime validation", True)
            except (ValueError, TypeError) as error:
                unsupported = str(error) in {"Only contiguous inverse-subnet wildcard masks are supported",
                                             "Only classic ToS 0 and K1 through K5 are covered"}
                code = "eigrp.unsupported-selection" if unsupported else "eigrp.network" if line.startswith("network ") else "eigrp.metric"
                _issue(report, code, f"{router}: {error}", warning=unsupported)
        process["networks"] = sorted(set(process["networks"]))
        # Never expose process text: unsupported lines could include sensitive data.
        process["_signature"] = tuple(sorted(item["lines"]))
        result[asn] = process
    return result


def _interfaces(device, report, router):
    ports, config = physical_ports(device), blocks(device)
    result = {}
    if not ports:
        _issue(report, "eigrp.unsupported-model", f"{router}: chassis interface schema is not supported", True)
    for name, commands in config.items():
        ip_lines = [line for line in commands if line.startswith("ip address ")]
        if not ip_lines:
            continue
        parent = name.split(".")[0]
        if parent not in ports:
            _issue(report, "eigrp.unsupported-interface", f"{router}: virtual or unknown interfaces need separate validation", True)
            continue
        if len(ip_lines) != 1 or len(ip_lines[0].split()) != 4:
            _issue(report, "eigrp.unsupported-address", f"{router} {name}: only one primary static IPv4 address is covered", True)
            continue
        try:
            addr = address(*ip_lines[0].split()[2:])
        except ValueError as error:
            _issue(report, "eigrp.interface-address", f"{router} {name}: {error}")
            continue
        enabled = (device.findtext("ENGINE/POWER") != "false" and ports[parent].findtext("POWER") != "false"
                   and "shutdown" not in commands and "shutdown" not in config.get(parent, []))
        result[name] = {"address": addr, "enabled": enabled, "parent": parent}
        if "." not in name and (ports[parent].findtext("IP") != str(addr.ip) or ports[parent].findtext("SUBNET") != str(addr.network.netmask)):
            _issue(report, "eigrp.interface-state", f"{router} {name}: physical IPv4 fields differ from running configuration")
    lines = [(node.text or "").strip() for node in device.findall("ENGINE/RUNNINGCONFIG/LINE")]
    if "no ip routing" in lines:
        _issue(report, "eigrp.ip-routing-disabled", f"{router}: global IPv4 routing is explicitly disabled")
    if any(line.startswith(("ip vrf", "ip nat ", "ip policy", "ip access-group ", "ip authentication ",
                            "tunnel ", "router bgp ", "router ospf ", "router rip")) for line in lines):
        _issue(report, "eigrp.unsupported-context", f"{router}: policies, authentication, tunnels or other dynamic protocols need separate validation", True)
    return result


def _devices(root):
    devices = root.findall("NETWORK/DEVICES/DEVICE")
    names = [device.findtext("ENGINE/NAME", "") for device in devices]
    if not devices or "" in names or len(names) != len(set(names)):
        raise ValueError("Topology requires devices with unique actual names")
    return devices, names


def _layer2(root, devices, report):
    """Join only links satisfying the known pkt_network saved-wiring rules."""
    graph = Components()
    ports = [physical_ports(device) for device in devices]
    for index, device in enumerate(devices):
        if device.findtext("ENGINE/TYPE") != "Switch":
            continue
        lines = [(node.text or "").strip() for node in device.findall("ENGINE/RUNNINGCONFIG/LINE")]
        if any(line.startswith(("vlan ", "switchport ", "interface Vlan")) for line in lines):
            _issue(report, "eigrp.unsupported-layer2", "VLAN/trunk or managed switching adjacency requires separate validation", True)
            continue
        configuration = blocks(device)
        enabled = [name for name, port in ports[index].items() if "Ethernet" in name and port.findtext("POWER") != "false"
                   and device.findtext("ENGINE/POWER") != "false" and "shutdown" not in configuration.get(name, [])]
        for name in enabled[1:]:
            graph.join((index, enabled[0]), (index, name))
    cables = []
    occupied = Counter()
    for link in root.findall("NETWORK/LINKS/LINK"):
        cable = link.find("CABLE")
        if cable is None:
            continue
        try:
            a, b = int(cable.findtext("FROM")), int(cable.findtext("TO"))
            pa, pb = [node.text for node in cable.findall("PORT")]
            if not 0 <= a < len(devices) or not 0 <= b < len(devices) or pa not in ports[a] or pb not in ports[b]:
                raise ValueError()
        except (ValueError, TypeError):
            _issue(report, "eigrp.link-schema", "A cable endpoint is not covered by actual known interface schemas", True)
            continue
        cables.append((link, cable, a, b, pa, pb))
        occupied.update([(a, pa), (b, pb)])
    for link, cable, a, b, pa, pb in cables:
        keys = [(a, pa), (b, pb)]
        if any(occupied[key] != 1 for key in keys):
            _issue(report, "eigrp.link-occupied", "A physical interface appears on multiple saved cable endpoints")
            continue
        if any(not devices[index].findtext("WORKSPACE/LOGICAL/DEV_ADDR") or
               cable.findtext(direction + "_DEVICE_MEM_ADDR") != devices[index].findtext("WORKSPACE/LOGICAL/DEV_ADDR")
               for index, direction in [(a, "FROM"), (b, "TO")]):
            _issue(report, "eigrp.link-identity", "A cable has missing or stale saved device identity references")
            continue
        if any(device.findtext("ENGINE/POWER") == "false" for device in [devices[a], devices[b]]) or any(port.findtext("POWER") == "false" for port in [ports[a][pa], ports[b][pb]]):
            continue
        if any("shutdown" in blocks(devices[index]).get(port, []) for index, port in [(a, pa), (b, pb)]):
            continue
        kind = link.findtext("TYPE")
        if kind in {"eCopper", "eFiber"} and "Ethernet" in pa and "Ethernet" in pb:
            allowed = ({"eCopperEthernet", "eCopperFastEthernet", "eCopperGigabitEthernet"} if kind == "eCopper"
                       else {"eFiberFastEthernet", "eFiberGigabitEthernet"})
            cable_type = cable.findtext("TYPE")
            if not all(port.findtext("TYPE") in allowed for port in [ports[a][pa], ports[b][pb]]) or (kind == "eCopper" and cable_type not in {"eCrossOver", "eStraightThrough"}):
                _issue(report, "eigrp.unsupported-media", "A link's media or copper cable type does not match known port schemas", True)
                continue
            if kind == "eCopper":
                pins = [ports[index][port].findtext("PINS") for index, port in keys]
                if any(value not in {"true", "false"} for value in pins):
                    _issue(report, "eigrp.unsupported-pins", "A copper endpoint's saved pin role is unknown", True)
                    continue
                expected = "eStraightThrough" if pins[0] != pins[1] else "eCrossOver"
                if cable_type != expected:
                    _issue(report, "eigrp.link-copper", "A copper cable type disagrees with the saved endpoint pin roles")
                    continue
            graph.join((a, pa), (b, pb))
        elif kind == "eSerial" and all(devices[index].findtext("ENGINE/TYPE") == "Router" for index in [a, b]):
            if any(ports[index][port].findtext("TYPE") != "eSerial" for index, port in keys):
                _issue(report, "eigrp.serial-media", "A serial cable does not use two known serial ports")
                continue
            try:
                dce, dce_port = int(cable.findtext("DCEDEV")), cable.findtext("DCEPORT")
                if (dce, dce_port) not in keys:
                    raise ValueError()
            except (ValueError, TypeError):
                _issue(report, "eigrp.serial-dce", "A direct serial cable has no valid saved DCE endpoint")
                continue
            try:
                if int(ports[dce][dce_port].findtext("CLOCKRATE", "0")) <= 0:
                    raise ValueError()
            except (ValueError, TypeError):
                _issue(report, "eigrp.serial-clock", "The saved DCE serial endpoint has no positive clock rate")
                continue
            configurations = [blocks(devices[index]).get(port, []) for index, port in [(a, pa), (b, pb)]]
            encapsulations = [next((line.split()[1] for line in commands if line.startswith("encapsulation ")), "hdlc") for commands in configurations]
            if encapsulations[0] != encapsulations[1]:
                _issue(report, "eigrp.serial-encapsulation", "Direct serial EIGRP candidates disagree on saved encapsulation")
                continue
            if encapsulations[0] not in {"hdlc", "ppp"}:
                _issue(report, "eigrp.unsupported-serial", "This serial encapsulation requires separate adjacency validation", True)
                continue
            graph.join((a, pa), (b, pb))
    return graph


def _neighbors(root, devices, names, memberships, report):
    graph = _layer2(root, devices, report)
    items = [(router, member) for router, members in memberships.items() for member in members]
    verified_active = set()
    for position, (a_name, a) in enumerate(items):
        for b_name, b in items[position + 1:]:
            if a_name == b_name:
                continue
            adjacent = graph.same((names.index(a_name), a["parent"]), (names.index(b_name), b["parent"]))
            same_subnet = a["ip"] in b["subnet"] and b["ip"] in a["subnet"]
            if not adjacent and not same_subnet:
                continue
            if adjacent and not same_subnet:
                _issue(report, "eigrp.transit-subnet", f"{a_name} {a['interface']} and {b_name} {b['interface']}: linked router interfaces disagree on IPv4 subnet")
                continue
            expectation = {"router": a_name, "interface": a["interface"], "peer": b_name, "peer_interface": b["interface"],
                           "supported_link_path_found": adjacent, "neighbor_established": False,
                           "status": "configuration_candidate" if adjacent else "potential_unverified"}
            report["neighbor_expectations"].append(expectation)
            if not adjacent:
                _issue(report, "eigrp.potential-peer", f"{a_name} and {b_name}: matching subnets alone do not prove adjacency; cloud/virtual or disconnected links need runtime checks", True)
                continue
            if a["ip"] == b["ip"]:
                _issue(report, "eigrp.duplicate-transit-ip", f"{a_name} and {b_name}: linked router interfaces use the same IPv4 address")
            if a["as"] != b["as"]:
                _issue(report, "eigrp.peer-as", f"{a_name} and {b_name}: linked EIGRP candidates have different AS numbers")
            if a["k_values"] != b["k_values"]:
                _issue(report, "eigrp.peer-k", f"{a_name} and {b_name}: linked EIGRP candidates have different K values")
            if a["passive"] or b["passive"]:
                _issue(report, "eigrp.passive-transit", f"{a_name} and {b_name}: router-to-router transit interface is passive")
            else:
                verified_active.update([(a_name, a["interface"]), (b_name, b["interface"])])
    for name, member in items:
        if not member["passive"] and (name, member["interface"]) not in verified_active:
            _issue(report, "eigrp.no-verified-peer", f"{name} {member['interface']}: no supported physically adjacent planned EIGRP peer was established by configuration checks", True)


def _member(name, info, process, passive):
    addr = info["address"]
    return {"interface": name, "parent": info["parent"], "ip": addr.ip, "subnet": addr.network,
            "as": process["as"], "k_values": process["k_values"], "passive": passive}


def _public_members(members):
    return [{"interface": member["interface"], "address": f"{member['ip']}/{member['subnet'].prefixlen}",
             "passive": member["passive"], "as": member["as"]} for member in members]


def plan_eigrp(root, plan):
    """Return validated classic commands without changing the XML or packet."""
    if not isinstance(plan, dict) or set(plan) != {"routers"} or not isinstance(plan["routers"], dict) or not plan["routers"]:
        raise ValueError("EIGRP plan requires a nonempty routers object")
    devices, names = _devices(root)
    report = _report()
    report["commands"] = {}
    report["verification_commands"] = {}
    memberships = {}
    for router, entry in sorted(plan["routers"].items()):
        if router not in names or devices[names.index(router)].findtext("ENGINE/TYPE") != "Router":
            raise ValueError(f"Unknown actual router: {router}")
        if not isinstance(entry, dict) or not {"as", "networks", "interfaces"} <= set(entry) or set(entry) - {"as", "networks", "interfaces", "k_values", "replace_process"}:
            raise ValueError("Router plan needs as, networks, interfaces and optional k_values/replace_process")
        asn, k = _as(entry["as"]), _k_values(entry.get("k_values", list(DEFAULT_K)))
        if type(entry.get("replace_process", False)) is not bool:
            raise ValueError("replace_process must be true or false")
        if not isinstance(entry["networks"], list) or not entry["networks"] or not isinstance(entry["interfaces"], list) or not entry["interfaces"]:
            raise ValueError("Networks and interfaces must be nonempty lists")
        selections = [_selection(value) for value in entry["networks"]]
        if len(selections) != len(set(selections)):
            raise ValueError("Duplicate EIGRP network selection")
        device = devices[names.index(router)]
        actual = _interfaces(device, report, router)
        declared = {}
        for interface in entry["interfaces"]:
            if not isinstance(interface, dict) or set(interface) != {"name", "passive"} or type(interface["passive"]) is not bool:
                raise ValueError("Every interface needs an actual name and boolean passive")
            name = interface["name"]
            if not isinstance(name, str) or name not in actual:
                raise ValueError(f"{router}: interface is not an actual supported configured IPv4 port")
            if name in declared:
                raise ValueError(f"{router}: duplicate interface declaration")
            if not actual[name]["enabled"]:
                raise ValueError(f"{router} {name}: selected interface is disabled")
            declared[name] = interface["passive"]
        selected = {name for name, info in actual.items() if any(_matches(info["address"].ip, selection) for selection in selections)}
        if selected != set(declared):
            raise ValueError(f"{router}: network selectors must match exactly the declared interfaces")
        if any(not any(_matches(info["address"].ip, selection) for info in actual.values()) for selection in selections):
            raise ValueError(f"{router}: a network selector matches no actual IPv4 interface")
        existing = _processes(device, "RUNNINGCONFIG", report, router)
        if set(existing) - {asn}:
            _issue(report, "eigrp.multiple-processes", f"{router}: other EIGRP AS processes require separate membership validation", True)
        if asn in existing and not entry.get("replace_process", False):
            raise ValueError(f"{router}: AS already exists; explicit replace_process is required to rebuild its membership")
        process = {"as": asn, "k_values": k}
        members = [_member(name, actual[name], process, passive) for name, passive in sorted(declared.items())]
        memberships[router] = members
        commands = ["enable", "configure terminal"]
        if asn in existing:
            commands.append(f"no router eigrp {asn}")
        commands += [f"router eigrp {asn}", "no auto-summary", "metric weights 0 " + " ".join(map(str, k))]
        commands += [f"network {network} {wildcard}" for network, wildcard in sorted(selections)]
        commands.append("passive-interface default")
        commands += [f"no passive-interface {name}" for name, passive in sorted(declared.items()) if not passive]
        commands += ["end", "copy running-config startup-config"]
        report["commands"][router] = commands
        report["verification_commands"][router] = list(VERIFICATION)
        report["routers"][router] = {"as": asn, "k_values": k, "no_auto_summary": True,
                                      "memberships": _public_members(members), "replaces_existing_process": asn in existing}
    _neighbors(root, devices, names, memberships, report)
    report["packet_mutated"] = False
    return _finish(report)


def audit_eigrp(root):
    """Read known classic AS/K/network/passive/startup config, not learned routes."""
    report = _report()
    try:
        devices, names = _devices(root)
    except ValueError as error:
        _issue(report, "eigrp.topology", str(error))
        return _finish(report)
    memberships, observed = {}, False
    for device, router in zip(devices, names):
        if device.findtext("ENGINE/TYPE") != "Router":
            continue
        running = _processes(device, "RUNNINGCONFIG", report, router)
        startup = _processes(device, "STARTUPCONFIG", report, router)
        if not running and not startup:
            continue
        observed = True
        if len(running) > 1:
            _issue(report, "eigrp.multiple-processes", f"{router}: multiple EIGRP processes require separate peer-domain validation", True)
        if {asn: process["_signature"] for asn, process in running.items()} != {asn: process["_signature"] for asn, process in startup.items()}:
            _issue(report, "eigrp.startup", f"{router}: saved classic EIGRP process differs from running configuration", True)
        actual = _interfaces(device, report, router)
        members, summaries = [], []
        for process in running.values():
            selected = {name: info for name, info in actual.items() if any(_matches(info["address"].ip, selection) for selection in process["networks"])}
            if not process["networks"]:
                _issue(report, "eigrp.no-networks", f"{router} AS {process['as']}: no interface network selection", True)
            for selection in process["networks"]:
                if not any(_matches(info["address"].ip, selection) for info in actual.values()):
                    _issue(report, "eigrp.unmatched-network", f"{router} AS {process['as']}: a selection matches no known primary interface", True)
            if process["auto_summary"] is not False:
                _issue(report, "eigrp.auto-summary", f"{router} AS {process['as']}: automatic summarization is enabled or platform default is not explicit", True)
            for name in process["passive_overrides"]:
                if name not in actual:
                    _issue(report, "eigrp.passive-interface", f"{router}: passive setting references no known configured IPv4 interface",
                           warning=not bool(physical_ports(device)))
            local = []
            for name, info in selected.items():
                passive = process["passive_overrides"].get(name, process["passive_default"])
                if not info["enabled"]:
                    _issue(report, "eigrp.interface-disabled", f"{router} {name}: selected IPv4 interface is disabled")
                    continue
                local.append(_member(name, info, process, passive))
            members += local
            summaries.append({"as": process["as"], "k_values": process["k_values"],
                              "auto_summary": process["auto_summary"], "memberships": _public_members(local)})
        memberships[router] = members if len(running) == 1 else []
        report["routers"][router] = summaries
    if not observed:
        _issue(report, "eigrp.no-process", "No supported classic IPv4 EIGRP process was found", True)
    _neighbors(root, devices, names, memberships, report)
    report["packet_mutated"] = False
    return _finish(report)
