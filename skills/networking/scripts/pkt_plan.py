"""Deterministic VLSM planning only; this module does not configure devices."""
import ipaddress as ip
import re


_FORBIDDEN = tuple(ip.IPv4Network(value) for value in (
    "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
))


def plan_ipv4(base: str, lans: list[str], transits: list[str]) -> dict:
    """Allocate NAME=PC_COUNT LANs and NAME /30 router links within base.

    LANs reserve the first usable address for a gateway and the next addresses
    for exactly PC_COUNT PCs. Largest blocks are assigned first, with names as
    a deterministic tie breaker. Actual model, port and runtime support remain
    outside this address plan.
    """
    if not isinstance(base, str) or "/" not in base:
        raise ValueError("Base must be an explicit IPv4 network in CIDR form")
    try:
        network = ip.IPv4Network(base.strip(), strict=True)
    except (ValueError, TypeError) as error:
        raise ValueError("Base must be an aligned IPv4 network in CIDR form") from error
    if any(network.overlaps(block) for block in _FORBIDDEN):
        raise ValueError("Base overlaps unspecified, loopback, multicast or reserved address space")
    if not isinstance(lans, list) or not isinstance(transits, list):
        raise ValueError("LANs and transits must be lists of request strings")
    if not lans and not transits:
        raise ValueError("Request at least one LAN or transit")

    requests, names = [], set()

    def register(name, kind, size, count=None):
        name = name.strip()
        if not name or "=" in name or any(char in name for char in "\r\n\t"):
            raise ValueError("Every request needs a nonempty, single-line name")
        key = name.casefold()
        if key in names:
            raise ValueError(f"Duplicate allocation name: {name}")
        names.add(key)
        requests.append((size, name, kind, count))

    for entry in lans:
        if not isinstance(entry, str) or entry.count("=") != 1:
            raise ValueError("LAN request must use NAME=PC_COUNT")
        name, value = entry.split("=")
        value = value.strip()
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError("PC count must be a positive integer")
        try:
            count = int(value)
        except ValueError as error:
            raise ValueError("PC count is too large") from error
        if not 1 <= count <= 2 ** 32 - 3:
            raise ValueError("PC count must be positive and fit IPv4 address space")
        size = 1 << (count + 2).bit_length()
        register(name, "lan", size, count)
    for entry in transits:
        if not isinstance(entry, str):
            raise ValueError("Transit request must be a name string")
        register(entry, "transit", 4)

    allocations = []
    cursor = int(network.network_address)
    end = int(network.broadcast_address) + 1
    for size, name, kind, count in sorted(requests, key=lambda item: (-item[0], item[1].casefold())):
        start = ((cursor + size - 1) // size) * size
        if size > network.num_addresses or start + size > end:
            raise ValueError(f"Insufficient space in {network} for {name}")
        prefix = 32 - (size.bit_length() - 1)
        subnet = ip.IPv4Network((start, prefix))
        first, last = ip.IPv4Address(start + 1), ip.IPv4Address(start + size - 2)
        entry = {
            "name": name,
            "kind": kind,
            "network": str(subnet),
            "prefix_length": prefix,
            "subnet_mask": str(subnet.netmask),
            "network_address": str(subnet.network_address),
            "broadcast_address": str(subnet.broadcast_address),
            "usable_range": {"first": str(first), "last": str(last)},
            "usable_capacity": size - 2,
        }
        if kind == "lan":
            entry.update({
                "pc_count": count,
                "gateway": str(first),
                "pc_range": {"first": str(ip.IPv4Address(start + 2)),
                             "last": str(ip.IPv4Address(start + 1 + count))},
            })
        else:
            entry["router_addresses"] = [str(first), str(last)]
        allocations.append(entry)
        cursor = start + size
    allocated = sum(2 ** (32 - entry["prefix_length"]) for entry in allocations)
    return {
        "base_network": str(network),
        "allocations": allocations,
        "allocated_addresses": allocated,
        "remaining_addresses": network.num_addresses - allocated,
        "scope": "IPv4 address planning only; models, ports, routes and services are not configured or tested",
        "simulation_tested": False,
    }
