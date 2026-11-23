"""Read-only PT5 saved DNS configuration checks; no DNS packets are sent.

Only same-server A/CNAME tables are resolved. Delegation, recursion, caches,
transport reachability and browser rendering are deliberately outside scope.
"""
from collections import Counter, defaultdict
import ipaddress as ip
import re

from pkt_network import address, physical_ports


def canonical_name(value):
    """Normalize case and one root dot without guessing search suffixes."""
    if not isinstance(value, str):
        raise ValueError("DNS name must be a string")
    name = value.strip().removesuffix(".").lower()
    if not name or len(name) > 253:
        raise ValueError("Invalid DNS name length")
    # Underscores occur in Cisco's supplied PT5 DNS specimen. Escaped,
    # wildcard and non-ASCII labels need separate schema/feature validation.
    if any(not re.fullmatch(r"[a-z0-9_-]{1,63}", label) for label in name.split(".")):
        raise ValueError("Unsupported or malformed DNS labels")
    return name


def _ipv4(value):
    parsed = ip.IPv4Address(value)
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast or parsed.is_reserved or int(parsed) < 2 ** 24:
        raise ValueError("Not an ordinary IPv4 unicast address")
    return str(parsed)


def _state(value):
    value = (value or "").strip().lower()
    return True if value in {"1", "true"} else False if value in {"0", "false"} else None


def audit_dns(root, queries=()):
    """Audit DNS tables and client settings without changing XML.

    Each query is (client_name, dns_name[, expected_ipv4[, web_server_name]]).
    The optional web target checks its saved IPv4/HTTP state only. It does not
    inspect or return HTML. Expected IPv4 may be None with a web target.
    """
    errors, warnings, results = [], [], []
    devices = root.findall("NETWORK/DEVICES/DEVICE")
    names = [d.findtext("ENGINE/NAME", "") for d in devices]
    server_tables, addresses = {}, defaultdict(list)
    summaries, clients = [], []
    record_count = 0

    def issue(code, message, warning=False, device=None, record=None):
        item = {"code": code, "message": message}
        if device is not None:
            item["device_index"] = device
        if record is not None:
            item["record_index"] = record
        target = warnings if warning else errors
        if item not in target:
            target.append(item)

    if not devices:
        issue("dns.network.empty", "No supported NETWORK/DEVICES layout found")
    if len(set(names)) != len(names) or "" in names:
        issue("dns.device.identity", "Device names must be present and unique")

    for index, device in enumerate(devices):
        for port_name, port in physical_ports(device).items():
            raw = port.findtext("IP", "")
            if not raw or raw == "0.0.0.0":
                continue
            try:
                interface = address(raw, port.findtext("SUBNET", ""))
                value = _ipv4(str(interface.ip))
                live = _state(device.findtext("ENGINE/POWER")) is True and _state(port.findtext("POWER")) is True
                addresses[value].append((index, port_name, live))
            except (ValueError, TypeError):
                if device.find("ENGINE/DNS_SERVER") is not None:
                    issue("dns.server.address", "DNS-capable device has an invalid saved interface address", device=index)
        service = device.find("ENGINE/DNS_SERVER")
        if service is None:
            continue
        enabled = _state(service.findtext("ENABLED"))
        records = service.findall("NAMESERVER-DATABASE/RESOURCE-RECORD")
        # An unused web server's default disabled, empty DNS service is valid.
        if enabled is False and not records:
            server_tables[index] = {"enabled": enabled, "entries": {}, "blocked": set(), "unsupported": False}
            continue
        if enabled is None:
            issue("dns.server.state", "DNS service enabled state is missing or unknown", True, index)
        if enabled is False and records:
            issue("dns.server.inactive-records", "Saved DNS records exist but their service is disabled; client intent needs checking", True, index)
        if enabled is True:
            endpoint_addresses = [live for matches in addresses.values() for device_index, _, live in matches if device_index == index]
            if not endpoint_addresses:
                issue("dns.server.interface", "Enabled DNS service has no supported usable saved IPv4 interface", True, index)
            elif not any(endpoint_addresses):
                issue("dns.server.power", "Enabled DNS service has no powered saved IPv4 interface", device=index)
        if service.find("NAMESERVER-DATABASE") is None:
            issue("dns.server.schema", "DNS record database is missing from the supported schema", True, index)
        entries, blocked = defaultdict(list), set()
        unsupported = False
        for number, record in enumerate(records):
            record_count += 1
            kind = record.findtext("TYPE", "")
            if kind not in {"A-REC", "CNAME"}:
                unsupported = True
                issue("dns.unsupported.record", "Record type requires delegation, IPv6 or other separate validation", True, index, number)
                try:
                    owner = canonical_name(record.findtext("NAME"))
                    entries[owner].append(("unsupported", None))
                except ValueError:
                    pass  # Root-zone/other owners may be valid in unmodeled record types.
                continue
            try:
                owner = canonical_name(record.findtext("NAME"))
            except ValueError:
                raw_owner = record.findtext("NAME", "")
                if raw_owner.startswith("*.") or any(ord(char) > 127 for char in raw_owner):
                    unsupported = True
                    issue("dns.unsupported.name", "Wildcard or international DNS names require separate validation", True, index, number)
                    continue
                issue("dns.record.name", "Record owner has malformed or unsupported DNS labels", device=index, record=number)
                continue
            try:
                ttl = int(record.findtext("TTL", ""))
                if not 0 <= ttl <= 2 ** 32 - 1:
                    raise ValueError()
            except (ValueError, TypeError):
                issue("dns.record.ttl", "Record TTL must be an unsigned 32-bit integer", device=index, record=number)
                blocked.add(owner)
            try:
                value = _ipv4(record.findtext("IPADDRESS")) if kind == "A-REC" else canonical_name(record.findtext("HOSTNAME"))
            except (ValueError, TypeError):
                issue("dns.record.address" if kind == "A-REC" else "dns.record.alias", "Invalid IPv4 address or alias target", device=index, record=number)
                blocked.add(owner)
                continue
            entries[owner].append((kind, value))
        for owner, records_for_name in entries.items():
            counts = Counter(records_for_name)
            if any(count > 1 for count in counts.values()):
                issue("dns.record.duplicate", "Duplicate equivalent records need cleanup or separate validation", True, index)
            aliases = {value for kind, value in records_for_name if kind == "CNAME"}
            if len(aliases) > 1 or (aliases and any(kind != "CNAME" for kind, _ in records_for_name)):
                issue("dns.record.conflict", "A CNAME owner must have one target and no other record type", device=index)
                blocked.add(owner)
            if len({value for kind, value in records_for_name if kind == "A-REC"}) > 1:
                issue("dns.multiple.addresses", "Multiple A answers are valid DNS but answer selection is not modeled", True, index)
        table = {"enabled": enabled, "entries": dict(entries), "blocked": blocked, "unsupported": unsupported}
        server_tables[index] = table
        summaries.append({"device_index": index, "service_enabled": enabled, "records": len(records),
                          "supported_records": sum(kind in {"A-REC", "CNAME"} for rs in entries.values() for kind, _ in rs)})

    def resolve(index, owner):
        table = server_tables[index]
        seen, chain = set(), []
        while True:
            if owner in seen:
                issue("dns.alias.loop", "CNAME chain returns to an already visited owner", device=index)
                return "failed", [], chain, "alias_loop"
            seen.add(owner)
            chain.append(owner)
            if owner in table["blocked"]:
                return "failed", [], chain, "invalid_record"
            rows = table["entries"].get(owner, [])
            if not rows:
                return "partial", [], chain, "no_same_server_record_recursion_not_modeled"
            if any(kind == "unsupported" for kind, _ in rows):
                return "partial", [], chain, "unsupported_record_or_delegation"
            aliases = {value for kind, value in rows if kind == "CNAME"}
            if aliases:
                owner = next(iter(aliases))
                continue
            answers = sorted({value for kind, value in rows if kind == "A-REC"}, key=lambda v: int(ip.IPv4Address(v)))
            if len(answers) > 1:
                return "partial", answers, chain, "multiple_answers_selection_not_modeled"
            return "modeled", answers, chain, "same_server_saved_records"

    # Detect loops even when no query has been requested. Resolve only local
    # tables: records on other servers are never silently combined.
    for index, table in server_tables.items():
        for owner, rows in table["entries"].items():
            if any(kind == "CNAME" for kind, _ in rows):
                status, _, _, reason = resolve(index, owner)
                if status == "partial" and reason == "no_same_server_record_recursion_not_modeled":
                    issue("dns.alias.external", "Alias target has no same-server answer; recursion is not modeled", True, index)

    def select_server(client_index, required):
        client = devices[client_index]
        configured = client.findtext("ENGINE/DNS_CLIENT/SERVER_IP", "")
        if not configured or configured == "0.0.0.0":
            if required:
                issue("dns.client.setting", "Requested client has no saved IPv4 DNS server", device=client_index)
            return "failed" if required else "unset", None
        try:
            configured = _ipv4(configured)
        except (ValueError, TypeError):
            issue("dns.client.setting", "Client DNS server address is invalid", device=client_index)
            return "failed", None
        matches = addresses.get(configured, [])
        if not matches:
            issue("dns.client.external", "Client DNS server is outside supported saved interface inventory; external DNS is not modeled", True, client_index)
            return "partial", None
        matched_devices = {index for index, _, _ in matches}
        if len(matched_devices) != 1:
            issue("dns.server.ambiguous", "Client DNS IP identifies multiple devices", device=client_index)
            return "failed", None
        index = next(iter(matched_devices))
        if not any(live for _, _, live in matches):
            issue("dns.server.power", "Configured DNS endpoint has no powered saved IPv4 interface", device=index)
            return "failed", index
        if index not in server_tables:
            kind = devices[index].findtext("ENGINE/TYPE")
            issue("dns.unsupported.server" if kind == "Router" else "dns.client.server",
                  "Configured local endpoint has no supported DNS server schema", kind == "Router", index)
            return "partial" if kind == "Router" else "failed", index
        state = server_tables[index]["enabled"]
        if state is False:
            issue("dns.server.disabled", "Configured DNS service is disabled", device=index)
            return "failed", index
        return "modeled" if state is True else "partial", index

    for index, device in enumerate(devices):
        node = device.find("ENGINE/DNS_CLIENT")
        if node is None:
            continue
        raw = node.findtext("SERVER_IP", "")
        if raw and raw != "0.0.0.0":
            status, server = select_server(index, False)
            clients.append({"device_index": index, "status": status, "server_index": server})
        ipv6 = node.findtext("SERVER_IPV6", "").strip()
        if ipv6:
            try:
                configured_ipv6 = ip.IPv6Address(ipv6)
                if not configured_ipv6.is_unspecified:
                    issue("dns.unsupported.ipv6", "IPv6 DNS client configuration requires separate validation", True, index)
            except ip.AddressValueError:
                issue("dns.client.ipv6", "Client IPv6 DNS server address is malformed", device=index)

    for query_index, query in enumerate(queries):
        if not isinstance(query, (list, tuple)) or len(query) not in {2, 3, 4} or not isinstance(query[0], str):
            issue("dns.query.input", "Query requires client, DNS name and optional expected IPv4/web-server name")
            results.append({"query_index": query_index, "status": "failed", "reason": "invalid_query"})
            continue
        client_name, raw_name = query[:2]
        expected, web_target = (query[2] if len(query) >= 3 else None), (query[3] if len(query) == 4 else None)
        try:
            owner = canonical_name(raw_name)
            expected = _ipv4(expected) if expected is not None else None
        except (ValueError, TypeError):
            issue("dns.query.input", "Query name or expected IPv4 is invalid")
            results.append({"query_index": query_index, "status": "failed", "reason": "invalid_query"})
            continue
        result = {"query_index": query_index, "name": owner, "expected_ipv4": expected, "addresses": [],
                  "status": "failed", "reason": "unknown_client", "web_configuration_checked": False}
        if names.count(client_name) != 1:
            issue("dns.query.client", "Query client must identify exactly one saved device")
            results.append(result)
            continue
        client_index = names.index(client_name)
        result["client_index"] = client_index
        if _state(devices[client_index].findtext("ENGINE/POWER")) is not True:
            issue("dns.client.power", "Requested client is powered off or its power state is unknown", device=client_index)
            result["reason"] = "client_not_enabled"
            results.append(result)
            continue
        status, server_index = select_server(client_index, True)
        result.update({"status": status, "reason": "resolver_not_available", "server_index": server_index})
        if status != "modeled":
            results.append(result)
            continue
        status, answers, chain, reason = resolve(server_index, owner)
        result.update({"status": status, "addresses": answers, "alias_chain": chain, "reason": reason})
        if status == "partial":
            issue("dns.query.coverage", "Requested answer needs unsupported recursion, delegation or answer selection", True, server_index)
        if expected is not None and answers and expected not in answers:
            issue("dns.query.expected", "Saved DNS answer does not match the expected IPv4", device=server_index)
            result.update({"status": "failed", "reason": "expected_ip_mismatch"})
        if web_target is not None:
            result["web_configuration_checked"] = True
            if not isinstance(web_target, str) or names.count(web_target) != 1:
                issue("dns.web.target", "Intended web server must identify exactly one saved device")
                result.update({"status": "failed", "reason": "unknown_web_target"})
            else:
                web_index = names.index(web_target)
                target_addresses = {value for value, matches in addresses.items() if any(index == web_index and live for index, _, live in matches)}
                http_state = _state(devices[web_index].findtext("ENGINE/HTTP_SERVER/ENABLED"))
                if http_state is not True:
                    issue("dns.web.service", "Intended web server HTTP service is disabled or its state is unknown", device=web_index)
                    result.update({"status": "failed", "reason": "http_not_enabled"})
                if answers and not set(answers) <= target_addresses:
                    issue("dns.web.address", "Saved answer does not identify an enabled interface of the intended web server", device=web_index)
                    result.update({"status": "failed", "reason": "web_target_ip_mismatch"})
        results.append(result)

    status = "failed" if errors else "partial" if warnings or any(r["status"] == "partial" for r in results) else "passed"
    return {"status": status, "errors": errors, "warnings": warnings, "servers": summaries, "clients": clients,
            "resolutions": results, "counts": {"dns_servers": len(summaries), "records": record_count, "queries": len(results)},
            "simulation_tested": False, "queries_executed": False, "path_tested": False, "path_modeled": False,
            "http_rendered": False, "raw_configuration_included": False,
            "scope": "Saved same-server IPv4 A/CNAME configuration only; no reachability, DNS query, recursive/delegation/cache behavior or page rendering test"}
