# Saved DNS configuration checks

Use `audit-dns` for a read-only check of client DNS settings and saved A/CNAME records:

```text
python <tool> audit-dns lab.pkt --resolve PC1 www.example.com
python <tool> audit-dns lab.pkt --expect PC1 www.example.com 192.168.10.3
python <tool> audit-dns lab.pkt --web PC1 www.example.com WEB1
```

Repeat `--resolve`, `--expect` or `--web` for additional clients/names. Expected IPv4 is the intended answer, not proof that its server is reachable. `--web` also checks an explicitly intended local server's saved IPv4 and HTTP service state; it does not render the page. Name matching ignores case and one trailing root dot. Search suffixes are not invented.

The helper verifies the selected saved DNS endpoint, service/power state, A IPv4 values, CNAME targets, loops, duplicate/conflicting names and optional expected answers. Multiple A answers can be valid DNS; answer selection remains partial. A CNAME owner with another record type or different alias targets is a conflict. Default disabled empty DNS services on unrelated web servers are benign.

The exact PT5 schema was inspected in a saved server lab and Cisco's installed `Server/DNS/Multilevel_DNS.pkt` sample: `ENGINE/DNS_SERVER/ENABLED`, `NAMESERVER-DATABASE/RESOURCE-RECORD`, `TYPE=A-REC` with `IPADDRESS`, and `TYPE=CNAME` with `HOSTNAME`. NS/SOA/AAAA and unknown record types remain partial. [Cisco Packet Tracer server documentation](https://tutorials.ptnetacad.net/help/default/config_servers.htm) describes A/CNAME records, NS delegation and SOA zone information; it does not validate our binary serializer or every Packet Tracer release.

Resolution follows only the selected server's saved table. Records from other servers are not merged. An external resolver or missing same-server alias target is partial because recursive queries/delegation are not modeled. External A answers can be legitimate and need not match a local device. Only an explicitly intended local web server should be checked against its actual saved interface and HTTP state.

## Small DNS and website design

For a single LAN example, use `192.0.2.0/24` with router gateway `192.0.2.1`, DNS1 at `192.0.2.53`, WEB1 at `192.0.2.20`, and PC1 at `192.0.2.10`. All hosts use mask `255.255.255.0` and gateway `192.0.2.1`. Set PC1's DNS resolver to `192.0.2.53`; enable DNS on DNS1 and HTTP on WEB1.

| Name | Type | Value |
|---|---|---|
| `example.com` | A | `192.0.2.20` |
| `www.example.com` | CNAME | `example.com` |

An A record maps a name to an IPv4 address. A CNAME points to another name, so its value is not an IP address; do not add an A record at that same alias name. Put both records on the resolver selected by PC1. For multiple LANs, add the required routed paths and return routes before testing the name. `example.com` is a reserved documentation name; this example is a local lab design.

With an existing compatible saved server specimen, inspect the actual record/service schema and prepare the explicit edits. Do not invent a server schema or bypass a file-only request with GUI actions. After authorized edits, decrypt the distinct output, verify the record inventory, run `audit-dns --expect PC1 www.example.com 192.0.2.20 --web PC1 www.example.com WEB1`, and audit the client-to-DNS1 and client-to-WEB1 paths separately. When runtime testing is permitted, test the server IP, name lookup and browser response as separate steps. [Packet Tracer server services and record types](https://tutorials.ptnetacad.net/help/default/config_servers.htm).

The Python API is `audit_dns(root, queries=())`. Each query is `(client_device_name, dns_name[, expected_ipv4[, web_server_device_name]])`; use `None` for an omitted expected address when naming a web target. The fourth field checks saved IPv4/HTTP configuration only. It never returns profiles, passwords or HTML, and it never renders a page. `--web CLIENT NAME SERVER` supplies this fourth field.

Reports state `simulation_tested: false`, `queries_executed: false`, `path_tested: false`, `path_modeled: false` and `http_rendered: false`. A modeled saved answer does not establish reachable DNS or a successful live lookup. Separately run `audit lab.pkt --between PC1 DNS1` for supported static path checks. When runtime testing is allowed, test the DNS server IP first, then run `nslookup www.example.com` from the exact saved lab, then open the website. Cisco's server documentation lists `nslookup` and describes the DNS/browser dependency.

This module does not mutate DNS records or server pages. Existing `configure` host plans can set a verified `DNS_CLIENT/SERVER_IP`; guarded `edit --domain` updates existing names when authorized. A new record/service design requires an explicit plan and compatible saved schema, followed by separate IP, DNS and HTTP checks. Neither a configured record nor the page's existence proves a live query or rendered response.
