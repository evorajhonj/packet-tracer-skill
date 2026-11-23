# Research-backed routing, addressing and service checks

Read for subnet planning, optional route syntax, DNS/web failures or compatibility questions. These sources explain behavior; they do not prove a particular Packet Tracer version implements it.

## Route selection

For the same prefix, lower administrative distance selects the preferred usable route. Packet forwarding then chooses the longest matching installed prefix. Static next-hop routes default to distance 1; distance 255 is never installed. A higher-distance backup for the same prefix is different from equal-cost next hops. [Cisco administrative distance](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/15986-admin-distance.html), [Cisco route selection](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/8651-21.html).

The helper accepts a simple optional numeric distance, excludes 255 from modeled forwarding and does not silently ignore route options. Equal-best next hops, tracking, permanent routes, exit-interface routes and policy need separate checks. Its `distance_usable` field describes the distance only; it is not proof of RIB installation or failover.

Next hops can be recursively resolved through other routes on real IOS. A next hop outside the immediate LAN is therefore not inherently invalid. Inspect its resolving route; use bounded recursion/cycle checks if extending the model. The helper marks recognized recursive dependencies partial rather than modeling them as adjacent. Verify `show ip route` and actual traffic when permitted. [Cisco next-hop guidance](https://www.cisco.com/c/en/us/support/docs/dial-access/floating-static-route/118263-technote-nexthop-00.html).

## Addressing and VLSM

Private and documentation addresses can be valid lab inputs even though they are not globally reachable. Reject ordinary-interface addresses in 0/8, loopback, multicast and reserved/broadcast space. Treat link-local as limited in scope; do not use global-reachability flags as blanket host-validity checks. [IANA special-purpose IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry).

For ordinary LANs, allocate room for PCs, their router gateway, network and broadcast. Example:

```text
python <tool> plan --base 192.168.10.0/24 --lan LAN1=20 --lan LAN2=8 --transit R1-R2 --json
```

This yields LAN1 `192.168.10.0/27`, LAN2 `192.168.10.32/28`, and transit `192.168.10.48/30`. Gateways are the first usable LAN IPs; PC ranges begin at the second. Each transit reserves two router IPs. The planner allocates largest-first, checks capacity/alignment and returns no device/port guesses. It defaults to /30 transits; intentional /31 point-to-point and /32 loopback designs require appropriate model support and separate validation.

## DNS, DHCP and HTTP

Diagnose services separately from IP routing. A working IP path is not evidence that DNS or a website works. Packet Tracer servers have separate DNS records and HTTP files; DHCP pools include gateway/DNS/mask/lease settings. [Packet Tracer server configuration](https://tutorials.ptnetacad.net/help/default/config_servers.htm).

For a requested website, use the [DNS configuration checker](dns.md) for the client resolver, saved A/CNAME records, alias loops/conflicts and optional intended web-server IP/HTTP state. Check path reachability and requested/default HTML files separately. Page text, DNS records, interface data and live service behavior are different checks; the IPv4 audit alone does not validate DNS.

When runtime testing is allowed, test IP reachability first, then `nslookup example.com`, then the browser URL. For DHCP, confirm the actual lease, mask, gateway and DNS values rather than only a configured pool. Saved service configuration is not a successful query, lease exchange or rendered-page test.

## Compatibility and evidence

Packet Tracer models a subset of Cisco features. Identify the installed version, exact chassis/modules/ports and supported commands before generating CLI. Real IOS references do not establish emulator support. [Packet Tracer limitations](https://tutorials.ptnetacad.net/help/default/faqTroubleShoot.htm).

Keep four evidence levels distinct: address-plan arithmetic, container/XML integrity, supported offline configuration checks, and runtime tests in the exact saved file. Do not describe one as proof of another. File-only work stops at available offline evidence and supplies the specific remaining test.
