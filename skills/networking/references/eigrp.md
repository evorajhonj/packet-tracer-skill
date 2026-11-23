# Classic IPv4 EIGRP

This skill generates reviewable CLI and audits saved configuration. It does not write dynamic routing state into `.pkt` files, execute DUAL, learn routes, establish neighbors or test convergence.

## Concepts for a basic lab

Neighboring classic IPv4 routers need the same **AS number**, compatible K values, a common link/subnet and participating interfaces. R1/R2 are device names; `router eigrp 100` selects AS 100. Mark user-facing LAN interfaces passive and keep intended router transits active. [Cisco EIGRP configuration](https://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/configuration/15-2s/config-eigrp.html).

- **DUAL** selects loop-free paths and coordinates recalculation after a change.
- **Successor:** the selected best next hop for a destination.
- **Feasible successor:** an alternate next hop already satisfying DUAL's loop-free test.
- **Feasibility condition:** the neighbor's reported distance, its advertised cost, must be strictly less than this router's feasible distance. Equality does not qualify. Losing the successor without a feasible successor can require queries before a replacement is chosen.
- **Metric:** default K values use the path's lowest bandwidth and cumulative delay. Lower metric is preferred. An interface's configured bandwidth affects metric calculation; it does not set physical speed or replace a serial DCE clock. [Cisco bandwidth command reference](https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/bandwidth.htm).

These are protocol concepts, not calculations performed by the file-only helper. [Cisco EIGRP operation, distances and successor examples](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/16406-eigrp-toc.html).

Default administrative distance is **90 for internal EIGRP**, **170 for external EIGRP**, and **1 for static routes**. Lower AD selects the route source for the same prefix; forwarding then uses longest-prefix matching. In `show ip route`, `D` identifies internal EIGRP and `D EX` identifies external EIGRP. [Cisco administrative distance](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/15986-admin-distance.html).

## JSON plan

Use actual router and interface names from inspection. Interfaces must already have enabled, supported primary IPv4 configuration. Network strings require aligned CIDRs; an explicit address/wildcard pair is also accepted. The planner supports contiguous inverse-subnet wildcard masks only.

```json
{
  "routers": {
    "R1": {
      "as": 100,
      "networks": ["192.0.2.0/24", {"address": "10.0.0.0", "wildcard": "0.0.0.3"}],
      "interfaces": [
        {"name": "FastEthernet0/0", "passive": true},
        {"name": "FastEthernet1/0", "passive": false}
      ],
      "k_values": [1, 0, 1, 0, 0]
    },
    "R2": {
      "as": 100,
      "networks": ["10.0.0.0/30", "198.51.100.0/24"],
      "interfaces": [
        {"name": "FastEthernet0/0", "passive": false},
        {"name": "FastEthernet1/0", "passive": true}
      ]
    }
  }
}
```

`as` must be an integer from 1 to 65535. Optional `k_values` defaults to `[1,0,1,0,0]`. Every selector must match a known interface, and the selected set must equal the declared interface set. The planner never creates ports, IPs, loopbacks or router IDs.

For an existing target AS, add `"replace_process": true` only when rebuilding that process is intended. Generated CLI then includes `no router eigrp AS` before recreating it. Applying that command resets its neighbors. CLI preserves static routes and other AS processes; additional dynamic processes make coverage partial.

## What the checks mean

The `network` command selects participating interfaces. A passive interface still contributes its connected network but suppresses EIGRP hellos and updates. Generation uses `no auto-summary`, `passive-interface default`, explicit active-interface exceptions, and saves running configuration. [Cisco configuration guidance](https://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/configuration/15-2s/config-eigrp.html).

Supported direct links and untagged switch paths supply configuration candidates. Saved paths require matching device references, unique cable endpoints, enabled interfaces and compatible media. Known copper paths must match saved pin roles; direct serial paths need a valid DCE endpoint, positive saved clock rate and matching HDLC/PPP encapsulation. These are file checks, not proof that a link is up. Matching subnets without a supported path remain potential peers with partial coverage. Checks also catch differing AS/K values and passive router transits; matching configuration does not prove adjacency. [Cisco troubleshooting, including default K values and mismatch behavior](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/118974-technote-eigrp-00.html).

Audit checks classic running/startup process text, network membership, AS, K values, passive interfaces and explicit summarization. Named mode, IPv6, redistribution, authentication, stub routing, VRFs, VLAN/trunks, tunnels, multiple AS peer domains and other chassis require separate validation. [Packet Tracer supported router commands](https://tutorials.ptnetacad.net/help/default/CLI_routerIOS.htm) describe the emulator subset; current IOS features do not guarantee support in an older installed version.

Advanced topics are guidance-only: named mode uses address-family contexts; IPv6 needs IPv6-specific configuration; authentication needs verified key and interface settings; redistribution imports routes and needs deliberate metrics; stub routing constrains advertisements and query scope. Do not insert these commands through the classic planner or imply they were audited. Check the actual model/version and a suitable runtime lab first. [Cisco EIGRP configuration guide](https://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/configuration/15-2s/config-eigrp.html).

The installed PT 5.3.3 `Security/GRE_Over_IPSec_EIGRP.pkt` sample was inspected read-only: it stores PT version `5.2.0.0065`, Cisco 1841 routers, classic `router eigrp 60`, `network 192.168.0.0 0.0.255.255` and `auto-summary`, with Tunnel interfaces. This confirms stored classic command syntax, not tunnel or serializer support. Audit must report partial coverage for that specimen.

## Runtime verification when permitted

Apply reviewed CLI in compatible Packet Tracer models, then check `show ip protocols`, `show ip eigrp interfaces`, `show ip eigrp neighbors`, `show ip eigrp topology`, and `show ip route eigrp`. Test destination and return paths after convergence. Existing static routes can take precedence; a successful ping alone does not establish that EIGRP supplied the route. Keep `simulation_tested:false`, `convergence_tested:false`, and `learned_routes_modeled:false` for file-only reports.

| Symptom | Targeted check |
|---|---|
| No neighbor | Check interface up/up, common subnet, AS, K values, network membership and passive status. |
| Neighbor exists; destination missing | Compare `show ip eigrp topology` with `show ip route`; inspect source selection, summarization and filters. |
| Ping works; EIGRP route absent | Check for a connected/static route to the same prefix before assuming EIGRP carried traffic. |
| Neighbors repeatedly reset | Check link changes, configuration changes and authentication before changing timers. |
| Settings disappear after reload | Compare running/startup configuration and save the reviewed configuration. |

Use only show commands supported by the actual emulator. [Cisco's targeted EIGRP troubleshooting](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/118974-technote-eigrp-00.html).
