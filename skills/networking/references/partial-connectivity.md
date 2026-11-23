# When some traffic works

Pick one failing source, destination and service. Compare it with one working pair that differs by just one thing: VLAN, subnet, client, or service. Keep the original lab; change one setting and repeat the same comparison.

| Observation | What it narrows down | Next check |
| --- | --- | --- |
| Two PCs in the same VLAN can talk on one switch, but not across switches | Local access ports work for that pair. The trunk is still untested. | Compare VLAN membership at both ends and the allowed, active and forwarding VLANs on the trunk. Don't change routing to fix a same-subnet failure. |
| The router can ping a remote PC, but a local PC cannot | The router may be sourcing its ping from the transit subnet. The reply need not take the same path back to the LAN. | Check the PC gateway; look up the source LAN prefix on the far router. If available, source a router ping from its LAN interface to distinguish the return paths. |
| A static client works, but a DHCP client in the same VLAN doesn't | A working static host doesn't prove broadcasts can reach the DHCP server. | Check the pool for free leases and the right mask/gateway. For a remote server, check the relay on the client-facing L3 interface and the route back. |
| A hostname opens the wrong page while the intended server IP works | Reachability to the intended server is already demonstrated. | Compare the name's resolved address with the intended server. Check which DNS server the client actually uses before editing HTTP files. |
| Small pings work; a larger transfer stalls | Size might matter, but one successful ping doesn't identify an MTU issue. | Compare the same endpoints at different sizes. Check interface MTUs and whether fragmentation is permitted before changing them. |

Treat these as hypotheses, not findings. If the file doesn't contain the needed runtime state, ask for the relevant output (for example, `show interfaces trunk` from both switches), not the entire configuration.
