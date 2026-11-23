# Small protocol recipes

These are classic IOS teaching patterns, not copy-paste promises for every Packet Tracer device. Replace each interface with a port confirmed on the selected model; check `show version` and CLI `?`. All names are generic. IPv4 lab examples use RFC 5737 documentation ranges; they are not public destinations. IPv6 uses the documentation prefix `2001:db8::/32`. Cisco Packet Tracer simplifies IOS and only models a subset of device features, so test the exact model and release. [Packet Tracer FAQ and modeled protocols](https://prelogin-authoring.netacad.com/sites/default/files/cisco-packet-tracer-faq.pdf) · [Packet Tracer FAQ/troubleshooting](https://tutorials.ptnetacad.net/help/default/faqTroubleShoot.htm)

## VLANs and router-on-a-stick

Use this pattern only when the selected switch supports 802.1Q trunks and the router has one physical Ethernet link carrying both VLANs. Example plan:

| Segment | VLAN | Subnet | Gateway |
|---|---:|---|---|
| Lab A | 10 | `192.0.2.0/24` | `192.0.2.1` |
| Lab B | 20 | `198.51.100.0/24` | `198.51.100.1` |

On SW1, replace ports with actual ports. Put client-facing ports into access VLANs and the R1 uplink in trunk mode:

```text
enable
configure terminal
vlan 10
 name LAB_A
vlan 20
 name LAB_B
interface <SW1-client-A-port>
 switchport mode access
 switchport access vlan 10
interface <SW1-client-B-port>
 switchport mode access
 switchport access vlan 20
interface <SW1-R1-uplink>
 switchport mode trunk
 switchport trunk allowed vlan 10,20
end
```

Some older switch IOS releases require `switchport trunk encapsulation dot1q` before `switchport mode trunk`; many fixed switches do not expose that command. Do not add it unless the selected CLI supports it. On R1, the physical uplink must be unaddressed. When migrating an existing address to a subinterface, include `no ip address` on the physical uplink in the reviewed migration plan:

```text
enable
configure terminal
interface <R1-switch-uplink>
 no shutdown
interface <R1-switch-uplink>.10
 encapsulation dot1Q 10
 ip address 192.0.2.1 255.255.255.0
 no shutdown
interface <R1-switch-uplink>.20
 encapsulation dot1Q 20
 ip address 198.51.100.1 255.255.255.0
 no shutdown
end
```

Set each PC to a usable address in its subnet with the corresponding gateway. Verify `show vlan brief`, `show interfaces trunk`, `show interfaces <uplink> switchport`, `show ip interface brief`, `show ip route connected`, `show spanning-tree vlan 10`, and `show spanning-tree vlan 20`. Ping each PC's own gateway first, then across VLANs. If same-VLAN works but cross-VLAN fails, check trunk state/allowed VLANs, subinterface tags, interface status and gateways. An ACL can intentionally block cross-VLAN traffic. Cisco documents VLAN/trunk checks and trunk consistency; Packet Tracer model/command support still needs local confirmation. [Cisco VLAN guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/vlan/vlan-configuration-guide/configure-vlan.html) · [Cisco trunk guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/vlan/vlan-configuration-guide/configure-vlan-trunks.html)

## OSPFv2 across a point-to-point link

Example: R1 LAN `192.0.2.0/24`, R1–R2 transit `10.0.0.0/30`, R2 LAN `198.51.100.0/24`. The router interfaces already have those connected addresses and are enabled. Use the same area on both routers; the `network` command's second value is a wildcard mask.

On R1:

```text
enable
configure terminal
router ospf 1
 router-id 1.1.1.1
 passive-interface default
 no passive-interface <R1-R2-link>
 network 192.0.2.0 0.0.0.255 area 0
 network 10.0.0.0 0.0.0.3 area 0
end
```

On R2:

```text
enable
configure terminal
router ospf 1
 router-id 2.2.2.2
 passive-interface default
 no passive-interface <R2-R1-link>
 network 198.51.100.0 0.0.0.255 area 0
 network 10.0.0.0 0.0.0.3 area 0
end
```

If the selected IOS rejects `passive-interface default`, configure passive LAN interfaces explicitly or follow its supported syntax. Verify `show ip ospf neighbor` reaches `FULL`, `show ip route ospf` contains the remote LAN on each router, and hosts can ping each other in both directions. If there is no adjacency, check link addressing/masks, `no shutdown`, area, timers/authentication, and whether the transit interface is passive. [Cisco OSPF configuration guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-routing/b-ip-routing/m_iro-cfg-0.html) · [Cisco OSPF neighbor command](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book/ospf-s1.html)

## Router DHCP for two LANs

Assume R1 already has `192.0.2.1/24` and `198.51.100.1/24` on enabled interfaces/subinterfaces. Reserve the gateway and any statically assigned hosts, then match each pool's network, mask and default router to its own interface:

```text
configure terminal
ip dhcp excluded-address 192.0.2.1 192.0.2.20
ip dhcp excluded-address 192.0.2.53
ip dhcp excluded-address 198.51.100.1 198.51.100.20
ip dhcp pool LAB_A
 network 192.0.2.0 255.255.255.0
 default-router 192.0.2.1
 dns-server 192.0.2.53
ip dhcp pool LAB_B
 network 198.51.100.0 255.255.255.0
 default-router 198.51.100.1
 dns-server 192.0.2.53
end
```

Replace the DNS address with a reachable resolver/server. Set each client to DHCP; verify its lease, mask, gateway and DNS using `ipconfig /all`, then check `show ip dhcp pool` and `show ip dhcp binding`. Test `ping <gateway>` and `nslookup <name>` separately. For a Packet Tracer Server pool, configure pool name, gateway, DNS, start address, mask and maximum users in **Services > DHCP**; then inspect the client lease. [Cisco DHCP configuration/verification](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_config-dhcp-server-xe.html) · [Packet Tracer Server services](https://tutorials.ptnetacad.net/help/default/config_servers.htm)

## PAT from a lab subnet to an outside test network

Assume R1 has an inside interface in `192.0.2.0/24` and an outside interface in `203.0.113.0/30`; replace ports and next hop. An upstream test router/server must exist and have a return path. PAT overload shares the outside interface address:

```text
configure terminal
access-list 10 permit 192.0.2.0 0.0.0.255
interface <R1-inside>
 ip nat inside
interface <R1-outside>
 ip nat outside
exit
ip nat inside source list 10 interface <R1-outside> overload
ip route 0.0.0.0 0.0.0.0 <upstream-next-hop>
end
```

Generate traffic from a lab client to the outside test host, then verify `show ip nat translations` and `show ip nat statistics`. Confirm the client can reach its gateway and the router can reach the next hop before debugging NAT. Common misses: inside/outside reversed, wrong ACL subnet/wildcard, no default route, or expecting a translation before traffic passes. [Cisco NAT translation monitoring](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_iadnat-monmain-xe.html)

## IPv6 addressing and a management VTY ACL

Use a documentation prefix and make routing intent explicit. This example puts the router at `2001:db8:10::1/64`; a management host is `2001:db8:10::10/64`. On a router that supports these features:

```text
configure terminal
ipv6 unicast-routing
interface <R1-LAN>
 ipv6 address 2001:db8:10::1/64
 no shutdown
ipv6 access-list MGMT6
 permit ipv6 host 2001:db8:10::10 any
 deny ipv6 any any log
line vty 0 4
 ipv6 access-class MGMT6 in
 transport input ssh
end
```

Configure SSH authentication/keys separately using the selected IOS' supported method. This VTY ACL restricts management sessions; it is not a data-plane firewall. Verify `show ipv6 interface brief`, `show ipv6 route`, `show ipv6 access-list`, and `show ip ssh`; test SSH from the permitted host and confirm a second IPv6 source is rejected. For a traffic-filter ACL, separately account for required ICMPv6 Neighbor Discovery and other control traffic; do not copy this VTY policy onto an interface. [Cisco IPv6 ACL configuration and verification](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m_ip6-acls-xe.html) · [Cisco SSH verification](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/xe-2/sec-usr-ssh-xe-2-book/sec-usr-ssh-sec-shell.html) · [Cisco IPv6 overview](https://www.cisco.com/site/us/en/learn/topics/networking/what-is-ipv6.html)

## Fast checks before calling a recipe complete

1. Confirm the exact model, interface names and accepted commands; don't substitute a remembered ISR/switch port.
2. Compare interface state, address/mask, route/neighbor state, and both end-host settings.
3. Test one hop at a time, then the requested end-to-end flow in both directions; test DHCP, DNS, HTTP, NAT, or SSH as its own service.
4. In Packet Tracer, distinguish saved config and Simulation Mode events from a runtime ping/application result. Feature presence in the FAQ is not proof that a particular model, release or command supports the desired scenario. [Packet Tracer FAQ](https://prelogin-authoring.netacad.com/sites/default/files/cisco-packet-tracer-faq.pdf) · [Packet Tracer troubleshooting FAQ](https://tutorials.ptnetacad.net/help/default/faqTroubleShoot.htm)
