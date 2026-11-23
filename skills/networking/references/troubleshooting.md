# Diagnosing packet failures

Run `inspect INPUT --json`, then `audit INPUT --between HOST_A HOST_B --json`. Exit 2 means errors; exit 0 may still include partial coverage. Read status/warnings.

| Code family | Inspect/fix |
|---|---|
| device.identity, device.mac, link.identity | Unique names/IDs/MACs and current endpoint references |
| link.port, link.media, link.occupied | Actual modules/ports, compatible cable, one physical cable per port |
| link.copper | Cable for fixed pin roles; auto-MDI-X only on a verified capable model |
| link.shutdown | Device power and both interface no-shutdown states |
| ip.invalid, ip.duplicate, ip.overlap, ip.link-subnet | Usable unique IPs, masks, distinct routed subnets |
| interface.state, config.startup | Serialized fields versus running/startup config |
| config.startup-routes | Running/static routes and IP-routing state differ from saved startup state |
| router.routing-disabled | IPv4 transit requires router routing enabled; inspect no ip routing |
| host.gateway | Enabled router on the actual LAN; matching prefix alone is insufficient |
| route.next-hop | Destination/mask, enabled adjacent next hop, cloud forwarding |
| route.inactive | AD 255 cannot supply a forwarding route; inspect a usable primary/backup route |
| serial.dce, serial.clock, serial.encapsulation | DCE endpoint, positive clock there, matching encapsulation |
| fr.unmapped, fr.mapping, fr.dlci, fr.lmi | PVC, per-side DLCI/sublink, subinterface IP, LMI/encapsulation |
| cloud.unmapped, cloud.mapping, cloud.provider | DSL/cable path, provider, modem/coax-to-Ethernet mapping |
| path.unreachable | Longest matching route, return route, LAN attachment or routing loop |
| unsupported.* | Inspect separately; don't report it as checked |

Paths list hosts/routers. Cloud/modem/switch hops are represented by modeled LAN connectivity. Modeled is static evidence, not an ICMP transmission.

## Runtime checks when permitted

Open the exact final file. Check the closest failing segment first:

1. Wait for active links; ping each host's gateway.
2. Ping router transit IPs across the WAN.
3. Ping remote LAN router and PC.
4. Repeat in reverse; retry an initial timeout after ARP/link convergence.

Useful commands where supported; use actual interface names:

```text
show ip interface brief
show ip route
show interfaces serial 2/0
show controllers serial 2/0
show frame-relay pvc
show frame-relay map
```

Inspect cloud mappings separately. If a site's IP works but its name fails, check host DNS IP, server records and service state. If DNS resolves but the page fails, check HTTP state/files separately from routing.

For file-only work, run offline checks and give the user's exact test. Don't operate the GUI, fabricate successful ping or hide coverage limits.

## Window header has no file path

Compare the exact files before assuming missing metadata. Packet Tracer's [opened filename](https://tutorials.ptnetacad.net/help/default/IpcAPI/class_network_file.html), [main-window title](https://tutorials.ptnetacad.net/help/default/IpcAPI/class_app_window.html) and [recent-file menu](https://tutorials.ptnetacad.net/help/default/IpcAPI/class_options.html) are separate API concepts. These newer API references do not prove an older version's title implementation. `RECENT_FILES` is history, not a supported current-file-path repair. Do not restore unrelated personal paths or invent a filename XML field.

Have the user open the exact saved artifact with File > Open (Ctrl+O), then use File > Save As (Ctrl+Shift+S) to a distinct copy and reopen it. These are documented [file shortcuts](https://tutorials.ptnetacad.net/help/default/keyboardShortcuts.htm). Check the title again and identify the installed version if it remains blank. Describe this as a diagnostic step, not a confirmed fix. File-only tests can establish the filesystem path, saved bytes and configuration; they cannot observe the current app title.
