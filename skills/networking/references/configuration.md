# Configuration plans and supported schemas

Read when configuring devices or writing tutorials.

## Actual model and ports

Supported direct-slot PT5 schemas:

| Device/model | Examples |
|---|---|
| Router / Router-PT | FastEthernet0/0, FastEthernet1/0, Serial2/0; type follows installed module |
| Switch / Switch-PT | FastEthernet0/1, FastEthernet1/1; one port per modular slot |
| Pc, Server, Laptop, Printer | FastEthernet or another actual interface type |
| Cloud / Cloud-PT | Serial0, Serial1, Modem4, Ethernet6, Coaxial7, according to installed modules |
| DslModem, CableModem | Port 0 toward cloud, Port 1 toward Ethernet host |

These are not schemas for ISR/2911/2960 devices. Inspect running configs and fixed/nested modules. Extend the resolver only with a verified specimen; don't configure unknown chassis by guesswork.

## JSON plan

At least one change is required. Names/ports must exist. Include `tests` for multiple host subnets; both directions are checked.

```json
{
  "interfaces": [
    {"device": "R1", "port": "FastEthernet0/0", "address": "192.168.30.1/24", "enabled": true},
    {"device": "R2", "port": "FastEthernet1/0", "address": "192.168.40.1/24", "enabled": true}
  ],
  "hosts": {
    "PC1": {"address": "192.168.30.10/24", "gateway": "192.168.30.1"},
    "PC2": {"address": "192.168.40.10/24", "gateway": "192.168.40.1"}
  },
  "routes": {
    "R1": [{"network": "192.168.40.0/24", "next_hop": "10.0.0.2"}],
    "R2": [{"network": "192.168.30.0/24", "next_hop": "10.0.0.1"}]
  },
  "tests": [["PC1", "PC2"]]
}
```

This assumes an existing configured `10.0.0.0/30` R1/R2 link. Adjust to the actual topology. `address` is a host IP/prefix, not a network address.

- `interfaces`: updates existing router interfaces/subinterfaces; synchronizes IP/mask/power and running/startup config. Missing modules/subinterfaces aren't invented. Encapsulation/DLCI remain.
- `hosts`: sets the addressed port (default FastEthernet), gateway and optional `dns` IPv4 address; doesn't change DNS records/server pages.
- `routes`: **replaces all IPv4 static routes on each named router**. Include every route that must remain. Empty lists clear routes; omitted routers stay unchanged. Connected routes follow interface IPs. Supports network/next-hop routes and optional integer `distance` (1-255). AD 255 is unusable for forwarding; recursive, tracked or exit-interface routes need separate validation.
- `clocks`: changes named serial **DCE** ports and saved router commands when applicable.
- `clouds`: adds/replaces DSL mappings for supplied modem ports, sets provider DSL and enables mapped ports. Other mappings remain. It doesn't create modems or recable links.
- `tests`: models host pairs/return paths; does not execute ping.

Optional sections:

```json
{
  "clouds": {"Cloud2": {"dsl": [{"modem": "Modem4", "ethernet": "Ethernet6"}]}},
  "clocks": [{"device": "Cloud1", "port": "Serial0", "rate": 64000}],
  "tests": [["PC1", "PC2"]]
}
```

Preview: `configure INPUT OUTPUT --plan plan.json --dry-run`. Resolve errors/partial coverage, then omit `--dry-run` and audit the saved output. Source stays unchanged. Existing outputs need `--overwrite`; that flag doesn't grant authorization itself.

## Cloud mappings

[Cisco cloud configuration](https://tutorials.ptnetacad.net/help/default/config_clouds.htm) defines DSL/cable and Frame Relay forwarding. An Ethernet pair alone provides no forwarding path.

For `PC - Cloud - Router`, use `PC - DSL Modem - Cloud - Router`:

- PC FastEthernet -> modem Port 1: straight-through for the inspected pin roles.
- Modem Port 0 -> cloud Modem4: phone cable (`ePhoneLine`).
- Cloud Ethernet6 -> router Ethernet: copper cable for those pin roles.
- Enable Modem4/Ethernet6, set provider DSL and add their DSL connection.
- PC/router share a subnet; cloud/modem bridge layer 2 and aren't IPv4 gateways.

```xml
<MODEM_CONNECTION_TYPES>
  <CONNECTION_TYPE><PORT>Ethernet6</PORT><DSL>true</DSL></CONNECTION_TYPE>
</MODEM_CONNECTION_TYPES>
<MODEM_CONNECTIONS>
  <CONNECTION><PORT1>Modem4</PORT1><PORT2>Ethernet6</PORT2></CONNECTION>
</MODEM_CONNECTIONS>
```

For cable, use a verified CableModem, coaxial cable, `Coaxial7 -> Ethernet6` and `<DSL>false</DSL>`. Audit models cable mapping; configure edits DSL only.

Frame Relay pairs cloud serial sublinks. DLCIs may differ at opposite ends: cloud Serial0/DLCI304 can map to Serial1/DLCI403. Each router matches its own side. Verify LMI, encapsulation, enabled parents and addressed point-to-point subinterfaces. An unaddressed parent is valid here.

## Cable and IP decisions

Use [Cisco connection rules](https://tutorials.ptnetacad.net/help/default/connectionsLinks.htm) and actual port roles. On fixed modular PT5 copper ports, opposite PINS roles use straight-through; matching roles use crossover. Don't assume modern auto-MDI-X.

Simple router Ethernet transit: `10.0.0.0/30`, R1 `.1`, R2 `.2`, mask `255.255.255.252`. Remote LAN routes point to the other transit IP. R3 as a name never changes installed interface numbering.

Use `plan --base CIDR --lan LAN1=20 --lan LAN2=8 --transit R1-R2` to allocate exact masks, gateways and host ranges. It reserves one gateway in each LAN, allocates largest subnets first and rejects overlaps or insufficient space. This is an address plan, not a generated topology or installed routing table.

Preserve supplied prefixes and subnet only as needed for requested routed links. Default to private lab addresses when unspecified. Avoid network/broadcast host addresses. /31 and /32 designs need intentional support/compatible devices, not casual use in beginner labs.
