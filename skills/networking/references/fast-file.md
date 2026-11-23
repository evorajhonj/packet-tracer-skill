# Direct-file fast path

Use the existing helper rather than opening Packet Tracer or writing another per-lab builder. Run with a working Python interpreter; on managed desktop use the bundled runtime if the system python command is a store shim. No browser, GUI, installed Packet Tracer process or extra Python package is needed.

## Build a topology, including when no .pkt was supplied

`python <tool> build output.pkt --plan topology.json`

Start from `templates/copper-chain.json` for PC–router–router–PC. It is explicitly a **static-routing example**, not a replacement for requested EIGRP/OSPF/RIP/BGP. Change its declared devices, addresses, links and routes; do not reconstruct XML for each task. `--dry-run` checks without writing.

Plan fields:
- `devices`: unique `name`, `kind` (`Router`, `Switch`, `Pc`), optional `x`/`y`, and `interfaces` mapping actual port names to IPv4/CIDR. A Pc requires `FastEthernet` and `gateway`; an untagged L2 Switch needs no IP.
- `links`: `{"from":["R1","FastEthernet0/0"],"to":["PC1","FastEthernet"]}`. Copper cable type is chosen from inspected PINS, not guessed. Endpoints cannot be reused.
- Router `routes`: explicit `{"network":"192.168.20.0/24","next_hop":"10.0.0.2"}` entries. Omit static routes when a dynamic-routing activity is requested.
- Router `routing`: reviewed process-to-subcommand lists, e.g. `{"eigrp 300":["network 10.0.0.0 0.0.0.3","network 192.168.10.0 0.0.0.255","passive-interface FastEthernet0/0","no auto-summary"]}`. Keys may be classic `eigrp N`, `ospf N`, `bgp N`, or `rip`. Supply exact supported CLI; this stores process text and does **not** execute an IOS parser, DUAL, SPF or BGP. Verify multi-area/redistribution intent separately.
- `tests`: requested host pairs, checked in both directions by the conservative static model.
- `notes`: optional `{"x":100,"y":50,"text":"Lab label"}`.

Bundled Router-PT actual ports: FastEthernet0/0, FastEthernet1/0, Ethernet4/0, FastEthernet5/0, FastEthernet6/0; the copper builder does not use its serial/fiber modules. Switch-PT copper ports FastEthernet0/1 through3/1. PC-PT port FastEthernet. Do not rename these to fictitious Fa2/0 or G0/0.

The builder supports these inspected copper schemas only. For Cloud-PT/Frame Relay, DSL/cable, another chassis or modules, inspect an appropriate .pkt/specimen and use the existing configure helper or direct verified XML adaptation. Do not replace clouds with switches, strip requested protocols, or silently switch to desktop automation. One missing specimen is a specific blocker, not permission for the GUI.

## Rewrite many addresses/AS references in one pass

Inspect/count once, then:

```text
python <tool> rewrite input.pkt output.pkt --plan changes.json
```

```json
{
  "prefixes": [
    {"old":"192.168.10","new":"10.30.10","expect":7},
    {"old":"192.168.20","new":"10.30.20","expect":7}
  ],
  "literals": [
    {"old":"router eigrp 100","new":"router eigrp 300","expect":4},
    {"old":"redistribute eigrp 100","new":"redistribute eigrp 300","expect":2}
  ]
}
```

Counts above are illustrative: use actual observed counts, never copy them blindly. Prefixes change simultaneously, preserve host octets/masks and update all matching saved fields, gateways, CLI and labels. Literals run in listed order with exact guards; use specific phrases so metrics such as10000/100 are not mistaken for an AS. For an AS change include every process, redistribution reference and relevant label. Optional `expect_input_sha256` pins the inspected source. Unknown fields, wrong counts, duplicate destinations, malformed XML or IPv4 audit errors refuse output. Literal edits are byte edits, not a full semantic protocol migration engine; don't use vague numeric replacements. Overlapping literal changes require deliberate ordering and review.

`auto` preserves legacy/EAX input format for rewrite; build uses the compatible bundled PT5 legacy container. `--container legacy|eax` is an explicit override, not a compatibility guarantee. Both commands verify the actual saved output and preserve their input/plan. Existing output requires `--overwrite`; that flag alone is not user authorization. Exit0 means saved/previewed successfully; always read `configuration_audit.status`, which may remain partial for dynamic routing. No runtime connectivity is implied.

## Other supported commands

Use `configure --plan ... --dry-run` for masks/new addresses, supported static routes, clouds and DCE clocks rather than prefix-only rewrite. See configuration.md. Keep `count`/`edit` for simple domain/heading changes. `inspect`, `audit`, `test`, `eigrp`, `audit-eigrp` and `audit-dns` remain available. `create --network CIDR` still builds the fixed router–switch–PC starter.

After normal builds/edits, use the embedded round-trip/audit and one targeted `test OUTPUT --between ...`; do not rerun the entire skill suite per artifact. Run the full regression suite only when changing the helper itself or diagnosing a suspected helper bug. Partial dynamic coverage is expected, not a reason to retry identical commands or substitute static routes.
