# Packet Tracer networking skill

Build a small Cisco Packet Tracer lab from a plan, or give Codex an existing `.pkt` and ask it to trace a connection that isn't working. The tools work on files, so you don't need Packet Tracer open to plan addresses or check a saved configuration.

## Install in Codex

Paste this into a Codex chat:

```text
Use $skill-installer to install https://github.com/evorajhonj/packet-tracer-skill/tree/main/skills/networking
```

Then try: **“Use $networking to build two LANs joined by two routers. Use static routes, save a new .pkt, and check the path between the PCs.”**

The file tools use Python 3 (tested with 3.14). No pip packages are needed. Open the finished lab in Packet Tracer when you want to test live traffic.

## Try the tools yourself

From the root of a clone:

```sh
python skills/networking/scripts/vlsm.py 192.168.40.0/24 Staff=61 Lab=29 Transit=2
python skills/networking/scripts/pkt_tool.py build example.pkt --plan skills/networking/templates/copper-chain.json
python skills/networking/scripts/pkt_tool.py test example.pkt --between PC1 PC2
```

The first command is a separate planning example. It assigns Staff a /26, Lab a /27 and Transit a /30. Count the gateway in each LAN's host total. The next two commands build the bundled two-router example and check its saved path in both directions.

## What the checker can tell you

It can find a duplicate IP, a gateway on the wrong LAN, or a missing static return route in supported topologies. It doesn't send a ping, form an OSPF or EIGRP adjacency, or load a page from a simulated web server. A partial result tells you where the model stops; it doesn't mean the network is down.

Start with the [skill guide](skills/networking/SKILL.md) for supported devices and edits. For a lab where only some clients or services fail, see [partial connectivity](skills/networking/references/partial-connectivity.md).

Run the regression tests with `python -m unittest discover -s skills/networking/scripts/tests`. The bundled crypto helpers carry their own [MIT notice](skills/networking/scripts/THIRD_PARTY_LICENSE.txt). This is an independent project, not a Cisco product.
