<div align="center">

**PACKET TRACER &nbsp; / &nbsp; CODEX SKILL**

# Give your AI a Packet Tracer skill.

**Describe the network. Get the `.pkt` file.**  
Skip dragging routers and cables onto a blank canvas. For supported copper labs, Codex builds the topology, assigns the addresses, and hands you a file you can open in Packet Tracer.

[![Latest release](https://img.shields.io/github/v/release/evorajhonj/packet-tracer-skill?style=flat-square&color=087f8c)](https://github.com/evorajhonj/packet-tracer-skill/releases/latest)
[![Release asset downloads](https://img.shields.io/github/downloads/evorajhonj/packet-tracer-skill/total?style=flat-square&label=asset%20downloads)](https://github.com/evorajhonj/packet-tracer-skill/releases)
[![GitHub stars](https://img.shields.io/github/stars/evorajhonj/packet-tracer-skill?style=flat-square&color=b57516)](https://github.com/evorajhonj/packet-tracer-skill/stargazers)
[![Open issues](https://img.shields.io/github/issues/evorajhonj/packet-tracer-skill?style=flat-square)](https://github.com/evorajhonj/packet-tracer-skill/issues)

[**Download a sample lab (.pkt)**](https://github.com/evorajhonj/packet-tracer-skill/releases/download/v1.0.0/two-lan-demo.pkt) &nbsp; · &nbsp; [**Install in Codex**](#install-in-codex) &nbsp; · &nbsp; [**Release notes**](https://github.com/evorajhonj/packet-tracer-skill/releases/latest)

</div>

---

## From a prompt to a lab

> Build two LANs with one PC each. Join their routers over a /30 link, add static routes in both directions, and give me the Packet Tracer file.

Here's the layout in the downloadable sample:

```text
PC1 ─────────── R1 ─────────── R2 ─────────── PC2
  192.168.10.0/24    10.0.0.0/30    192.168.20.0/24
```

Open the sample in Packet Tracer. On **PC1 → Desktop → Command Prompt**, try `ping 192.168.20.10`. That's the address of PC2. The saved routes were checked offline; this ping is how you test them in the simulator.

## Install in Codex

Paste this into a Codex chat to install the **v1.0.0** release:

```text
Use $skill-installer to install https://github.com/evorajhonj/packet-tracer-skill/tree/v1.0.0/skills/networking
```

Then start a request with `Use $networking`. The helpers use Python 3 (tested with 3.14) and need no pip packages.

| If you want to… | Try asking… |
| --- | --- |
| Build a lab from scratch | “Use $networking to build the two-LAN lab above. Save it as branch-office.pkt.” |
| Fix an existing lab | “Use $networking on my attached .pkt. PC1 reaches its gateway but not PC2. Check the return route and save any fix as a copy.” |
| Plan subnets | “Use $networking to split 192.168.40.0/24 for 61 staff interfaces, 29 lab interfaces and a two-address transit link. Those counts include gateways.” |

**What builds from scratch?** Router-PT, Switch-PT and PC-PT copper topologies. For other chassis or WAN media, start with an appropriate existing file. The offline checker can spot issues such as duplicate addresses and missing static routes; it does not send packets or prove a dynamic routing protocol has converged.

<details>
<summary><strong>Prefer the command line?</strong></summary>

From the repository root:

```sh
python skills/networking/scripts/pkt_tool.py build example.pkt --plan skills/networking/templates/copper-chain.json
python skills/networking/scripts/pkt_tool.py test example.pkt --between PC1 PC2
python skills/networking/scripts/vlsm.py 192.168.40.0/24 Staff=61 Lab=29 Transit=2
```

Run the regression suite with `python -m unittest discover -s skills/networking/scripts/tests`.

</details>

[Skill guide](skills/networking/SKILL.md) · [Topology plan format](skills/networking/references/fast-file.md) · [Troubleshooting](skills/networking/references/partial-connectivity.md) · [Third-party notices](skills/networking/scripts/THIRD_PARTY_LICENSE.txt)

Independent project. Not affiliated with Cisco.
