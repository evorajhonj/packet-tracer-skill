"""Apply a guarded batch in one decode/encode pass, preserving the input format."""
import time

import pkt_tool
from pkt_fast_io import encode, read_plan, require_distinct, write_verified
from pkt_network import audit


def entries(plan: dict, key: str) -> list[dict]:
    items = plan.get(key, [])
    if not isinstance(items, list):
        raise ValueError(f"{key} must be a list")
    for entry in items:
        if not isinstance(entry, dict) or set(entry) != {"old", "new", "expect"}:
            raise ValueError("Each replacement requires only old, new and expect")
        if not all(isinstance(entry[name], str) and entry[name] for name in ("old", "new")):
            raise ValueError("Replacement strings must be nonempty")
        if entry["old"] == entry["new"] or type(entry["expect"]) is not int or entry["expect"] < 1:
            raise ValueError("Replacement must change text and expect a positive integer count")
    return items


def replace_prefixes(xml: bytes, replacements: list[dict]) -> bytes:
    mapping = {pkt_tool.prefix(entry["old"]): pkt_tool.prefix(entry["new"]) for entry in replacements}
    if len(mapping) != len(replacements) or len(set(mapping.values())) != len(mapping):
        raise ValueError("Old and new prefixes must each be unique")
    observed = [match.group(1).decode() for match in pkt_tool.PREFIX_RE.finditer(xml)]
    for entry in replacements:
        pkt_tool.require_count("IP prefix", observed.count(entry["old"]), entry["expect"])
        if entry["new"] in observed and entry["new"] not in mapping:
            raise ValueError("Destination prefix already exists outside this batch")

    def substitute(match):
        old = match.group(1).decode()
        return mapping[old].encode() + match.group(0)[len(old):] if old in mapping else match.group(0)

    return pkt_tool.PREFIX_RE.sub(substitute, xml)


def transform(xml: bytes, plan: dict) -> tuple[bytes, int]:
    if set(plan) - {"prefixes", "literals", "expect_input_sha256"}:
        raise ValueError("Unknown rewrite plan field")
    prefixes, literals = entries(plan, "prefixes"), entries(plan, "literals")
    if not prefixes and not literals:
        raise ValueError("At least one guarded replacement is required")
    edited = replace_prefixes(xml, prefixes)
    seen = set()
    for entry in literals:
        if entry["old"] in seen:
            raise ValueError("Duplicate literal replacement")
        seen.add(entry["old"])
        edited, _ = pkt_tool.replace_literal(edited, entry["old"], entry["new"], entry["expect"], "literal")
    pkt_tool.parse_xml(edited)
    if edited == xml:
        raise ValueError("Rewrite made no change")
    return edited, sum(entry["expect"] for entry in prefixes + literals)


def rewrite(args) -> dict:
    started = time.perf_counter()
    require_distinct(args.output, args.input, args.plan)
    plan = read_plan(args.plan)
    original = args.input.read_bytes()
    digest = pkt_tool.sha256(original)
    if "expect_input_sha256" in plan and plan["expect_input_sha256"] != digest:
        raise ValueError("Source hash changed since inspection")
    edited, changed = transform(pkt_tool.decrypt_pkt(original), plan)
    checked = audit(pkt_tool.parse_xml(edited))
    if checked["errors"]:
        raise ValueError("Edited configuration failed physical/IPv4 audit: " + str(checked["errors"]))
    report = {"status": "preview" if args.dry_run else "saved", "changes": changed,
              "configuration_audit": checked, "simulation_tested": False, "convergence_tested": False}
    if pkt_tool.sha256(args.input.read_bytes()) != digest:
        raise ValueError("Source changed during rewrite")
    if not args.dry_run:
        packet = encode(edited, args.container, original)
        report.update(write_verified(args.output, packet, edited, args.overwrite))
    if pkt_tool.sha256(args.input.read_bytes()) != digest:
        raise ValueError("Source changed before rewrite completed")
    report.update({"source_unchanged": True, "input_sha256": digest,
                   "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)})
    return report
