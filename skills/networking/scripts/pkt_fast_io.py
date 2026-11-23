"""Shared verified file I/O; no desktop, browser, network or subprocess calls."""
import json
from pathlib import Path

import pkt_tool


def is_legacy(packet: bytes) -> bool:
    decoded = pkt_tool.obfuscate_stage2(packet)
    return len(decoded) > 6 and decoded[4:6] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01")


def encode(xml: bytes, container: str, source: bytes | None = None) -> bytes:
    if container not in {"auto", "legacy", "eax"}:
        raise ValueError("container must be auto, legacy or eax")
    legacy = container == "legacy" or container == "auto" and (source is None or is_legacy(source))
    packet = pkt_tool.obfuscate_stage2(pkt_tool.compress_qt(xml)) if legacy else pkt_tool.pack_xml(xml)
    if pkt_tool.decrypt_pkt(packet) != xml:
        raise ValueError("In-memory container round trip failed")
    return packet


def read_plan(path: Path) -> dict:
    plan = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(plan, dict):
        raise ValueError("Plan must be a JSON object")
    return plan


def require_distinct(output: Path, *protected: Path) -> None:
    if output.resolve() in {path.resolve() for path in protected}:
        raise ValueError("Output cannot replace its input or plan")


def write_verified(output: Path, packet: bytes, xml: bytes, overwrite: bool) -> dict:
    pkt_tool.atomic_write(output, packet, overwrite=overwrite)
    reopened = output.read_bytes()
    if reopened != packet or pkt_tool.decrypt_pkt(reopened) != xml:
        raise ValueError("Saved output failed exact reopen verification")
    return {"output": str(output.resolve()), "sha256": pkt_tool.sha256(reopened),
            "container": "legacy" if is_legacy(reopened) else "eax", "round_trip_verified": True,
            "simulation_tested": False, "convergence_tested": False}
