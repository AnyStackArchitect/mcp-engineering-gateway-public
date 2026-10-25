#!/usr/bin/env python3
"""Bounded packet-local DNS and SMB2 diagnostic candidates.

No TCP reassembly, decryption, live traffic, names, authentication material,
network access, packet payload return or causal inference is performed.
"""
from __future__ import annotations

from typing import Any

MAX_PENDING_DNS = 32768
SMB2_PROTOCOL = b"\xfeSMB"
SMB2_KNOWN_MAX_COMMAND = 18
KNOWN_SMB2_ERRORS = {
    0xC0000022: "access_denied",
    0xC000006D: "logon_failure",
    0xC00000CC: "bad_network_name",
    0xC0000034: "object_name_not_found",
    0xC00000BA: "file_is_a_directory",
}


class DnsCandidateTracker:
    """Pair on capture-local 5-tuple and DNS transaction ID, not question name.

    These are candidates: spoofing, capture loss, duplicates, and ID reuse
    cannot be excluded without more complete, authorized evidence.
    """
    def __init__(self) -> None:
        self.pending: dict[tuple[bytes, int, bytes, int, int], None] = {}
        self.overflow = False
        self.collisions = 0
        self.matched = 0
        self.orphan_responses = 0

    def observe(self, source: bytes, source_port: int, destination: bytes,
                destination_port: int, payload: bytes, role: str) -> None:
        if len(payload) < 12 or type(source_port) is not int or type(destination_port) is not int:
            return
        if role not in ("query", "response"):
            return
        transaction = int.from_bytes(payload[:2], "big")
        if role == "query":
            key = (source,source_port,destination,destination_port,transaction)
            if key in self.pending:
                self.collisions += 1
            elif len(self.pending) >= MAX_PENDING_DNS:
                self.overflow = True
            else:
                self.pending[key] = None
        else:
            key = (destination,destination_port,source,source_port,transaction)
            if key in self.pending:
                self.pending.pop(key)
                self.matched += 1
            else:
                self.orphan_responses += 1

    def summary(self) -> dict[str, int | bool]:
        return {
            "dns_tuple_id_match_candidates": self.matched,
            "dns_duplicate_id_query_candidates": self.collisions,
            "dns_response_without_seen_query_candidates": self.orphan_responses,
            "dns_query_without_seen_response_candidates": len(self.pending),
            "dns_pending_tracker_overflow": self.overflow,
        }


def smb2_header(segment: bytes) -> dict[str, Any] | None:
    """Decode only a contiguous NBSS+SMB2 64-byte header, never its body.

    An SMB2 message crossing TCP segments is NOT parsed and must not be
    represented as evidence of absence or a completed SMB2 exchange.
    """
    if type(segment) is not bytes or len(segment) < 68:
        return None
    if segment[0] != 0x00 or segment[4:8] != SMB2_PROTOCOL:
        return None
    nb_length = ((segment[1] & 0x01) << 16) | int.from_bytes(segment[2:4],"big")
    if nb_length < 64 or segment[1] & 0xfe:
        return None
    if int.from_bytes(segment[8:10], "little") != 64:
        return None
    command = int.from_bytes(segment[16:18], "little")
    if command > SMB2_KNOWN_MAX_COMMAND:
        return None
    flags = int.from_bytes(segment[20:24],"little")
    response = bool(flags & 1)
    status = int.from_bytes(segment[12:16],"little") if response else None
    return {
        "command": command,
        "response": response,
        "status_label": KNOWN_SMB2_ERRORS.get(status,"other_error") if response and status else
                        "success" if response else "request",
        "error": bool(response and status),
        "message_complete_in_segment": len(segment) >= nb_length + 4,
    }
