#!/usr/bin/env python3
"""Fail-closed, dependency-free read-only MCP protocol smoke for Rocky01."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys

ENTRY = Path(__file__).resolve().parents[1] / "gateway.py"
MODERN = {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "rocky-smoke", "version": "0.8.0-dev"},
    "io.modelcontextprotocol/clientCapabilities": {},
}}


def check(messages: list[dict], ids: list[int]) -> list[dict]:
    wire = "".join(json.dumps(x, separators=(",", ":")) + "\n" for x in messages)
    proc = subprocess.run([sys.executable, "-u", str(ENTRY)], input=wire,
                          text=True, capture_output=True, timeout=12, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"Gateway startup/stdio exit code {proc.returncode}; inspect stderr locally")
    if proc.stderr.strip():
        raise RuntimeError("Gateway wrote unexpected stderr")
    lines = proc.stdout.splitlines()
    if len(lines) != len(ids):
        raise RuntimeError("Unexpected MCP response count or extra stdout")
    payloads = [json.loads(line) for line in lines]
    if [response.get("id") for response in payloads] != ids:
        raise RuntimeError("Unexpected MCP response IDs")
    if any(response.get("jsonrpc") != "2.0" or "error" in response for response in payloads):
        raise RuntimeError("MCP protocol returned an error")
    return payloads


def main() -> int:
    if os.geteuid() == 0:
        print("Run as the normal Rocky login user, not root", file=sys.stderr)
        return 2
    modern = check([
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": MODERN},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": MODERN},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            **MODERN, "name": "gateway_status", "arguments": {}}},
    ], [1, 2, 3])
    for response in modern[:2]:
        result = response["result"]
        if (result.get("resultType") != "complete" or
                result.get("ttlMs") != 0 or result.get("cacheScope") != "private"):
            raise RuntimeError("Modern discovery/list result has wrong schema or cache policy")
    public_version = json.loads(modern[2]["result"]["content"][0]["text"])["version"]
    if modern[2]["result"].get("_meta", {}).get("io.modelcontextprotocol/serverInfo", {}).get("version") != public_version:
        raise RuntimeError("Modern tool response is missing server identity")
    if len(modern[1]["result"].get("tools", [])) < 3:
        raise RuntimeError("Missing baseline tools")
    if modern[2]["result"].get("isError", True):
        raise RuntimeError("Modern tool call failed")
    legacy = check([
        {"jsonrpc":"2.0", "id":4, "method":"initialize", "params": {
            "protocolVersion":"2025-11-25", "capabilities":{},
            "clientInfo":{"name":"rocky-smoke", "version":"0.2"}}},
        {"jsonrpc":"2.0", "method":"notifications/initialized"},
        {"jsonrpc":"2.0", "id":5, "method":"tools/list"},
        {"jsonrpc":"2.0", "id":6, "method":"tools/call", "params":{
            "name":"gateway_status", "arguments":{}}},
    ], [4, 5, 6])
    if legacy[0]["result"].get("protocolVersion") != "2025-11-25":
        raise RuntimeError("Legacy handshake negotiated wrong version")
    if legacy[2]["result"].get("isError", True):
        raise RuntimeError("Legacy tool call failed")
    print("PASS: modern discover/list/call and legacy initialize/list/call; no extra stdio output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
