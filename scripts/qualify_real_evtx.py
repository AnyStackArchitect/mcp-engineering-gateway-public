#!/usr/bin/env python3
"""Real provider qualification using a hash-pinned *public* EVTX fixture.

Run ONLY on a disposable, nonroot off-host CI worker with optional python-evtx
0.8.1 installed. No raw event/XML/username/payload is printed or uploaded.
All production case code runs unchanged, including its opaque provider aliases.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
UPSTREAM_FIXTURE_SHA256 = "becab64455866f8fae5583fbaa5dab901115e4397ea7abe14f37ad732d5d7eb9"
UPSTREAM_FIXTURE_BYTES = 69632
META = {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}}


def _run(home: Path, program: str, data: str | None = None) -> str:
    args = [sys.executable, "-u", str(ROOT / program)]
    if program == "jobwork.py":
        args.append("--once")
    process = subprocess.run(args, input=data, text=True, capture_output=True,
        env={**os.environ, "HOME": str(home)}, timeout=40)
    if process.returncode or process.stderr:
        raise RuntimeError("EVTX qualification subprocess rejected fixture")
    return process.stdout


def _call(home: Path, name: str, args: dict) -> dict:
    wire = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                       "params": {**META, "name": name, "arguments": args}}) + "\n"
    data = json.loads(_run(home, "gateway.py", wire))
    if data.get("id") != 8 or "error" in data or data.get("result", {}).get("isError"):
        raise RuntimeError("EVTX qualification MCP tool error: " + name)
    return json.loads(data["result"]["content"][0]["text"])


def _worker(home: Path, cid: str, kind: str, aid: str | None = None) -> dict:
    args = {"case_id": cid, "kind": kind}
    if aid:
        args["artifact_id"] = aid
    jid = _call(home, "job_submit", args)["job_id"]
    _run(home, "jobwork.py")
    outcome = _call(home, "job_result", {"job_id": jid})
    if outcome["state"] != "SUCCEEDED":
        raise RuntimeError("Actual offline provider job did not succeed: " + kind)
    return outcome["result"]


def _fixture_metadata(path: Path) -> tuple[int, Counter, int]:
    # Real, unmodified optional external parser; compare to the derived
    # index generated via an independently started worker process. This
    # verifies integration correctness, NOT independent EVTX parser accuracy.
    from Evtx.Evtx import Evtx
    from evtxwork import _metadata
    seen = 0
    ids = Counter()
    utc_count = 0
    with Evtx(str(path)) as stream:
        for row in stream.records():
            seen += 1
            if seen > 500_000:
                raise RuntimeError("Fixture exceeded bounded EVTX record inventory")
            eid, _, _, utc = _metadata(row.xml())
            ids[eid] += 1
            if utc is not None:
                utc_count += 1
    if not seen:
        raise RuntimeError("Real public EVTX fixture had no decodable records")
    return seen, ids, utc_count


def main():
    if os.geteuid() == 0:
        raise RuntimeError("Real EVTX smoke must run unprivileged")
    if len(sys.argv) != 2:
        raise RuntimeError("Pass the CI-controlled verified fixture path")
    fixture = Path(sys.argv[1])
    if fixture.is_symlink() or not fixture.is_file() or fixture.stat().st_size != UPSTREAM_FIXTURE_BYTES:
        raise RuntimeError("EVTX fixture provenance/size mismatch")
    with fixture.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != UPSTREAM_FIXTURE_SHA256:
        raise RuntimeError("Public fixture SHA256 mismatch")
    from importlib.metadata import version
    if version("python-evtx") != "0.8.1":
        raise RuntimeError("Real EVTX provider version does not match pinned package")
    seen, ids, utc_count = _fixture_metadata(fixture)
    with tempfile.TemporaryDirectory(prefix="rocky-evtx-real-") as folder:
        home = Path(folder)
        cid = _call(home, "case_open", {})["case_id"]
        inbox = home / ".local/share/rocky-mcp-gateway/inbox"
        staged = inbox / "public-binary-fixture.evtx"
        shutil.copyfile(fixture, staged)
        staged.chmod(0o600)
        aid = _call(home, "artifact_register", {
            "case_id": cid, "filename": staged.name})["artifact_id"]
        analyzed = _worker(home, cid, "analyze_evtx", aid)
        if (analyzed["status"] != ("PARTIAL" if seen != utc_count else "PASS") or
                analyzed["records_examined"] != seen or analyzed["records_skipped"] or
                analyzed["records_without_utc"] != seen - utc_count):
            raise RuntimeError("Actual provider metadata/coverage differs from upstream baseline")
        summary = _call(home, "evtx_summary", {"case_id": cid, "artifact_id": aid})
        events = _call(home, "evtx_events", {"case_id": cid, "artifact_id": aid})
        rules = _call(home, "windows_rule_report", {"case_id": cid, "artifact_id": aid})
        if (rules['status'] != 'PARTIAL' or rules['records_examined'] != seen or
                rules['collection_completeness_verified'] or rules['eventdata_evaluated'] or
                rules['sigma_engine_available'] or len(rules['rules']) != 4):
            raise RuntimeError('Real binary rule-pack coverage or scope was overstated')
        counts = {row["event_id"]: row["count"] for row in summary["event_id_counts"]}
        if (summary["records_examined"] != seen or
                summary["records_without_utc"] != seen - utc_count or
                sum(counts.values()) != seen or counts != ids):
            raise RuntimeError("Gateway EVTX counts contradict direct real parser")
        if not events["events"] or not events["payloads_excluded"]:
            raise RuntimeError("Gateway EVTX metadata-only response missing")
        joined = _worker(home, cid, "build_correlation")
        summary2 = _call(home, "correlation_summary", {"case_id": cid})
        if (joined["missing_indexes"] != 0 or
                joined["events"] != seen or summary2["event_count"] != seen):
            raise RuntimeError("Real EVTX index did not join to common event model")
        rows = _call(home, "correlation_query", {
            "case_id": cid, "kind": "evtx", "include_unknown": True})
        evidence = _call(home, "case_evidence_report", {
            "case_id": cid, "index_revision": summary2['index_revision']})
        if (evidence['facts']['indexed_events'] != seen or
                not evidence['observed_source_producers'] or
                evidence['observed_source_producers'][0]['recorded_producer'].get('optional_provider_version') != '0.8.1' or
                'evtxwork' not in evidence['observed_source_producers'][0]['recorded_producer'].get('modules', {})):
            raise RuntimeError('Real binary producer provenance missing from evidence report')
        if not rows["events"]:
            raise RuntimeError("No real binary EVTX source locators in correlation result")
        for row in rows["events"]:
            if (row["artifact_id"] != aid or row["kind"] != "evtx" or
                    row["locator_type"] != "record" or
                    row["time_basis"] not in ("DECLARED_UTC_CLOCK_UNVERIFIED","UNANCHORED_NO_UTC")):
                raise RuntimeError("Real EVTX event provenance/clock basis invalid")
        serialized = json.dumps((analyzed, summary, events, rules, joined, summary2, rows, evidence))
        if ("public-binary-fixture.evtx" in serialized or str(home) in serialized or
                "<Event" in serialized or "<EventData>" in serialized or
                "TargetUserName" in serialized):
            raise RuntimeError("Actual EVTX binary/event payload leaked through MCP")
        original = home / ".local/share/rocky-mcp-gateway/cases" / cid / "originals" / aid
        # Source integrity: corruption immediately invalidates derived metadata
        # even though the byte count stays the same; do not hide stale evidence.
        with original.open("r+b") as stream:
            stream.seek(6)
            stream.write(b"X")
        request = json.dumps({"jsonrpc":"2.0","id":9,"method":"tools/call",
            "params":{**META,"name":"evtx_summary",
                "arguments":{"case_id":cid,"artifact_id":aid}}})+"\n"
        rejected = json.loads(_run(home,"gateway.py",request))
        if not rejected["result"].get("isError"):
            raise RuntimeError("Mutated Windows evidence retained an allegedly valid index")
    # Bounded, nonprivate fixture metadata only.
    print("PASS: real hash-pinned EVTX binary via python-evtx 0.8.1, "
          "MCP/worker source-index correlation and stale-source refusal; "
          "records=" + str(seen) + "; utc=" + str(utc_count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
