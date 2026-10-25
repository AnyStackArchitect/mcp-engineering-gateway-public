"""Adversarial, offline known-answer tests for private gateway cases."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import casework
import gateway


def pcap(payload: bytes = b"abcd", *, endian: str = "<", nano: bool = False):
    magic = {
        ("<", False): b"\xd4\xc3\xb2\xa1", (">", False): b"\xa1\xb2\xc3\xd4",
        ("<", True): b"\x4d\x3c\xb2\xa1", (">", True): b"\xa1\xb2\x3c\x4d",
    }[(endian, nano)]
    return (magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1) +
            struct.pack(endian + "IIII", 1000, 5, len(payload), len(payload)) + payload)


def pcapng():
    shb = (b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) +
           b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28))
    idb = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    epb = (struct.pack("<II", 6, 36) + struct.pack("<IIIII", 0, 0, 1, 4, 4) +
           b"abcd" + struct.pack("<I", 36))
    return shb + idb + epb


class CaseTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.home = Path(t.name)
        self.store = casework.CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]

    def stage(self, name: str, data: bytes) -> str:
        file = self.store.inbox / name
        file.write_bytes(data)
        file.chmod(0o600)
        return name

    def register(self, name: str, data: bytes):
        self.stage(name, data)
        return self.store.register(self.case, name)

    def test_list_cases_is_resumable_without_exposing_paths(self):
        result = self.store.list_cases()
        self.assertEqual(result["cases_found"], 1)
        self.assertEqual(result["cases"][0]["case_id"], self.case)
        self.assertNotIn(str(self.home), json.dumps(result))
        self.assertEqual(result["status"], "PASS")

    def test_case_list_does_not_claim_clean_when_manifest_unreadable(self):
        (self.store.cases/self.case/"manifest.json").write_text("not json")
        result=self.store.list_cases()
        self.assertEqual(result["cases_unreadable"],1)
        self.assertEqual(result["status"],"PARTIAL")

    def test_private_case_and_original_immutable_by_interface(self):
        self.assertEqual(stat.S_IMODE((self.store.cases / self.case).stat().st_mode), 0o700)
        manifest = self.store.cases / self.case / "manifest.json"
        self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
        source = b"2026-10-15T17:20:10Z Something failed\n"
        details = self.register("server.log", source)
        self.assertEqual(details["sha256"], hashlib.sha256(source).hexdigest())
        self.assertNotIn(str(self.home), json.dumps(details))
        preserved = self.store.cases / self.case / "originals" / details["artifact_id"]
        self.assertEqual(preserved.read_bytes(), source)
        self.assertEqual((self.store.inbox / "server.log").read_bytes(), source)
        self.assertEqual(stat.S_IMODE(preserved.stat().st_mode), 0o600)
        status = self.store.status(self.case)
        self.assertEqual(status["artifact_count"], 1)
        self.assertNotIn("server.log", json.dumps(status))

    def test_alias_traversal_bad_names_denied(self):
        for name in ("..", ".", "../bad.log", "name/evil", "name\\evil", "name with spaces", "-bad", "", "x"*129):
            with self.subTest(name=name), self.assertRaises(casework.CaseError):
                self.store.register(self.case, name)
        with self.assertRaises(casework.CaseError):
            self.store.status("../" + self.case)

    def test_symlink_file_cannot_leave_inbox(self):
        real = self.home / "secret.txt"
        real.write_text("secret")
        (self.store.inbox / "symlink.txt").symlink_to(real)
        with self.assertRaises((casework.CaseError, OSError)):
            self.store.register(self.case, "symlink.txt")

    def test_symlink_case_and_manifest_denied(self):
        victim = self.store.cases / self.case
        manifest = victim / "manifest.json"
        manifest.rename(victim / "backup.json")
        manifest.symlink_to(victim / "backup.json")
        with self.assertRaises((casework.CaseError, OSError)):
            self.store.status(self.case)

    def test_world_writable_stage_rejected(self):
        p = self.store.inbox / "loose.log"
        p.write_text("hi")
        p.chmod(0o666)
        with self.assertRaises(casework.CaseError):
            self.store.register(self.case, p.name)

    def test_world_readable_stage_rejected(self):
        file = self.store.inbox / "readable.log"
        file.write_bytes(b"secret")
        file.chmod(0o644)
        with self.assertRaisesRegex(casework.CaseError, "mode 0600"):
            self.store.register(self.case, file.name)

    def test_case_limit_rejected(self):
        with patch.object(casework, "MAX_CASES", 1):
            with self.assertRaisesRegex(casework.CaseError, "Maximum number of cases"):
                self.store.open_case()

    def test_failed_manifest_update_does_not_orphan_original(self):
        self.stage("diskfull.log", b"abc")
        with patch.object(casework, "_write_json_atomic", side_effect=OSError("test disk full")):
            with self.assertRaises(OSError):
                self.store.register(self.case, "diskfull.log")
        self.assertEqual(list((self.store.cases/self.case/"originals").iterdir()), [])
        self.assertEqual(self.store.status(self.case)["artifact_count"], 0)

    def test_dir_traversal_via_private_base_symlink_denied(self):
        share = self.home / ".local" / "share"
        share.rename(self.home / "oldshare")
        share.symlink_to(self.home / "oldshare")
        with self.assertRaises(casework.CaseError):
            self.store.open_case()

    def test_low_disk_and_per_file_quota_rejected_without_partial(self):
        self.stage("huge.log", b"abc")
        with patch.object(casework, "MAX_ARTIFACT", 2):
            with self.assertRaisesRegex(casework.CaseError, "size limit"):
                self.store.register(self.case, "huge.log")
        with patch.object(casework, "FREE_RESERVE", 10**20):
            with self.assertRaisesRegex(casework.CaseError, "Insufficient space"):
                self.store.register(self.case, "huge.log")
        self.assertEqual(self.store.status(self.case)["artifact_count"], 0)

    def test_duplicate_bytes_get_distinct_artifact_ids(self):
        self.stage("same.log", b"x")
        a = self.store.register(self.case, "same.log")
        b = self.store.register(self.case, "same.log")
        self.assertEqual(a["sha256"], b["sha256"])
        self.assertNotEqual(a["artifact_id"], b["artifact_id"])
        self.assertEqual(self.store.status(self.case)["artifact_count"], 2)

    def test_case_status_bounded_to_twenty(self):
        self.stage("short.txt", b"a")
        for _ in range(22):
            self.store.register(self.case, "short.txt")
        status = self.store.status(self.case)
        self.assertEqual(len(status["artifacts"]), 20)
        self.assertTrue(status["list_truncated"])

    def test_valid_log_index_and_secret_redaction(self):
        raw = ("2026-10-15T11:12:13-04:00 SERVICE START\n"
               "2026-10-15T11:12:14-04:00 ERROR token=ABCD123456 Bearer abcdefgh123456\n")
        artifact = self.register("troubleshoot.log", raw.encode())
        indexed = self.store.index_log(self.case, artifact["artifact_id"])
        self.assertEqual(indexed["status"], "PASS")
        self.assertEqual(indexed["lines_examined"], 2)
        found = self.store.search_log(self.case, artifact["artifact_id"], "ERROR")
        self.assertEqual(len(found["matches"]), 1)
        self.assertEqual(found["matches"][0]["timestamp_utc"], "2026-10-15T15:12:14+00:00")
        self.assertIn("[REDACTED]", found["matches"][0]["excerpt"])
        self.assertNotIn("ABCD123456", json.dumps(found))
        self.assertNotIn("abcdefgh123456", json.dumps(found))

    def test_naive_timestamps_remain_unknown_timezone(self):
        art = self.register("naive.log", b"2026-10-15 11:12:14 ERROR thing\n")
        meta = self.store.index_log(self.case, art["artifact_id"])
        self.assertEqual(meta["timestamps_without_timezone"], 1)
        rows = self.store.search_log(self.case, art["artifact_id"], "ERROR")["matches"]
        self.assertIsNone(rows[0]["timestamp_utc"])
        self.assertEqual(rows[0]["source_timestamp"], "2026-10-15 11:12:14")

    def test_search_percent_underscore_are_literal(self):
        art = self.register("literal.log", b"ERROR xx%_match\nERROR xxnormalmatch\n")
        self.store.index_log(self.case, art["artifact_id"])
        rows = self.store.search_log(self.case, art["artifact_id"], "%_")["matches"]
        self.assertEqual([x["line"] for x in rows], [1])
        with self.assertRaises(casework.CaseError):
            self.store.search_log(self.case, art["artifact_id"], "\n")

    def test_oversize_line_partial_with_correct_line_number(self):
        art = self.register("long.log", b"a"*17000 + b"\n" + b"2026-10-15T10:00:00Z ERROR\n")
        meta = self.store.index_log(self.case, art["artifact_id"])
        self.assertEqual((meta["lines_examined"], meta["lines_indexed"], meta["lines_skipped"]), (2,1,1))
        self.assertEqual(meta["status"], "PARTIAL")
        rows = self.store.search_log(self.case, art["artifact_id"], "ERROR")["matches"]
        self.assertEqual(rows[0]["line"], 2)

    def test_modified_original_rejected_on_index(self):
        art = self.register("source.log", b"critical ERROR\n")
        target = self.store.cases / self.case / "originals" / art["artifact_id"]
        target.write_bytes(b"CRITICAL ERROR\n")  # same size, different hash
        with self.assertRaisesRegex(casework.CaseError, "hash changed"):
            self.store.index_log(self.case, art["artifact_id"])
        self.assertFalse((self.store.cases/self.case/"indexes"/(art["artifact_id"]+".sqlite3")).exists())

    def test_log_index_limit_and_repeat(self):
        art = self.register("sample.log", b"hello\n")
        with patch.object(casework, "MAX_SYNC_LOG", 2):
            with self.assertRaisesRegex(casework.CaseError, "worker"):
                self.store.index_log(self.case, art["artifact_id"])
        self.store.index_log(self.case, art["artifact_id"])
        with self.assertRaisesRegex(casework.CaseError, "already exists"):
            self.store.index_log(self.case, art["artifact_id"])

    def test_index_symlink_denied(self):
        art = self.register("foo.log", b"hey\n")
        index = self.store.cases / self.case / "indexes" / (art["artifact_id"] + ".sqlite3")
        index.symlink_to(self.home / "other")
        with self.assertRaisesRegex(casework.CaseError, "symlink"):
            self.store.index_log(self.case, art["artifact_id"])

    def test_binary_and_zip_not_executed_as_logs(self):
        for name, body, expected in [("malware.bin", b"MZ\0program", "binary"),
                                     ("bundle.zip", b"PK\x03\x04"+b"bad zip", "zip"),
                                     ("events.gz", b"\x1f\x8b"+b"bad", "gzip")]:
            with self.subTest(name=name):
                art=self.register(name, body)
                self.assertEqual(art["type"],expected)
                with self.assertRaisesRegex(casework.CaseError, "plain text"):
                    self.store.index_log(self.case, art["artifact_id"])

    def test_pcap_micro_and_big_endian_nano(self):
        for endian,nano in (("<",False),(">",True)):
            art=self.register("capture"+("nan" if nano else "us")+".cap",pcap(endian=endian,nano=nano))
            result=self.store.summarize_pcap(self.case,art["artifact_id"])
            self.assertEqual(result["status"],"PASS")
            self.assertEqual(result["packets_examined"],1)
            self.assertEqual(result["linktype"],1)
            self.assertFalse(result["payloads_examined"])

    def test_pcap_truncated_rejected(self):
        for name,data in [("short.cap",pcap()[:-2]),("head.cap",pcap()[:13])]:
            with self.subTest(name=name):
                art=self.register(name,data)
                with self.assertRaises(casework.CaseError):
                    self.store.summarize_pcap(self.case,art["artifact_id"])

    def test_pcap_bad_record_timestamp_rejected(self):
        data = bytearray(pcap())
        struct.pack_into("<I",data,28,1_000_000)
        art=self.register("time.cap",bytes(data))
        with self.assertRaisesRegex(casework.CaseError,"timestamp"):
            self.store.summarize_pcap(self.case,art["artifact_id"])

    def test_pcapng_valid_sample(self):
        art=self.register("sample.pcapng",pcapng())
        out=self.store.summarize_pcap(self.case,art["artifact_id"])
        self.assertEqual((out["sections"],out["interfaces"],out["packets_examined"]),(1,1,1))
        self.assertIsNone(out["earliest_utc"])

    def test_pcapng_bad_trailer_refused(self):
        sample=bytearray(pcapng())
        sample[-1] ^= 1
        art=self.register("bad.pcapng",bytes(sample))
        with self.assertRaisesRegex(casework.CaseError,"trailer"):
            self.store.summarize_pcap(self.case,art["artifact_id"])

    def test_pcapng_unknown_interface_refused(self):
        sample = bytearray(pcapng())
        epb_offset = 28 + 20
        struct.pack_into("<I", sample, epb_offset + 8, 7)
        art = self.register("wrong-interface.pcapng", bytes(sample))
        with self.assertRaisesRegex(casework.CaseError, "unknown interface"):
            self.store.summarize_pcap(self.case, art["artifact_id"])

    def test_large_capture_rejected_for_sync(self):
        art = self.register("sample.cap", pcap())
        with patch.object(casework, "MAX_SYNC_PCAP", 2):
            with self.assertRaisesRegex(casework.CaseError, "worker"):
                self.store.summarize_pcap(self.case, art["artifact_id"])

    def test_pcapng_short_section_refused(self):
        sample=bytearray(pcapng())
        struct.pack_into("<I",sample,4,12)
        art=self.register("bad-section.pcapng",bytes(sample))
        with self.assertRaisesRegex(casework.CaseError,"length"):
            self.store.summarize_pcap(self.case,art["artifact_id"])

    def test_modified_capture_same_size_rejected_hash(self):
        art=self.register("capture.cap",pcap())
        source=self.store.cases/self.case/"originals"/art["artifact_id"]
        original=source.read_bytes()
        source.write_bytes(original[:-1]+b"X")
        with self.assertRaisesRegex(casework.CaseError,"hash mismatch"):
            self.store.summarize_pcap(self.case,art["artifact_id"])

    def test_pcap_record_count_cutoff_is_partial(self):
        art=self.register("cap.pcap",pcap())
        with patch.object(casework,"MAX_PCAP_RECORDS",0):
            result=self.store.summarize_pcap(self.case,art["artifact_id"])
        self.assertEqual(result["status"],"PARTIAL")
        self.assertEqual(result["packets_examined"],0)

    def test_gateway_mcp_case_open_register_index_search(self):
        g=gateway.Gateway(gateway.Config({}, (), self.home))
        server=gateway.MCPServer(g)
        for name,args in [("case_open", {}), ("gateway_status", {})]:
            self.assertIn(name,[t["name"] for t in g.tools()])
        c=g.call("case_open",{})
        self.stage("mcp.log", b"2026-10-15T12:00:00Z problem discovered\n")
        a=g.call("artifact_register",{"case_id":c["case_id"],"filename":"mcp.log"})
        index=g.call("log_index",{"case_id":c["case_id"],"artifact_id":a["artifact_id"]})
        self.assertEqual(index["status"],"PASS")
        message={"jsonrpc":"2.0","id":10,"method":"tools/call","params":{
            "name":"log_search", "arguments":{"case_id":c["case_id"],
                "artifact_id":a["artifact_id"],"query":"problem"}}}
        legacy=server.process({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{}}})
        self.assertIn("result",legacy)
        server.process({"jsonrpc":"2.0","method":"notifications/initialized"})
        out=server.process(message)
        self.assertFalse(out["result"]["isError"])
        found=json.loads(out["result"]["content"][0]["text"])
        self.assertEqual(found["matches"][0]["line"],1)

    def test_gateway_denies_arbitrary_arguments_and_raw_executable(self):
        g=gateway.Gateway(gateway.Config({}, (), self.home))
        with self.assertRaisesRegex(gateway.GatewayError,"Unknown or disabled"):
            g.call("execute_shell",{"command":"cat /etc/shadow"})
        with self.assertRaisesRegex(gateway.GatewayError,"Unexpected"):
            g.call("case_open",{"path":"/etc"})
        with self.assertRaisesRegex(gateway.GatewayError,"Invalid"):
            g.call("case_status",{"case_id":"../bad"})


if __name__ == "__main__":
    unittest.main()
