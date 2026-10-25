"""Phase B: explicit UTC and source-linked event-window known answers."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import casework
import correlationwork
import eventmodel
import gateway
import jobwork
import timelinework


class EventModelTests(unittest.TestCase):
    def test_clock_basis_never_implies_synchronized_clocks(self):
        self.assertEqual(eventmodel.checked_time_basis(
            "2026-10-17T10:02:00+00:00", "OFFSET"),
            "DECLARED_UTC_CLOCK_UNVERIFIED")
        self.assertEqual(eventmodel.checked_time_basis(None, "NO_TIMEZONE"),
                         "UNANCHORED_NO_UTC")
        for utc, quality in [
            ("2026-10-17T10:00:00", "OFFSET"),
            ("2026-10-17T10:00:00+02:00", "OFFSET"),
            ("2026-10-17T10:00:00Z", "NO_TIMESTAMP"),
            (None, "OFFSET"), (None, "not-real"),
            ("garbage", "EXPLICIT_EPOCH"),
        ]:
            with self.subTest(utc=utc, quality=quality):
                with self.assertRaises(casework.CaseError):
                    eventmodel.checked_time_basis(utc, quality)

    def test_window_microsecond_precision_and_bounds(self):
        stamp = "2026-10-17T10:00:00.000500Z"
        self.assertEqual(eventmodel.window_bounds(stamp, 1, 2),
            ("2026-10-17T09:59:59.999500+00:00",
             "2026-10-17T10:00:00.002500+00:00"))
        self.assertEqual(eventmodel.observed_delta_ms(
            stamp, "2026-10-17T10:00:00.001250Z"), .75)
        for item in [(True, 0), (-1, 0), (0, 300001), ("1", 0), (1.5, 2)]:
            with self.assertRaises(casework.CaseError):
                eventmodel.window_bounds(stamp, *item)


class CaseWindowTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.jobs = jobwork.JobStore(self.home)
        self.store = self.jobs.cases
        self.case = self.store.open_case()["case_id"]

    def add_log(self, name, text):
        path = self.store.inbox / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return self.store.register(self.case, name)["artifact_id"]

    def build(self):
        self.first = self.add_log("first.log",
            "2026-10-17T10:00:00Z ERROR password=never-expose\n"
            "Oct 17 10:00:00 unanchored source\n")
        self.second = self.add_log("second.log",
            "2026-10-17T10:00:01.250+00:00 WARN recovered\n"
            "2026-10-17T10:00:19Z late event\n")
        timelinework.build_timeline(self.store, self.case)
        correlationwork.build_correlation(self.store, self.case)
        q = correlationwork.correlation_query(self.store, self.case,
                                              include_unknown=True)
        self.revision = q["index_revision"]
        self.anchor = next(r["event_id"] for r in q["events"]
                           if r["artifact_id"] == self.first and r["utc"])
        self.unknown = next(r["event_id"] for r in q["events"]
                            if r["utc"] is None)
        return q

    def test_known_answer_cross_source_delta_provenance_and_privacy(self):
        q = self.build()
        self.assertEqual(len(self.revision), 32)
        self.assertEqual({r["time_basis"] for r in q["events"]},
                         {"DECLARED_UTC_CLOCK_UNVERIFIED", "UNANCHORED_NO_UTC"})
        w = correlationwork.correlation_window(
            self.store, self.case, index_revision=self.revision,
            anchor_event_id=self.anchor, before_ms=1000, after_ms=1500)
        self.assertEqual(len(w["events"]), 1)
        event = w["events"][0]
        self.assertEqual(event["artifact_id"], self.second)
        self.assertEqual(event["locator_type"], "line")
        self.assertEqual(event["locator_number"], 1)
        self.assertEqual(event["observed_delta_ms"], 1250.0)
        self.assertFalse(w["clock_offsets_applied"])
        self.assertFalse(w["cross_source_identity_inferred"])
        self.assertFalse(w["causality_inferred"])
        self.assertEqual(w["time_basis"], "DECLARED_UTC_CLOCK_UNVERIFIED")
        self.assertEqual(w["unknown_utc_event_count"], 1)
        self.assertNotIn("never-expose", json.dumps((q, w)))
        self.assertNotIn("first.log", json.dumps((q, w)))
        self.assertNotIn(str(self.home), json.dumps((q, w)))

    def test_untimed_anchor_refused_and_no_false_clock_alignment(self):
        self.build()
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_window(self.store, self.case,
                index_revision=self.revision, anchor_event_id=self.unknown)
        w = correlationwork.correlation_window(self.store, self.case,
            index_revision=self.revision, anchor_event_id=self.anchor,
            before_ms=0, after_ms=0)
        self.assertEqual(w["events"], [])
        self.assertEqual(w["clock_alignment"], "UNVERIFIED")

    def test_revision_cannot_replay_after_rebuild(self):
        self.build()
        old = self.revision
        correlationwork.build_correlation(self.store, self.case)
        self.assertNotEqual(correlationwork.correlation_query(
            self.store, self.case)["index_revision"], old)
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_window(self.store, self.case,
                index_revision=old, anchor_event_id=self.anchor)

    def test_untrusted_inputs_and_extra_tool_arguments_rejected(self):
        self.build()
        good = {"index_revision": self.revision, "anchor_event_id": self.anchor}
        for changed in [
            {"anchor_event_id": True}, {"anchor_event_id": -1},
            {"anchor_event_id": 999999}, {"anchor_event_id": "1"},
            {"before_ms": -1}, {"before_ms": True},
            {"after_ms": 300001}, {"limit": 21}, {"limit": False},
            {"offset": -1}, {"cross_source_only": "true"},
            {"index_revision": "f" * 32},
        ]:
            with self.subTest(changed=changed):
                with self.assertRaises(casework.CaseError):
                    correlationwork.correlation_window(
                        self.store, self.case, **(good | changed))
        gw = gateway.Gateway(gateway.Config({}, (), self.home))
        schema = {t["name"]: t for t in gw.tools()}
        self.assertIn("correlation_window", schema)
        self.assertNotIn("shell", schema)
        with self.assertRaises(gateway.GatewayError):
            gw.call("correlation_window", {
                "case_id": self.case, **good, "raw_path": "/etc/shadow"})

    def test_cross_source_toggle_and_pagination(self):
        self.build()
        base = dict(index_revision=self.revision,
                    anchor_event_id=self.anchor, before_ms=0, after_ms=20000)
        other = correlationwork.correlation_window(self.store, self.case, **base)
        self.assertEqual({e["artifact_id"] for e in other["events"]},
                         {self.second})
        all_sources = correlationwork.correlation_window(
            self.store, self.case, **base, cross_source_only=False,
            limit=1)
        self.assertEqual(len(all_sources["events"]), 1)
        self.assertIsNotNone(all_sources["next_offset"])

    def test_index_stale_when_new_source_arrives(self):
        self.build()
        self.add_log("third.log", "2026-10-17T10:00:00Z changed\n")
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_window(self.store, self.case,
                index_revision=self.revision, anchor_event_id=self.anchor)

    def test_actual_gateway_window_response(self):
        self.build()
        gw = gateway.Gateway(gateway.Config({}, (), self.home))
        answer = gw.call("correlation_window", {
            "case_id": self.case, "index_revision": self.revision,
            "anchor_event_id": self.anchor, "before_ms": 1000,
            "after_ms": 1500})
        self.assertEqual(answer["events"][0]["observed_delta_ms"], 1250.0)
        self.assertEqual(answer["clock_alignment"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
