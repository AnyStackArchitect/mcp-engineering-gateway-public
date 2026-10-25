"""Known-answer tests for durable fixed-template analysis job execution."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import casework
import gateway
import jobwork


def pcap():
    return (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2,4,0,0,65535,1) +
            struct.pack("<IIII", 1720000000,0,4,4) + b"TEST")


class JobTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name)
        self.store=jobwork.JobStore(self.home)
        self.cid=self.store.cases.open_case()["case_id"]

    def stage(self,name,data):
        self.store.cases.inbox.joinpath(name).write_bytes(data)
        self.store.cases.inbox.joinpath(name).chmod(0o600)

    def register(self,name,data):
        self.stage(name,data)
        return self.store.cases.register(self.cid,name)["artifact_id"]

    def test_queue_and_list_survives_new_object(self):
        art=self.register("messages.log", b"2026-10-15T15:00:00Z BOOT\n")
        x=self.store.submit("index_log",self.cid,artifact_id=art)
        assert x["status"]=="QUEUED"
        replacement=jobwork.JobStore(self.home)
        assert replacement.status(x["job_id"])["state"]=="QUEUED"
        listing=replacement.list()
        self.assertEqual(listing["total_jobs"],1)
        self.assertNotIn(str(self.home),json.dumps(listing))
        self.assertEqual(listing["jobs"][0]["kind"],"index_log")

    def test_fixed_import_job_and_persisted_result(self):
        self.stage("large.log",b"2026-10-15T12:00:00Z SUCCESS\n")
        j=self.store.submit("import_staged",self.cid,filename="large.log")
        outcome=self.store.work_once()
        self.assertEqual(outcome["state"],"SUCCEEDED")
        result=jobwork.JobStore(self.home).result(j["job_id"])
        self.assertEqual(result["result"]["status"],"REGISTERED")
        self.assertEqual(self.store.cases.status(self.cid)["artifact_count"],1)
        self.assertNotIn("large.log",json.dumps(result))

    def test_index_log_job_and_result(self):
        art=self.register("error.log",b"2026-10-15T12:00:00Z ERROR password=abc\n")
        j=self.store.submit("index_log",self.cid,artifact_id=art)
        self.assertEqual(self.store.work_once()["state"],"SUCCEEDED")
        result=self.store.result(j["job_id"])
        self.assertEqual(result["result"]["lines_indexed"],1)
        find=self.store.cases.search_log(self.cid,art,"ERROR")
        self.assertEqual(len(find["matches"]),1)
        self.assertNotIn("abc", " ".join(item["excerpt"] for item in find["matches"]))

    def test_pcap_summary_job(self):
        art=self.register("capture.cap",pcap())
        j=self.store.submit("pcap_summary",self.cid,artifact_id=art)
        self.assertEqual(self.store.work_once()["state"],"SUCCEEDED")
        result=self.store.result(j["job_id"])
        self.assertEqual(result["result"]["packets_examined"],1)
        self.assertFalse(result["result"]["payloads_examined"])

    def test_queued_cancel_has_no_side_effect(self):
        self.stage("never.log",b"secret")
        j=self.store.submit("import_staged",self.cid,filename="never.log")
        cancelled=self.store.cancel(j["job_id"])
        self.assertEqual(cancelled["state"],"CANCELLED")
        self.assertEqual(self.store.work_once()["processed"],0)
        self.assertEqual(self.store.cases.status(self.cid)["artifact_count"],0)
        self.assertEqual(self.store.result(j["job_id"])["failure_code"],"operator_cancelled")

    def test_recover_stale_running_is_not_success(self):
        self.stage("x.log",b"data")
        j=self.store.submit("import_staged",self.cid,filename="x.log")
        with self.store._db() as db:
            db.execute("UPDATE jobs SET state='RUNNING' WHERE id=?",(j["job_id"],))
            db.commit()
        self.assertEqual(self.store.work_once()["processed"],0)
        status=self.store.status(j["job_id"])
        self.assertEqual(status["state"],"INTERRUPTED")
        self.assertEqual(status["outcome"],"UNKNOWN")

    def test_running_cancel_sets_flag_and_worker_respects(self):
        art=self.register("x.log",b"hello\n")
        j=self.store.submit("index_log",self.cid,artifact_id=art)
        original=self.store.cases.index_log
        def simulate_cancellation(*args,**kwargs):
            self.store.cancel(j["job_id"])
            kwargs["should_cancel"]()
            return original(*args,**kwargs)
        with patch.object(self.store.cases,"index_log",side_effect=simulate_cancellation):
            status=self.store.work_once()
        self.assertEqual(status["state"],"CANCELLED")
        self.assertEqual(self.store.status(j["job_id"])["outcome"],"CANCELLED")
        self.assertFalse((self.store.cases.cases/self.cid/"indexes"/(art+".sqlite3")).exists())

    def test_job_error_does_not_claim_success(self):
        art=self.register("broken.cap",b"\xd4\xc3\xb2\xa1garbage")
        j=self.store.submit("pcap_summary",self.cid,artifact_id=art)
        self.assertEqual(self.store.work_once()["state"],"FAILED")
        self.assertEqual(self.store.result(j["job_id"])["outcome"],"FAIL")
        self.assertNotIn(str(self.home),json.dumps(self.store.result(j["job_id"])))

    def test_refuse_unapproved_job_kind_and_parameter_combinations(self):
        with self.assertRaisesRegex(jobwork.JobError,"Unknown job"):
            self.store.submit("run_python",self.cid,filename="evil.py")
        with self.assertRaisesRegex(jobwork.JobError,"requires approved"):
            self.store.submit("import_staged",self.cid,filename="../.ssh/id_rsa")
        with self.assertRaisesRegex(jobwork.JobError,"requires registered"):
            self.store.submit("pcap_summary",self.cid,artifact_id="not-an-id")
        with self.assertRaisesRegex(jobwork.JobError,"requires approved"):
            self.store.submit("import_staged",self.cid,artifact_id="a"*32,filename="x.log")

    def test_worker_queue_capacity(self):
        self.stage("x.log",b"ok")
        with patch.object(jobwork,"MAX_QUEUED",1):
            self.store.submit("import_staged",self.cid,filename="x.log")
            with self.assertRaisesRegex(jobwork.JobError,"capacity"):
                self.store.submit("import_staged",self.cid,filename="x.log")

    def test_worker_history_capacity(self):
        self.stage("x.log",b"ok")
        with patch.object(jobwork,"MAX_HISTORY",1):
            x=self.store.submit("import_staged",self.cid,filename="x.log")
            self.store.cancel(x["job_id"])
            with self.assertRaisesRegex(jobwork.JobError,"capacity"):
                self.store.submit("import_staged",self.cid,filename="x.log")

    def test_private_db_refuses_relaxed_permissions(self):
        self.assertEqual(self.store.list()["total_jobs"],0)
        db=self.store.dbfile
        db.chmod(0o644)
        with self.assertRaisesRegex(jobwork.JobError,"permissions"):
            self.store.list()

    def test_symlink_job_database_rejected(self):
        self.store.list()
        db=self.store.dbfile
        target=db.parent/"another.sqlite3"
        db.rename(target)
        db.symlink_to(target)
        with self.assertRaisesRegex(jobwork.JobError,"symlink"):
            self.store.list()

    def test_second_worker_lock_blocked(self):
        self.store.list()
        fd=self.store._worker_exclusive()
        try:
            with self.assertRaisesRegex(jobwork.JobError,"Another analysis worker"):
                self.store.work_once()
        finally:
            import fcntl,os
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_worker_mode_can_exceed_sync_artifact_threshold(self):
        self.stage("bigger.log",b"extended")
        j=self.store.submit("import_staged",self.cid,filename="bigger.log")
        with patch.object(casework,"MAX_ARTIFACT",3):
            self.assertEqual(self.store.work_once()["state"],"SUCCEEDED")
        self.assertEqual(self.store.result(j["job_id"])["result"]["bytes"],8)

    def test_worker_cancel_flag_checked_during_import(self):
        self.stage("big.log",b"aaa"*300)
        j=self.store.submit("import_staged",self.cid,filename="big.log")
        original=self.store.cases.register
        def cancelled(*args,**kwargs):
            self.store.cancel(j["job_id"])
            kwargs["should_cancel"]()
            return original(*args,**kwargs)
        with patch.object(self.store.cases,"register",side_effect=cancelled):
            status=self.store.work_once()
        self.assertEqual(status["state"],"CANCELLED")
        self.assertEqual(self.store.cases.status(self.cid)["artifact_count"],0)

    def test_mcp_job_client_does_not_get_to_run_shell(self):
        g=gateway.Gateway(gateway.Config({},(),self.home))
        client=gateway.MCPServer(g)
        names=[entry["name"] for entry in g.tools()]
        self.assertIn("job_submit",names)
        self.assertNotIn("shell_execute",names)
        self.assertFalse(next(x for x in g.tools() if x["name"]=="job_submit")["annotations"]["readOnlyHint"])
        case=g.call("case_open",{})["case_id"]
        self.stage("test.log",b"log")
        data=g.call("job_submit",{"kind":"import_staged","case_id":case,"filename":"test.log"})
        self.assertEqual(data["status"],"QUEUED")
        with self.assertRaises(gateway.GatewayError):
            g.call("job_submit",{"kind":"shell_execute","case_id":case,"filename":"test.log"})


if __name__=="__main__":
    unittest.main()
