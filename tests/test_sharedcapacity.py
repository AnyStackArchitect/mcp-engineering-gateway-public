"""Unenrolled mode and untrusted enrollment refuse; native two-UID proof is CI."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import capacitywork
import sharedcapacity
from casework import CaseStore,CaseError


class SharedCapacityTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);home=self.root/'home';home.mkdir(mode=0o700)
        self.store=CaseStore(home)
        self.store._ensure_store()

    def test_absent_policy_retains_explicit_local_only_admission(self):
        with patch.object(sharedcapacity,'POLICY_FILE',self.root/'absent.json'):
            self.assertIsNone(sharedcapacity.load_policy(self.store))
            with capacitywork.admission_lock(self.store):
                self.assertIsNone(sharedcapacity.current(self.store))
                self.assertEqual(capacitywork.outstanding_reservations(self.store),0)

    def test_present_user_writable_or_symlink_policy_never_falls_back(self):
        path=self.root/'policy.json';path.write_text('{}')
        link=self.root/'link.json';link.symlink_to(path)
        for candidate in (path,link):
            with self.subTest(path=candidate),patch.object(sharedcapacity,'POLICY_FILE',candidate):
                with self.assertRaises((CaseError,OSError)):
                    with capacitywork.admission_lock(self.store):pass

    def test_aggregate_cannot_silently_read_enrolled_policy_without_lock(self):
        path=self.root/'policy.json';path.write_text('{}')
        with patch.object(sharedcapacity,'POLICY_FILE',path),self.assertRaises(CaseError):
            sharedcapacity.aggregate(self.store,0)

    def test_store_slots_are_opaque_and_distinct(self):
        first=sharedcapacity.slot_id(self.store.base)
        self.assertEqual(len(first),64)
        self.assertNotEqual(first,sharedcapacity.slot_id(self.root/'different'))
        self.assertNotIn(str(self.root),first)

    def test_capacity_helper_is_preloaded_before_identity_crossing(self):
        import builtins
        original=builtins.__import__
        def unavailable(name,*args,**kwargs):
            if name=='sharedcapacity':raise ImportError('checkout inaccessible after UID change')
            return original(name,*args,**kwargs)
        with patch.object(sharedcapacity,'POLICY_FILE',self.root/'absent.json'), \
                patch.object(builtins,'__import__',side_effect=unavailable):
            with capacitywork.admission_lock(self.store):
                self.assertEqual(capacitywork.outstanding_reservations(self.store),0)
