"""Real Ed25519 synthetic signed checkpoints and fail-closed prefix comparison."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from anchorwork import (DOMAIN, MAX_ENVELOPE_BYTES, create_unsigned_checkpoint,
                        validate_unsigned_preview, verify_signed_checkpoint)
from case_handoff import _canonical
from casework import CaseError, CaseStore
from operator_sign_preservation_checkpoint import (canonical, sign_preview,
                                                   validate_preview, _read_source)
import operator_sign_preservation_checkpoint as offhost_signer
from unittest.mock import patch
from preservationwork import propose_or_record, read_controls


class SignedPreservationAnchorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "gateway-synthetic"
        self.home.mkdir(mode=0o700)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        src = self.store.inbox / "customer-private-reference.log"
        self.secret = b"synthetic password=must-not-leak\n"
        src.write_bytes(self.secret)
        src.chmod(0o600)
        self.artifact = self.store.register(self.case, src.name)
        self.reference = hashlib.sha256(b"separately recorded source").hexdigest()
        self.trust = self.root / "trusted-separate-key"
        self.trust.mkdir(mode=0o700)
        self.external = self.root / "operator-workstation-synthetic"
        self.external.mkdir(mode=0o700)
        self.key = self.external / "preservation_key.pem"
        self.openssl = shutil.which("openssl") or ""
        if not self.openssl:
            self.fail("Native OpenSSL required for real signed checkpoint tests")
        self._generate_key(self.key, self.trust / "preservation_anchor_ed25519_pub.pem")

    def _generate_key(self, priv, pub):
        for argv in (
            [self.openssl, "genpkey", "-algorithm", "ED25519", "-out", str(priv)],
            [self.openssl, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)]
        ):
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=15, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("ascii", "replace"))
        priv.chmod(0o600)
        pub.chmod(0o644)

    def _add(self, *, reason="investigation"):
        request = dict(action="PRESERVATION_HOLD", reason_code=reason,
                       reference_sha256=self.reference)
        planned = propose_or_record(self.store, self.case, **request)
        self.assertEqual(planned["status"], "PREVIEW_ONLY")
        return propose_or_record(self.store, self.case, **request,
                                 confirm=True, plan_sha256=planned["plan_sha256"])

    def _packet(self):
        return create_unsigned_checkpoint(self.store, self.case)

    def _signed(self):
        packet = self._packet()
        raw = _canonical(packet) + b"\n"
        signed = sign_preview(raw, self.key, self.openssl)
        self.assertEqual(signed["payload"]["domain"], DOMAIN)
        return canonical(signed) + b"\n"

    def _verify(self, data):
        return verify_signed_checkpoint(self.store, self.case, data,
                                        trust_root=self.trust,
                                        trusted_uid=os.getuid())

    def test_zero_records_are_not_anchorable(self):
        with self.assertRaisesRegex(CaseError, "No established"):
            self._packet()
        self.assertFalse(read_controls(self.store, self.case)["record_count"])

    def test_valid_signed_current_ledger_exact_and_redacted(self):
        self._add()
        before = self.artifact["sha256"]
        packet = self._packet()
        self.assertEqual(validate_unsigned_preview(_canonical(packet)), packet["payload"])
        self.assertEqual(validate_preview(_canonical(packet))[1], packet["payload_sha256"])
        result = self._verify(self._signed())
        self.assertEqual(result["status"], "SIGNED_CHECKPOINT_MATCHES_CURRENT_LEDGER")
        self.assertTrue(result["checkpoint_signature_verified"])
        self.assertTrue(result["signed_prefix_matches"])
        self.assertTrue(result["signed_checkpoint_covers_current_ledger"])
        self.assertEqual(result["additional_unanchored_records"], 0)
        self.assertEqual(result["checkpoint_record_count"], 1)
        for key in ("external_custody_independently_verified",
                    "latest_checkpoint_independently_verified",
                    "signer_legal_authority_verified",
                    "checkpoint_timestamp_authoritative",
                    "ledger_fully_immutable", "deletion_authorized",
                    "public_disclosure_approved", "hold_release_supported"):
            self.assertFalse(result[key], key)
        self.assertEqual(result["originals_removed"], 0)
        self.assertEqual(result["raw_originals_exported"], 0)
        self.assertEqual(self.artifact["sha256"], before)
        encoded = json.dumps(result).encode()
        for confidential in (self.secret, b"customer-private-reference.log",
                             self.reference.encode(), str(self.key).encode()):
            self.assertNotIn(confidential, encoded)

    def test_prefix_remains_valid_but_new_records_are_unanchored(self):
        self._add()
        anchor = self._signed()
        self._add(reason="customer_request")
        result = self._verify(anchor)
        self.assertEqual(result["status"], "SIGNED_PREFIX_MATCHES_WITH_UNANCHORED_TAIL")
        self.assertTrue(result["signed_prefix_matches"])
        self.assertFalse(result["signed_checkpoint_covers_current_ledger"])
        self.assertEqual(result["additional_unanchored_records"], 1)
        self.assertEqual(read_controls(self.store, self.case)["active_hold_count"], 2)

    def test_truncated_signed_history_detected(self):
        self._add()
        self._add(reason="compliance_review")
        anchor = self._signed()
        second = sorted((self.home / ".local/share/rocky-mcp-gateway" /
                         "cases" / self.case / "preservation").iterdir())[1]
        second.unlink()
        self.assertEqual(self._verify(anchor)["status"],
                         "LEDGER_TRUNCATED_BELOW_SIGNED_CHECKPOINT")
        self.assertFalse(self._verify(anchor)["signed_prefix_matches"])

    def test_entire_history_deleted_detected_by_external_checkpoint(self):
        self._add()
        anchor = self._signed()
        folder = (self.store.cases / self.case / "preservation")
        for p in folder.iterdir():
            p.unlink()
        folder.rmdir()
        answer = self._verify(anchor)
        self.assertEqual(answer["current_record_count"], 0)
        self.assertEqual(answer["status"], "LEDGER_TRUNCATED_BELOW_SIGNED_CHECKPOINT")
        self.assertFalse(answer["signed_checkpoint_covers_current_ledger"])

    def test_validly_rewritten_local_chain_diverges_from_signed_prefix(self):
        self._add()
        anchor = self._signed()
        folder = self.store.cases / self.case / "preservation"
        path = next(folder.iterdir())
        old = json.loads(path.read_bytes())
        old["reason_code"] = "customer_request"  # same-UID rewrite example
        path.write_bytes(_canonical(old))
        path.chmod(0o600)
        self.assertEqual(read_controls(self.store, self.case)["active_hold_count"], 1)
        outcome = self._verify(anchor)
        self.assertEqual(outcome["status"], "LEDGER_PREFIX_DIVERGED_FROM_SIGNED_CHECKPOINT")
        self.assertFalse(outcome["signed_prefix_matches"])

    def test_invalid_modified_signed_payload_rejected(self):
        self._add()
        doc = json.loads(self._signed())
        doc["payload"]["head_sha256"] = "a" * 64
        with self.assertRaisesRegex(CaseError, "signature did not verify"):
            self._verify(canonical(doc))

    def test_invalid_modified_signature_rejected(self):
        self._add()
        doc = json.loads(self._signed())
        sig = base64.b64decode(doc["signature"])
        doc["signature"] = base64.b64encode(bytes([sig[0] ^ 1]) + sig[1:]).decode("ascii")
        with self.assertRaisesRegex(CaseError, "signature did not verify"):
            self._verify(canonical(doc))

    def test_untrusted_signing_key_rejected(self):
        self._add()
        packet = _canonical(self._packet())
        rogue = self.external / "rogue.pem"
        rogue_pub = self.external / "rogue_pub.pem"
        self._generate_key(rogue, rogue_pub)
        envelope = sign_preview(packet, rogue, self.openssl)
        with self.assertRaisesRegex(CaseError, "signature did not verify"):
            self._verify(canonical(envelope))

    def test_key_symlink_and_group_writable_refused(self):
        self._add()
        data = self._signed()
        trusted = self.trust / "preservation_anchor_ed25519_pub.pem"
        trusted.chmod(0o666)
        with self.assertRaisesRegex(CaseError, "key identity invalid"):
            self._verify(data)
        trusted.chmod(0o644)
        elsewhere = self.external / "key_backup.pub"
        trusted.rename(elsewhere)
        trusted.symlink_to(elsewhere)
        with self.assertRaises(CaseError):
            self._verify(data)

    def test_non_ed25519_public_key_refused_by_algorithm_check(self):
        self._add()
        data = self._signed()
        unrelated = self.external / "wrong-ec-private.pem"
        public = self.trust / "preservation_anchor_ed25519_pub.pem"
        generated = subprocess.run(
            [self.openssl, "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(unrelated)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())
        changed = subprocess.run(
            [self.openssl, "pkey", "-in", str(unrelated), "-pubout", "-out",
             str(public)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(changed.returncode, 0, changed.stderr.decode())
        public.chmod(0o644)
        with self.assertRaisesRegex(CaseError, "must be Ed25519"):
            self._verify(data)

    def test_nonexistent_trust_anchor_fails_not_self_signed(self):
        self._add()
        data = self._signed()
        trusted = self.trust / "preservation_anchor_ed25519_pub.pem"
        trusted.unlink()
        with self.assertRaises((CaseError, OSError)):
            self._verify(data)

    def test_cross_case_signed_checkpoint_refused(self):
        self._add()
        another = self.store.open_case()["case_id"]
        data = self._signed()
        with self.assertRaisesRegex(CaseError, "different case"):
            verify_signed_checkpoint(self.store, another, data,
                                     trust_root=self.trust, trusted_uid=os.getuid())

    def test_malformed_duplicate_extra_fields_and_oversize_refused(self):
        self._add()
        signed = self._signed()
        with self.assertRaisesRegex(CaseError, "duplicate"):
            self._verify(signed.strip()[:-1] + b',"payload":{}}')
        obj = json.loads(signed)
        obj["extra"] = "malicious"
        with self.assertRaisesRegex(CaseError, "schema"):
            self._verify(canonical(obj))
        with self.assertRaisesRegex(CaseError, "size"):
            self._verify(b"X" * (MAX_ENVELOPE_BYTES + 1))

    def test_reject_bogus_types_negative_count_future_time_and_domain(self):
        self._add()
        base = json.loads(self._signed())
        changes = [
            {"record_count": True},
            {"record_count": -1},
            {"record_count": 0},
            {"record_count": 129},
            {"domain": "rocky-eng:execution-grant:v1"},
            {"issued_at": int(time.time()) + 3600},
            {"nonce": "bad"},
            {"head_sha256": "nonhex"},
        ]
        for update in changes:
            with self.subTest(update=update):
                edited = json.loads(self._signed())
                edited["payload"].update(update)
                with self.assertRaises(CaseError):
                    self._verify(canonical(edited))

    def test_offhost_preview_file_symlink_hardlink_and_good_identity(self):
        self._add()
        checkpoint = self.external / "private-checkpoint.json"
        checkpoint.write_bytes(_canonical(self._packet()))
        checkpoint.chmod(0o600)
        self.assertEqual(_read_source(checkpoint), checkpoint.read_bytes())
        alias = self.external / "preview-hardlink.json"
        os.link(checkpoint, alias)
        with self.assertRaisesRegex(ValueError, "identity or privacy"):
            _read_source(checkpoint)
        alias.unlink()
        alias.symlink_to(checkpoint)
        with self.assertRaisesRegex(ValueError, "symlink"):
            _read_source(alias)

    def test_offhost_preview_open_time_inode_replacement_refused(self):
        self._add()
        checkpoint = self.external / "review-source.json"
        raw = _canonical(self._packet())
        checkpoint.write_bytes(raw)
        checkpoint.chmod(0o600)
        preserved = self.external / "source-before-swap.json"
        real_open = offhost_signer.os.open
        replaced = False

        def swap_on_open(path, flags, *args, **kwargs):
            nonlocal replaced
            if Path(path) == checkpoint and not replaced:
                replaced = True
                checkpoint.rename(preserved)
                checkpoint.write_bytes(raw)
                checkpoint.chmod(0o600)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(offhost_signer.os, "open", side_effect=swap_on_open):
            with self.assertRaisesRegex(ValueError, "changed while opening"):
                _read_source(checkpoint)
        self.assertTrue(replaced)

    def test_offhost_preview_digest_mutation_and_key_privacy_refused(self):
        self._add()
        packet = self._packet()
        packet["payload_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            sign_preview(_canonical(packet), self.key, self.openssl)
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "not private"):
            sign_preview(_canonical(self._packet()), self.key, self.openssl)

    def test_cli_preview_and_negative_commands_no_arbitrary_trust_paths(self):
        self._add()
        cli = Path(__file__).resolve().parents[1] / "scripts/preservation_anchor_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        def call(*args, payload=b""):
            return subprocess.run([sys.executable, "-u", str(cli), *args],
                                  input=payload, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=30, check=False)
        accepted = call("preview", "--case-id", self.case)
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
        doc = json.loads(accepted.stdout)
        self.assertEqual(doc["status"], "UNSIGNED_CHECKPOINT_PREVIEW")
        self.assertEqual(doc["payload"]["record_count"], 1)
        self.assertNotIn(self.reference.encode(), accepted.stdout)
        self.assertNotIn(self.secret, accepted.stdout)
        for forbidden in [
            ("delete", "--case-id", self.case),
            ("verify", "--case-id", self.case, "--trusted-key", str(self.key)),
            ("verify", "--case-id", self.case, "--release"),
        ]:
            self.assertEqual(call(*forbidden).returncode, 2, forbidden)

    def test_canonical_checkpoint_required(self):
        self._add()
        data = self._signed()
        with self.assertRaisesRegex(CaseError, "not canonical"):
            self._verify(data.replace(b',"signature":', b', "signature":'))
        with self.assertRaisesRegex(CaseError, "not canonical"):
            validate_unsigned_preview(_canonical(self._packet()).replace(
                b',"status":', b', "status":'))

    def test_local_case_status_never_discloses_anchor_heads(self):
        self._add()
        data = read_controls(self.store, self.case)
        self.assertNotIn("record_heads", data)
        self.assertNotIn("source_references", data)
        self.assertFalse(data["legal_hold_authority_verified"])
        self.assertFalse(data["deletion_authorized"])


if __name__ == "__main__":
    unittest.main()
