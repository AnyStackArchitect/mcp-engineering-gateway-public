"""Two independently held Ed25519 grants for an exact case disposition plan.

There is no trust-path, enable-policy, private-key or clock override in the CLI.
Native Windows signing remains unavailable until ACL-aware key custody is proven.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

DOMAIN = "rocky-eng:case-disposition:v1"
ROLES = ("policy_owner", "evidence_custodian")
TRUST_ROOT = Path("/etc/rocky-eng")
POLICY_PATH = TRUST_ROOT / "case-disposition-policy.json"
KEY_NAMES = {role: "disposition_" + role + "_ed25519_pub.pem" for role in ROLES}
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
MAX_BYTES = 32768
MAX_SECONDS = 300
ATTESTATIONS = {
    "authority_record_sha256", "backup_manifest_sha256",
    "restore_evidence_sha256", "latest_checkpoint_record_sha256",
}
PLAN_FIELDS = {"schema", "action", "case_id", "state_sha256", "history_sha256",
               "minimum_age_days", "retention_start_utc", "original_count",
               "original_bytes", "remaining_evidence_files"}


class DispositionGrantError(Exception):
    """A disposition approval or deployment policy cannot be trusted."""


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DispositionGrantError("Duplicate disposition key")
        out[key] = value
    return out


def decode(raw: bytes, maximum: int = MAX_BYTES) -> dict:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        raise DispositionGrantError("Disposition input size invalid")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_duplicates)
        if not isinstance(value, dict) or raw.strip() != canonical(value):
            raise DispositionGrantError("Disposition input must be canonical JSON")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DispositionGrantError("Disposition JSON invalid") from exc


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_size,
            info.st_nlink, stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_ctime_ns)


def private_read(path: Path, maximum: int = MAX_BYTES, *, private=True,
                 owner: int | None = None, link_count: int = 1) -> bytes:
    before = path.lstat()
    expected_owner = os.getuid() if owner is None else owner
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != link_count
            or before.st_uid != expected_owner
            or before.st_mode & (0o077 if private else 0o022)
            or not 0 < before.st_size <= maximum):
        raise DispositionGrantError("Disposition file identity invalid")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if _identity(before) != _identity(os.fstat(fd)):
            raise DispositionGrantError("Disposition file changed while opening")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if (len(data) != before.st_size
                or _identity(before) != _identity(os.fstat(fd))
                or _identity(before) != _identity(path.lstat())):
            raise DispositionGrantError("Disposition file changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def _admin_path(path: Path) -> None:
    if not path.is_absolute():
        raise DispositionGrantError("Disposition trust path invalid")
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (item != path and not stat.S_ISDIR(info.st_mode))):
            raise DispositionGrantError("Disposition trust path is not administrator controlled")


def production_gate() -> None:
    """Disabled until a root-managed policy explicitly accepts the local model.

This gate does not pretend gateway-owned state defeats a hostile same-UID
process. Administrators must review that limitation before enabling production.
"""
    if os.name != "posix" or os.geteuid() == 0:
        raise DispositionGrantError("Disposition requires a nonroot POSIX operator")
    try:
        _admin_path(POLICY_PATH)
        policy = decode(private_read(POLICY_PATH, 4096, private=False, owner=0), 4096)
    except OSError as exc:
        raise DispositionGrantError("Production disposition is disabled: policy unenrolled") from exc
    if (set(policy) != {"schema", "enabled", "case_owner_uid", "same_uid_risk_accepted"}
            or type(policy["schema"]) is not int or policy["schema"] != 1
            or policy["enabled"] is not True
            or type(policy["case_owner_uid"]) is not int
            or policy["case_owner_uid"] != os.getuid()
            or policy["same_uid_risk_accepted"] is not True):
        raise DispositionGrantError("Production disposition policy does not enable this operator")


def _public_key(role: str) -> bytes:
    path = TRUST_ROOT / KEY_NAMES[role]
    try:
        _admin_path(path)
        return private_read(path, 2048, private=False, owner=0)
    except OSError as exc:
        raise DispositionGrantError("Disposition role verification key unenrolled") from exc


def validate_plan(plan: dict) -> dict:
    if (not isinstance(plan, dict) or set(plan) != PLAN_FIELDS
            or type(plan["schema"]) is not int or plan["schema"] != 1
            or plan["action"] not in ("RETIRE", "RESTORE", "FINAL_DELETE")
            or not isinstance(plan["case_id"], str) or not HEX32.fullmatch(plan["case_id"])
            or any(not isinstance(plan[k], str) or not HEX64.fullmatch(plan[k])
                   for k in ("state_sha256", "history_sha256"))
            or type(plan["minimum_age_days"]) is not int
            or not 1 <= plan["minimum_age_days"] <= 3650
            or not isinstance(plan["retention_start_utc"], str)
            or len(plan["retention_start_utc"]) != 20
            or any(type(plan[k]) is not int or not 0 <= plan[k] <= 40 * 1024 ** 3
                   for k in ("original_count", "original_bytes", "remaining_evidence_files"))):
        raise DispositionGrantError("Disposition plan invalid")
    return plan


def validate_payload(payload: dict, *, check_time=True) -> dict:
    if (not isinstance(payload, dict)
            or set(payload) != {"domain", "role", "decision", "plan", "plan_sha256",
                                "nonce", "issued_at", "expires_at", "attestations"}):
        raise DispositionGrantError("Disposition grant schema invalid")
    plan = validate_plan(payload["plan"])
    attest = payload["attestations"]
    if (payload["domain"] != DOMAIN or payload["role"] not in ROLES
            or payload["decision"] != "APPROVE"
            or payload["plan_sha256"] != hashlib.sha256(canonical(plan)).hexdigest()
            or not isinstance(payload["nonce"], str) or not HEX32.fullmatch(payload["nonce"])
            or type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int
            or payload["issued_at"] <= 0
            or not 0 < payload["expires_at"] - payload["issued_at"] <= MAX_SECONDS
            or not isinstance(attest, dict) or set(attest) != ATTESTATIONS
            or any(not isinstance(value, str) or not HEX64.fullmatch(value)
                   or value == "0" * 64 for value in attest.values())):
        raise DispositionGrantError("Disposition grant fields invalid")
    if check_time:
        check_expiry([payload])
    return payload


def check_expiry(payloads: list[dict]) -> None:
    current = int(time.time())
    for value in payloads:
        if value["issued_at"] > current + 30 or current >= value["expires_at"]:
            raise DispositionGrantError("Disposition grant expired or future dated")


def verify_grants(raw: bytes, *, check_time=True) -> tuple[list[dict], list[str]]:
    document = decode(raw)
    if set(document) != {"grants"} or not isinstance(document["grants"], list) or len(document["grants"]) != 2:
        raise DispositionGrantError("Exactly two independent disposition grants required")
    payloads, fingerprints = [], []
    for envelope in document["grants"]:
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise DispositionGrantError("Disposition envelope invalid")
        payload = validate_payload(envelope["payload"], check_time=check_time)
        sig = envelope["signature"]
        if not isinstance(sig, str) or len(sig) != 88:
            raise DispositionGrantError("Disposition signature encoding invalid")
        try:
            signed = base64.b64decode(sig, validate=True)
        except ValueError as exc:
            raise DispositionGrantError("Disposition signature invalid") from exc
        if len(signed) != 64:
            raise DispositionGrantError("Disposition Ed25519 signature required")
        public = _public_key(payload["role"])
        with tempfile.TemporaryDirectory(prefix="rocky-disposition-verify-") as name:
            folder = Path(name)
            for leaf, content in (("key.pem", public), ("message", canonical(payload)), ("signature", signed)):
                fd = os.open(folder / leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as out:
                    out.write(content)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            try:
                algorithm = subprocess.run(["/usr/bin/openssl", "pkey", "-pubin", "-in",
                    str(folder / "key.pem"), "-outform", "DER"], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8, env=env)
                if (algorithm.returncode or len(algorithm.stdout) != 44
                        or not algorithm.stdout.startswith(bytes.fromhex("302a300506032b6570032100"))):
                    raise DispositionGrantError("Disposition role key must be Ed25519")
                result = subprocess.run(["/usr/bin/openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-inkey", str(folder / "key.pem"), "-in", str(folder / "message"),
                    "-sigfile", str(folder / "signature")], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, env=env)
            except (OSError, subprocess.SubprocessError) as exc:
                raise DispositionGrantError("Disposition signature provider unavailable") from exc
            if result.returncode:
                raise DispositionGrantError("Disposition signature verification failed")
            fingerprints.append(hashlib.sha256(algorithm.stdout).hexdigest())
        payloads.append(payload)
    if ({p["role"] for p in payloads} != set(ROLES) or len(set(fingerprints)) != 2
            or len({p["nonce"] for p in payloads}) != 2
            or payloads[0]["plan"] != payloads[1]["plan"]
            or payloads[0]["attestations"] != payloads[1]["attestations"]):
        raise DispositionGrantError("Disposition needs distinct roles and keys signing the same plan and attestations")
    return payloads, fingerprints
