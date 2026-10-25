# Clean-host command procedure — approval required

**NOT RUN for this combined artifact.** Start with the canonical [source installation](install-from-source.md), [first analysis](client-first-analysis.md), [maintenance commands](maintenance-commands.md) and [reader acceptance matrix](reader-validation.md). This supplement retains additional negative/isolation/recovery cases; it is not a competing quick start.

 These are administrator/controller commands for a newly approved,
disposable Rocky10.2 amd64 target only. Do not run on an accepted deployment.
Select and record the VM identity, hostname, machine-id, network, disk, exact
source/image hashes and fixture trust before mutation. Stop on any mismatch or
refusal. A shell variable is not authorization. Human review/signing remains
interactive; this procedure does not grant unattended approval authority.

Use [QUICKSTART.md](QUICKSTART.md) commands for source verification, doctor,
inventory, planning, package/bundle construction, prepare/verify and deliberate
activation. All inputs must come from this distribution, trusted public package
sources and the operator's authorized symbol acquisition. Never import a lab
cache/archive, private development script or existing key. Keep all receipts and
failed attempts in a NEW private QA output directory outside the source.

## 1. Guard and record the selected guest

Run as administrator inside the approved new guest; set actual approved values:

```sh
set -eu
test "$(id -u)" = 0
test "$(hostname)" = "$APPROVED_QA_HOSTNAME"
test "$(cat /etc/machine-id)" = "$APPROVED_QA_MACHINE_ID"
test -f /root/THIS_IS_DISPOSABLE_MCP_PUBLIC_QA
umask 077
python3 -B "$SOURCE/tools/doctor.py" > "$QA/doctor.json"
cat /etc/os-release > "$QA/os-release.txt"
uname -srmo > "$QA/kernel.txt"
python3 --version > "$QA/python.txt"
podman --version > "$QA/podman.txt"
systemctl --version > "$QA/systemd.txt"
getenforce > "$QA/selinux.txt"
sha256sum "$SOURCE/SHA256SUMS.txt" "$APPROVED_OCI_ARCHIVE" > "$QA/input-hashes.txt"
```

`SOURCE`, `QA` and approved identity variables refer to independently verified
absolute paths/values. Create the sentinel only during the approved provisioning
of this new VM, not on a preexisting host. Hostname alone is insufficient identity.
Unsupported OS/architecture/controller/tool observations must refuse before any
installation. Run the distribution and installer fixture suites as a nonroot QA
user to retain negative-input, collision, symlink, policy-drift and partial-state
coverage. Fixtures are supplementary to the actual installed checks below.

## 2. Fresh installation, refusal and recovery

From the clean committed controller checkout, use QUICKSTART to generate exact
source and site-review packages. The site JSON selects fresh gateway/worker IDs
and subids; the target administrator recollects inventory before prepare. Retain
all actual return codes and state journals. Before final installation on this
empty disposable guest, exercise a selected interrupted preparation:

```sh
if python3 -I -B "$ENTRY" prepare --source-manifest-sha256 "$SOURCE_MANIFEST_SHA" \
  --bundle "$BUNDLE" --bundle-sha256 "$BUNDLE_SHA" --state "$FAILED_TRANSACTION" \
  --allow-experimental-prepare --fail-after 3 > "$QA/injected-prepare.json" 2>&1
then
  echo 'Expected injected failure did not occur' >&2; exit 1
fi
```

Require the journal to show successful conservative rollback and the actual
native-policy/account/path inventory to equal the retained pre-prepare baseline.
An ambiguous/incomplete policy operation stops for review; do not reuse or edit
the failed transaction to force success. Use a NEW transaction for the final
ordinary prepare/verify from QUICKSTART. Repeat prepare against its occupied
site and require refusal without changes. Exercise drift/collision cases in
separate fresh synthetic inventories/transactions, never by corrupting the
accepted final installation merely to obtain a green result.

Create a unique **test-only** signing identity on the approved isolated controller
using TRUST.md's interactive encrypted-key procedure, and approve only its public
SPKI on this guest. It is not a production operator key. No private signing key
is transferred to the guest. Authorize a separate synthetic SSH identity for the
gateway login. Activate the reviewed OCI and public SPKI through QUICKSTART.

## 3. Actual SSH MCP protocol and source-linked first use

On the approved controller, set `GW` to the actual gateway login and `HOST` to its
independently verified SSH host alias. Record a modern discovery request:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
 | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -l "$GW" "$HOST" \
   /usr/bin/python3 -B -u /opt/rocky-eng/gateway.py > "$QA/discover.json"
```

Repeat with `tools/list` and `tools/call` for gateway_status, and with a legacy
initialize/initialized/list/call exchange following scripts/smoke_stdio.py. Check
JSONRPC IDs, absence of error/isError, declared version, private result metadata
and actual catalog; SSH registration alone is not proof. Every tool request uses
the same `_meta` protocol object, plus actual `name`/`arguments`. For example:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"case_open","arguments":{}}}
```

Retain the actual returned case_id; do not invent IDs. Stage a small synthetic
UTC log using the approved gateway SSH identity and owner-only inbox metadata.
Record its controller SHA-256. Invoke artifact_register, log_index, log_search,
case_status and fixed verify_case using actual returned IDs. Assert exact bytes,
hash, expected marker source line/time, persistent case identity and honest
coverage. Repeat with a small synthetic PCAP through registered intake and the
fixed decoder. Public scripts/smoke_casework.py and smoke_protocols.py provide
the exact accepted request/result keys and synthetic fixture construction;
substitute the approved installed SSH command, not a temporary HOME, for this
installed test. Keep temporary-HOME smoke results separately labelled.

## 4. Real installed signed positive/negative cases

Prepare a bounded plan through execution_prepare using the actual case_id:

```json
{"case_id":"RETURNED_CASE_ID","script":"from pathlib import Path\nPath('/output/result.txt').write_text('synthetic-only')\n","artifact_ids":[],"output_names":["result.txt"],"timeout_seconds":10,"memory_mib":256,"disk_mib":8}
```

Retain actual execution_id and plan digest. As the gateway login on the guest:

```sh
/usr/bin/python3 -B /opt/rocky-eng/operator_approve.py export "$EXECUTION_ID" --out "$NEW_REVIEW_PATH"
```

The CLI/operator modules are in the runtime manifest. Transfer only the exported
review bundle to the controller. In its human interactive terminal:

```sh
python3 -B "$SOURCE/operator_sign.py" "$REVIEW_BUNDLE" --private-key "$QA_SIGNER_PRIVATE" --out "$NEW_GRANT"
```

Review the exact script, source hashes, image and limits; type the displayed full
digest for APPROVE, or DENY for the denial case. Transfer only the resulting
grant to the gateway's approved private staging directory, then as that login:

```sh
/usr/bin/python3 -B /opt/rocky-eng/operator_approve.py import "$STAGED_GRANT"
```

Poll execution_status/result to the required terminal state. Separate cases:

| Case | Plan/operation | Required observation |
|---|---|---|
| Positive | Above script; human APPROVE | SUCCEEDED and allowlisted output identity |
| Denial | New plan; human DENY | DENIED/no container execution |
| Timeout | New plan sleeps30s;10s plan limit | FAILED with failure_code execution_timeout and verified container cleanup |
| Unexpected output | Writes undeclared output file | Output refusal; no unreviewed publication |
| Cancellation | New approved sleeping plan; execution_cancel while RUNNING | CANCELLED and verified cleanup |
| Bad signature | New signed grant copy with one signature byte changed | Import rejected; original history unchanged |
| Expired | Keep a new signed grant past its displayed expiry without importing | Import rejected |
| Replay | Re-import an already consumed valid grant | Rejected; no additional execution/nonce consumption |

Use fresh plans/grants and separate files. Never edit the worker DB or advance
clocks to manufacture these outcomes. Never reuse QA trust on another host.
Record return codes, relevant terminal states, output hashes and retained failure
receipts without printing private key material, raw case evidence or nonce values.

## 5. Isolation, recovery and boot

Run the source-verified site audit after actual workloads. Independently inspect
effective gateway/worker UID/GID, worker SELinux domain, private IPC metadata and
gateway access denial, no sudo/wheel, worker cgroup memory/CPU/pid controls and
actual sandbox no-network/read-only/capability/NoNewPrivs restrictions. Record
observations; a plan/command line is not proof of effective enforcement.

On this disposable guest only, perform the approved worker SIGKILL/orphan case
while one synthetic job is running. Use the exact site worker unit and observed
PID/UID, never a wildcard process kill. Verify automatic restart, interrupted job
terminal status, container cleanup, unchanged consumed history and replay refusal.
Reboot only this disposable VM; verify startup before interactive worker login,
same source/image/config/trust/history, a fresh signed positive job and final audit.
Keep every failed restart/boot result rather than replacing it with a later pass.

## 6. Backup/restore, update and retained-state uninstall

Follow OPERATIONS.md to block new gateway sessions, drain active/pending jobs and
quiesce the exact site worker. Capture coherent gateway/worker stores with their
SQLite sidecars and private ownership/ACL/xattr/SELinux metadata, plus root-owned
code/config, public trust, image identities and transaction records. Exclude live
sockets and unrelated Podman storage. Verify every captured byte and reference,
including nonempty terminal job rows, original counts/results and consumed history.

Restore first into a NEW isolated directory. Use SQLite integrity_check and full
table/row comparisons to the retained capture, then public JobStore result and
source-locator queries. Refuse active-job capture, corrupt DBs, missing references,
corrupt originals and omitted rows. This must use real captured QA stores, not
only recreated fixture databases. Never restore an older ledger over active state.
Actual restored startup requires a stopped disposable recovery layout and proof
the current history has not advanced beyond the capture; otherwise stop for an
additional recovery-target decision. No production restore is authorized.

Generate update/uninstall plans with tools/lifecycle.py from the exact prior
manifest and installed bytes. Follow LIFECYCLE.md's reviewed administrator
maintenance procedure; stop/disable the exact site unit and block callers first.
For the supported unchanged57-module path, retain prior code and replace only
manifest-owned code with root:root0644 and correct labels. Verify all existing
case hashes/job results and nonce/history bytes before restart, then fresh MCP,
signed positive/negative and replay checks. An incompatible schema/version is
unsupported, not an invitation to reset state.

For uninstall, after re-verification remove only manifest-owned code and the
unchanged site unit/drop-ins. Retain all cases, keys/public trust, execution/nonce
history, images, accounts/subids, SELinux policy and journals by default. Prove
retained-state hashes equal the pre-uninstall baseline, the unit is disabled,
no job/container/socket remains and unrelated services are unchanged. Do not use
recursive deletion or native fresh-install rollback on activated state. Any purge
or another restore target needs its own reviewed approval.

Complete docs/ACCEPTANCE.md with actual command transcript, source/image digests,
platform/tool versions, start/end times, return codes and PASS/FAIL/SKIP/NOT RUN
per case. These commands and expected observations are a procedure, not evidence
that any of these installed tests have run.
