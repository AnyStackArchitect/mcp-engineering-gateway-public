# First use: a synthetic analysis

[Documentation index](index.md) / [Practical workflows](analysis-workflows.md) / [Tool catalog](tool-catalog.md) / [Architecture](architecture.md) / [Extensions](extensions.md)

This page explains the workflow. Use the [executable first-analysis manual](client-first-analysis.md) with the exact combined source package and an approved installed target; the baseline reader-led execution passed on the [qualified profile](qualification.md). Use a new authorized installation with synthetic data first.

## Connect and establish evidence identity

Connect the MCP client using the gateway SSH login and an independently verified host key. Verify initialize/discovery, the tool list and an actual status invocation. A configured connection alone is not proof. The qualified candidate exposed 44 tools; client compatibility must still be checked for the actual application.

Create a few synthetic UTC log lines with a known marker on the operator workstation and record their SHA-256. Deliberately stage the file in that gateway login's private inbox through authenticated transport. Chat attachments are not automatic uploads. Use the candidate's `case_open` and `artifact_register` tools, retain the returned identifiers, and compare the registered size/hash with the original.

Use `log_index` followed by `log_search` for the known marker. Inspect its source locator and coverage. Use the returned case/artifact IDs rather than sample IDs copied from another installation. A small offline packet sample can similarly exercise packet summary. Retain the real result, including partial/unsupported outcomes.

## Understand fixed jobs

`job_submit` queues fixed built-in work such as `verify_case`; `job_status` and `job_result` observe it. Processing requires the installed `jobwork.py` CLI under the **gateway account**, using its foreground loop or one-job mode. The [client and first-analysis tutorial](client-first-analysis.md) supplies its `--loop` and `--once` invocation. It must not run as root or as the sandbox worker.

Without that processor a fixed job can correctly remain QUEUED. Its foreground session does not automatically persist across disconnect/boot. The separate signed-execution service has qualified boot persistence. Poll conservatively: each gateway process/session enforces 60 tool calls per 60-second window in memory, rather than an account-wide persistent quota. After a transport failure retain job IDs and resume observation; do not blindly repeat a mutation whose response was lost.

## Deliberately approve sandbox work

Provider planning or `execution_prepare` produces a plan, not permission. The custodian reviews the exact script, input identities, pinned image and output/resource bounds through the local export/review/sign/import workflow. The private signer remains off the analysis host; import transfers only a signed decision.

Exercise a small declared-output job and verify its recorded result. Also test DENY, invalid/expired grants and consumed-grant replay refusal on synthetic cases. Chat must never turn a prepared plan into approval. Qualification includes actual human encrypted-key signing in a native terminal: approved and denied decisions, invalid-signature refusal, consumed-grant replay refusal, natural expiry and interrupted-job recovery after reboot. This attests only the recorded synthetic test decisions, not later operator approvals.

If startup or cleanup is uncertain, preserve the state and use the documented reviewed recovery procedure. Do not reset the nonce database, remove markers or weaken isolation to obtain a positive result. [Qualification](qualification.md) identifies what the preparation actually tested.

## Executable source-release tutorial

The [client and first-analysis manual](client-first-analysis.md) supplies exact transport requests, synthetic sample construction, explicit Windows staging parameters, returned-ID use, hash/index/search verification and queue processing. [Configuration and trust](configuration-trust.md) covers real interactive signing. The [reader checklist](reader-validation.md) records executed baseline steps, optional paths, evidence bridges and the separate public-download verification that remains pending.
