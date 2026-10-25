# Operations, troubleshooting and retained-state maintenance

[Index](index.md) / [Install](install-from-source.md) / [First analysis](client-first-analysis.md) / [Acceptance checklist](reader-validation.md)

This is the source-release operating contract, not authorization to change a host. Use exact site/transaction identities. A reader-led rehearsal of this revised runbook is NOT RUN. Prior mechanism/lifecycle qualification does not prove these new instructions were followed.

## Health and private logs

Check actual MCP `gateway_status` and case_status/job_status/execution_status first. As the authorized administrator, run `deploy.py audit` with the retained source-manifest hash and transaction path from [installation](install-from-source.md). Audit must validate installed bytes, public trust, image binding, IPC, identities, SELinux and limits. A site worker unit name comes from bundle/transaction; never guess a global daemon name or restart an unrelated user manager.

| Location | Owner / purpose / handling |
|---|---|
| Gateway `~/.local/share/rocky-mcp-gateway/` | Gateway private inbox/cases/derived state; use case tools for locators rather than editing originals |
| Gateway `~/.local/state/rocky-mcp-gateway/audit.jsonl` | Private gateway audit; review capacity and sensitive content before exporting |
| Gateway `~/.config/rocky-mcp-gateway/config.json` | Owner-only observer allowlists |
| `/etc/rocky-eng/` | Root-managed policy/config/public trust, not gateway writable |
| `/home/rocky-eng-worker/` | Private worker configuration/stores/replay state; never grant gateway access to troubleshoot |
| `/run/rocky-eng/` | Private IPC; sockets are live state, not backup payload |
| Retained transaction path | Root-private installer/activation journal and receipts; preserve failures |
| Actual worker user-unit journal | Inspect through the authorized site's existing systemd user manager; site-specific unit/UID from transaction |

The worker manager and private stores are not universal paths a client should open. Generate exact `systemctl --user`/journal commands with the actual site unit, UID, environment and existing manager during the approved rehearsal; guessing these is unsafe. Root's default `systemctl --user` is not the worker's manager. Retain stderr/exit codes and exact targeted unit for the maintenance record.

## Refusal and failure guide

| Symptom | Check / safe response |
|---|---|
| doctor BLOCKED | Exact booted kernel/OS/architecture, SELinux, controllers, tools, setools/CIL. Stop on mismatch; do not edit gate. |
| Inventory incomplete/collision | Fresh target inventory and actual local identity/subid/path/storage. Choose a new reviewed site/target; never delete a collision. |
| Source or bundle refusal | Exact hashes, clean LF-preserving checkout, file closure/ownership/links, correct manifest-vs-ZIP hash. Preserve originals; don't patch staged bytes. |
| SSH/host-key refusal | Independently verify host/login/key/ACL; never disable checking or accept a new fingerprint blindly. |
| Client discovery absent | Check actual stdio command, protocol/version and extra stdout; reconnect after reviewed allowlist change. No host reboot needed just to refresh a catalog. |
| QUEUED fixed job | Gateway foreground jobwork processor present? Retain job ID and restart only that owned processor after review. |
| Provider unavailable/PARTIAL | Check selected dependency/version/symbol entitlement and input profile. This can be an honest result; don't report full analysis. |
| Busy/interrupted upload | Keep token and identical original; wait receiver idle timeout (at least30seconds) and use resume helper. Never delete locks to force a retry. |
| Signing/import refusal | Exact plan/image/input/SPKI/digest, expiry and consumed grant. Make a new reviewed plan if needed; never reset ledger or clocks. |
| Startup uncertainty / lingering creator | Durable launch-intent preserves RUNNING and blocks further execution. Do not delete marker or assume a killed CLI means no container. |
| Failed activation after image/trust import | Stop/disable, preserve journal/trust/image/history. Fresh rollback or image replacement may deliberately refuse. No general force recovery promised. |

For uncertain startup, same-boot automatic recovery deliberately refuses. A separately approved host reboot permits the worker to remove the exact container, independently confirm absence, remove private workspace and record INTERRUPTED. Reboot affects all workloads; never use it casually on a shared host. Preserve failure evidence and replay history.

## Backup and restore — recovery-sensitive administrator work

1. Choose retention and failure domains deliberately. Same-disk copies exercise logical restoration but do not protect against loss of that disk. No automatic backup destination/schedule is created.
2. Block new gateway sessions through the site's authorized access control, drain/cancel fixed and signed jobs deliberately, quiesce the exact worker unit and verify no active container/socket. Do not change global sshd or unrelated services for this product.
3. Capture coherent gateway cases/job DBs, worker cases/execution+nonce history, code/config/public trust/image identities, metadata (owner/mode/ACL/xattr/SELinux labels), installation journals and exact source manifests. Keep SQLite main/WAL/SHM coherent: a changing main DB copy alone is not a backup. Private signing key custody is separate.
4. Restore first into a NEW isolated directory with no service/socket. Verify hashes, SQLite `PRAGMA integrity_check`, full table/row counts, nonempty terminal job results, every referenced artifact/source locator and consumed history. Reject missing/corrupt/omitted data rather than constructing replacements.
5. Restored startup needs an approved stopped recovery layout and compatible source/schema/trust/image. Never overwrite active history with an older backup; doing so can reopen replay. Do not resume/resubmit old work automatically. Record current-vs-backup ledger identity before a recovery decision.

No generic live backup/restore CLI is shipped. An exact site capture/restore command transcript must be written and rehearsed on the approved isolated target before relying on it. Existing synthetic fixtures and previous populated-store restoration do not qualify a newcomer following this revised procedure. RPO/RTO, production restore, private-key recovery and arbitrary crash durability are not promised.

## Update — code-only compatible path

From the verified matching new source root, with authorized read access and existing private output directory, generate a plan (read-only):

```sh
python3 -B tools/lifecycle.py update --installed-code /opt/rocky-eng --prior-manifest "$PRIOR_MANIFEST" > "$PRIVATE_OUTPUT/update-plan.json"
```

PRIOR_MANIFEST is the exact prior installed57-module manifest, not the new one. Require exit0 and no drift/missing/extra/link refusal. The planner never applies live changes. Review exact prior/new module hashes, schema compatibility and rollback copies. Block callers, drain/quiesce the exact site unit, record coherent state/history and save prior code. Administrator replaces only reviewed manifest-owned code as root:root0644 with correct labels; leave config/trust/image/state/journals untouched. Reverify closure/labels before enabling. On failure preserve stopped state; code rollback requires compatible schema/state and never rolls back replay history. Image/policy/trust changes are separate migrations.

After restart verify MCP first-use, existing hashes/results/history, fresh signed positive/negative and consumed-grant replay refusal. Generic updates from arbitrary versions are unsupported. Exact maintenance commands must be generated for the actual unit and manifest during rehearsal, not inferred from fixtures.

## Safe uninstall — retained-state retirement, not purge

Generate a read-only review plan from matching source with authorized read access:

```sh
python3 -B tools/lifecycle.py uninstall --installed-code /opt/rocky-eng --prior-manifest "$PRIOR_MANIFEST" > "$PRIVATE_OUTPUT/uninstall-plan.json"
```

After approved maintenance isolation/quiescence and exact plan re-verification, remove **only** the57 manifest-owned code modules and unchanged site unit/drop-ins. Record hashes and retain rollback copies. Confirm unit disabled, no active job/container/socket and unrelated services unchanged. Preserve cases, private keys/public trust, accounts/subids, SELinux policy, images, journals and nonce/history by default. Retained accounts/paths deliberately cause fresh-install refusal. Purge, trust removal, account deletion or image pruning need a separate scoped review; no recursive delete or fresh-install rollback against activated state.

There is no automatic destructive live uninstaller. Documented manual retirement and its exact target-specific commands must be rehearsed and reviewed, with retained-state before/after hashes. The source CLI's offline apply helpers are fixture-only, not a supported way to mutate a live site.
