# Capabilities and boundaries

[Documentation index](index.md) / [First use](first-use.md)

These are implemented Phase I behaviors from the qualified candidate. Source publication remains pending.

## Evidence and analysis

Inputs enter a private case through deliberate staging and registration. Registration preserves a private original copy and records its hash and size. Log indexing/search, packet inspection, timelines, configuration comparisons and evidence reports operate within bounded workflows. Source locators and hashes help readers trace an observation back to its input; they do not make storage write-once or establish evidence completeness.

Built-in fixed jobs have a persistent queue. Their processor runs under the gateway account. Separately approved custom analysis runs under the isolated worker account. Submitting a job, preparing a script or generating a provider plan does not authorize sandbox execution.

## Fixed provider scope

| Provider in the candidate | Bounded purpose | Important limit |
|---|---|---|
| `git_bundle` | Inspect a self-contained Git bundle | Selected bundle operation, not arbitrary repository execution |
| `ansible_syntax` | Offline playbook syntax checking | Does not execute tasks against hosts |
| `tsk_fsstat` | Inspect raw ext2/ext3/ext4 filesystem metadata at offset zero | Does not imply file recovery or all disk-image formats |
| `volatility_banners` | Bounded Linux/macOS banner scanning | Does not validate a memory image or its operating system |
| `xfs_geometry` | Read-only XFS geometry | No filesystem repair |
| `xfs_repair_check` | Read-only XFS repair dry run | No modification or successful-recovery claim |
| `windows_memory_info` | Offline Windows x64 crash-dump kernel information for the qualified build | Volatility 2.28.2, exact authorized symbols, Windows 10.0/build 19041 only; no process analysis |
| `xfs_recovery_experiment` | A controlled injected-fault experiment on a disposable copy | Never repairs the registered original; does not prove general filesystem/file recovery |

The image qualification exercised 17 fixed-provider vectors, including expected rejection and partial-result cases. The Windows information test returned the expected bounded `PARTIAL` result. These are different scopes from universal tool or format support.

## Interpreting results

Preserve `PARTIAL`, unavailable, rejected, interrupted and unknown outcomes. Provider catalog availability is not proof that a tool is installed, correctly licensed, version-matched or validated against a particular input. Versions and input hashes must be bound to the reviewed plan and actual execution.

EVTX is a separately installed optional dependency profile; its installation was not qualified in this release-preparation scope. Direct Internet exposure, multi-tenant operation, live packet capture, arbitrary production repair and broad Windows forensic analysis are outside the qualified profile.
