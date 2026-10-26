# Implemented analysis and supported inputs

[Documentation index](index.md) / [Complete tool catalog](tool-catalog.md) / [Workflow examples](analysis-workflows.md)

Phase I implements the functions below in qualified source candidate `6aa2aaf`. This combined source candidate preserves that runtime implementation; public source/assets remain unpublished. This page inventories implemented behavior, not a claim that every registered method has live qualification for every input.

## Built-in analysis

| Input / task | Implemented functions and outputs | Boundary |
|---|---|---|
| Staged local files | Private case creation/listing, copied original registration, SHA-256/size/type metadata, paged artifact identities and case hash verification | Deliberate staging is required; chat attachments are not automatic intake; storage is not write-once |
| ZIP, TAR, GZIP | Explicit bounded expansion into registered derived artifacts, archive-to-member lineage and integrity checks | Unsafe paths/types, quotas and expansion limits are enforced; not arbitrary extraction into operator-chosen paths |
| Plain-text logs | Bounded local index, literal search, redacted excerpts, source lines and timezone-aware timestamps | Redaction is best-effort; review disclosure. Unknown/invalid/truncated coverage is retained |
| Multiple text logs | UTC-range timeline queries, per-source coverage and event-volume summaries | Unknown timestamps stay explicit; no inferred clock correctness |
| PCAP / PCAPNG | Offline record summaries and bounded protocol decode; TCP/UDP aliases, TCP/DNS/TLS counters, packet-signal source frames and TCP byte-range coverage | Format/link/protocol bounds apply; no live capture, raw endpoint/payload export or loss/delivery/root-cause proof |
| Log/capture/optional EVTX metadata together | Paged cross-format observations, pinned-event windows and declared clock-offset/uncertainty sensitivity models | Time proximity does not prove endpoint identity or causation; source clocks are not verified or rewritten |
| JSON or key=value configuration pairs | Normalized comparison and semantic change kinds including additions/removals/type/value changes, with report-local field aliases | No raw configuration values, inferred change time or causal claim |
| Accepted local reference notes | Literal search with exact product/version labels; bounded returned matches | Operator acceptance is separate; notes remain untrusted data, not execution authority or automatic Internet research |
| Pinned case evidence | A report separating measured metadata, coverage/unknowns and deliberately reviewed operator reasoning when present | Not an automatic diagnosis or external disclosure approval |

The [catalog](tool-catalog.md) maps each function to the actual registered MCP names and fixed-job kinds. Optional provider registration does not establish dependency availability.

## Fixed provider scope

These eight provider adapters use the operator-built, digest-pinned analysis image and the existing signed execution path. They do not install tools on the host or authorize themselves.

| Provider ID / dependency | Accepted operation | Boundary |
|---|---|---|
| `git_bundle` / Git | Verify a self-contained bundle and list/count heads | Not arbitrary repository execution, checkout or Git repair |
| `ansible_syntax` / Ansible core | Offline playbook syntax check | Does not execute tasks against hosts |
| `tsk_fsstat` / The Sleuth Kit | Raw ext2/ext3/ext4 metadata at offset zero | Not all image formats or file recovery |
| `volatility_banners` / Volatility | Bounded banner scan of raw Linux/macOS input | Not memory-image or OS validation |
| `xfs_geometry` / xfsprogs | Read-only XFS superblock/geometry observations | No filesystem modification |
| `xfs_repair_check` / xfsprogs | Read-only repair dry run | No successful repair claim |
| `windows_memory_info` / Volatility 2.28.2 | Windows x64 PAGEDU64 crash-dump kernel information for NT10.0/build19041, exact authorized symbol pack | Expected bounded `PARTIAL`; no process analysis, broad Windows support or general customer symbol rights |
| `xfs_recovery_experiment` / xfsprogs | Defined injected-fault experiment on a disposable copy of a clean raw XFS image | Original never repaired; no general filesystem/file recovery qualification |

Planning binds source hash, expected version, resource policy and declared outputs. Execution must still be separately reviewed and signed. Result reading verifies the recognized current template and output lineage; an arbitrary Python result is not automatically a recognized provider report. The image qualification covered 17 provider vectors including negative/partial cases and the additional bounded Windows-information fixture.

## Offline diagnostic recipe families

All nine families are implemented source-linked text-marker packs. They run over a freshly built text timeline and return observations, reference context, required evidence, candidate explanations and checks that could disprove them. Catalog support for actual platform versions is explicitly `UNVERIFIED`.

| Family | Included evidence topics |
|---|---|
| VMware | ESXi/vCenter, storage/datastore and snapshot markers, VCF workflow context |
| Veeam | Backup/session, snapshot, repository/proxy, VSS and Cloud Connect markers |
| Hyper-V | Cluster/CSV, migration and resource-failure markers |
| Nutanix | AHV/Foundation/Phoenix, CVM/Genesis and storage-timeout context |
| Proxmox | Corosync/quorum, pmxcfs/cluster and migration context |
| Linux | systemd, rootless Podman/Quadlet, startup and cgroup-memory context |
| Storage | XFS, multipath, NFS and iSCSI markers |
| OpenShift | OADP/Velero, Kasten and CSI snapshot context |
| Identity | Kerberos, Active Directory and DNS context |

These are not live VMware/Veeam/Nutanix or other vendor API integrations, certified signatures or repair commands. A marker hit is an evidence lead rather than a root-cause determination. Vendor names identify recipe context, not tested deployment support or endorsement.

## Optional, configured and operator-only capabilities

**EVTX:** `evtx_summary`, `evtx_events` and `windows_rule_report` are registered, but processing requires separately installed `python-evtx` dependencies and an `analyze_evtx` job. They expose System metadata such as event IDs/levels and provider aliases, plus a fixed metadata-only Windows rule pack. They do not return EventData or execute Sigma rules. This optional installation profile was NOT RUN in clean-host qualification.

**Host observations:** gateway/host summaries and gateway-visible rootless container names/states are implemented. `git_repo_status` and `user_service_status` appear only for configured allowlists. They return limited status, not a general host shell, service control, repository write access or access to the isolated worker's private store.

**Operator tooling outside the MCP catalog:** the candidate includes Windows staging/resume helpers, local reference acceptance and report/preservation/retention-review workflows, source/site/image verification, installer preparation/enrollment/audit and documented maintenance. These are deliberately operated CLIs/procedures, not extra chat tools. Windows staging requires explicit operator-selected host, login, key and installation path; inherited defaults are not portable setup values. The code-copy planner and safe retirement preserve operational state; no automatic activated-state purge is offered. This first public release has no supported in-place cross-version upgrade path. Same-byte copy checks prove preservation mechanics, not version migration. See [operations in the installation path](installation.md#operating-and-retiring-a-site).

## What the validation means

Built-in functions have source/regression coverage, with separate native smokes and selected real clean-host workflows. Provider vectors exercise the actual image. Optional/configured paths have their own prerequisites and scope. The 44-tool discovery result is a registration count, not a claim of 44 independently live-qualified features. [Qualification](qualification.md) keeps these evidence classes and NOT RUN profiles separate.
