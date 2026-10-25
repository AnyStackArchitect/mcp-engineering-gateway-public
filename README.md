# MCP Engineering Gateway

**Analyze logs, packet captures, configuration snapshots and case evidence through the Model Context Protocol (MCP), then run reviewed analysis code with independent operator approval.**

MCP Engineering Gateway gives infrastructure engineers, operations teams and developers a common workflow for technical analysis on a Linux host. Phase I combines built-in offline analysis, fixed adapters for existing tools, evidence-linked reports and bounded Python execution in a pinned rootless container. It is a technical product for people who want to use and extend analysis tools while keeping input identity, execution authority and result limits visible.

**Candidate status:** this combined source candidate includes the implementation, installer/build recipes and reader manual. It preserves the previously qualified runtime, but the exact combined package still requires the documentation-led clean-host walkthrough. Source publication and release assets remain unapproved; the default remote branch may still be a documentation preview. Use only the exact source commit/package named by the candidate or release manifest. No prebuilt image is supplied.

## What is already implemented

| Work you can do with Phase I | What it provides |
|---|---|
| Organize and verify analysis inputs | Private cases, staged-file registration, SHA-256 identities, artifact listing and case integrity checks. Bounded ZIP, TAR and GZIP expansion retains original-to-derived lineage. |
| Find a problem in staged logs | Local indexing and literal search return redacted excerpts with source-line and timestamp references. Large fixed jobs use a persistent queue and separate processor. |
| Build an event sequence | Text timelines expose source coverage, unknown timestamps and event counts. Cross-format queries bring log, packet and optional EVTX metadata into a common review window. |
| Inspect an offline packet capture | PCAP/PCAPNG summaries, TCP/UDP flow aliases, protocol counters, source-frame observations and bounded TCP byte-range coverage. No live capture or application-payload export. |
| Review a configuration change | Compare registered JSON or key=value snapshots; inspect normalized field changes and semantic drift through opaque field aliases, without returning raw configuration values. |
| Apply existing diagnostic recipes | Nine offline log-marker families provide source-linked observations, evidence prompts and checks for alternative explanations. They do not connect to vendor management APIs. |
| Use an existing analysis tool | Eight fixed provider adapters bind input hash and tool version to a reviewed sandbox plan; the operator-built image supplies the selected dependencies. |
| Run your own bounded Python analysis | Prepare exact source, inputs, outputs and resource limits; obtain a separate signed decision; execute in the pinned image; inspect recorded result/output hashes. |
| Record and reuse analysis context | Build a pinned case evidence report and search locally operator-accepted reference notes by product/version. Operator reasoning remains separate from measured metadata. |
| Observe the analysis environment | Read gateway/host summaries and containers visible to the gateway login. Explicit allowlists can add local Git status and systemd user-service status; there is no general host shell tool. |

The default catalog registers **44 MCP tools**, with two additional observation tools exposed only when their allowlists are configured. Registration does not mean every optional dependency is installed or every format is qualified. [Browse the complete tool catalog](docs/tool-catalog.md), [supported input classes and limits](docs/capabilities.md), or [worked workflow examples](docs/analysis-workflows.md).

## Existing tool adapters

These adapters are implemented now. Their binaries come from an **operator-built analysis image**, not a publisher-hosted image download.

| Tool / adapter | Implemented analysis |
|---|---|
| Git | Verify a self-contained Git bundle and count advertised heads. |
| Ansible | Check an offline playbook's syntax without executing its tasks. |
| The Sleuth Kit (`fsstat`) | Read filesystem metadata from raw ext2/ext3/ext4 images at offset zero. |
| Volatility banner scan | Scan raw Linux/macOS input for bounded banner observations; this does not validate a memory image or OS. |
| XFS geometry / repair check | Read geometry or perform a read-only repair dry run; no original filesystem is repaired. |
| XFS copy experiment | Inject a defined fault and attempt repair on a disposable copy, with original identity preserved. This is not general file recovery. |
| Volatility Windows information | Parse kernel information from the qualified Windows 10.0/build 19041 x64 crash-dump profile, using Volatility 2.28.2 and exact independently authorized symbols. No process analysis. |

The eight provider IDs include separate XFS geometry and dry-run adapters. Qualification exercised 17 fixed-provider vectors plus the bounded Windows information path, with expected rejection and `PARTIAL` outcomes retained. Details: [provider scope](docs/capabilities.md#fixed-provider-scope).

**Also implemented, with optional prerequisites:** Windows EVTX System-metadata summaries, event paging and a fixed metadata-only rule pack require separately installed `python-evtx` dependencies. That installation profile was **NOT RUN** in clean-host qualification; it is not an EventData/Sigma engine or a clean-system verdict.

## Diagnostic recipes already included

The nine log-based families cover **VMware, Veeam, Hyper-V, Nutanix, Proxmox, Linux, storage, OpenShift and identity**. They match defined markers in registered text timelines and return source references, required evidence, candidate explanations and falsification checks. These are offline analysis recipes, not live vendor integrations or vendor-certified diagnostic rules; platform-version support remains unverified. [See the families and their boundaries](docs/capabilities.md#offline-diagnostic-recipe-families).

## Concrete uses

- **A timeout across application logs and a packet capture:** search the log marker, anchor a timeline event, inspect nearby capture-local TCP/DNS/TLS observations and model a declared clock offset. Retain uncertainty; proximity does not prove a common endpoint or root cause.
- **A before/after configuration review:** register two JSON snapshots, inspect added/removed/type/value changes through aliases, and keep the original hashes for follow-up. Raw values are not returned by the comparison tools.
- **An artifact-specific tool check:** stage a Git bundle or an Ansible playbook, generate the corresponding fixed provider plan, review/sign/import it and inspect the bounded result. Preparing the plan alone never runs it.

[Follow these workflows in more detail](docs/analysis-workflows.md).

## Installation and operation included in the candidate

The implementation includes site inventory/planning, source and OCI verification, disabled preparation, explicit image/public-trust enrollment and a boot-persistent signed worker. It also includes Windows staging/resume helpers and operator workflows for health, private audit/log review, coherent backup/restore, code-only updates and safe retirement that preserves cases, keys/public trust and replay history. Maintenance uses reviewed procedures; it is not an automatic purge or arbitrary-version upgrader.

The qualified host is **Rocky Linux 10.2 amd64**, running kernel `6.12.0-211.68.1.el10_2.x86_64`, with SELinux Enforcing and cgroup v2. Dependencies and signing identity are established by the operator. Fixed queued analysis needs the gateway-account processor; the separate signed worker has qualified boot persistence. [Platform](docs/platform.md) · [Installation path](docs/installation.md) · [First use](docs/first-use.md) · [Architecture and trust](docs/architecture.md).

Recorded validation includes 905 tests (904 passed, one intentional skip; root refusal passed separately), 21 distribution tests, 82 installer fixtures, seven MCP smokes and real installation/execution/recovery/lifecycle checks. Those scopes do not imply every registered tool was exercised live on every input. [Exact candidate and qualification boundaries](docs/qualification.md).

## Extending Phase I and the Phase II direction

Phase I already supports operator-reviewed Python in the approved image and source-level development of fixed adapters. The [extension guide](docs/extensions.md) explains both paths and the controls a new tool must retain. This source candidate can be inspected in a separate authorized development checkout; publication remains pending.

Phase II is intended to add further analysis-tool integrations separately. It is future work, with no committed tool list, dates or plugin-SDK compatibility promise. [Future direction](docs/direction.md).

[Documentation index](docs/index.md) · [Licensing and support](docs/licensing-support.md) · [Project MIT license](LICENSE). Dependencies, symbols and adapters have their own rights conditions; no prebuilt image, symbol archive or dump is cleared for redistribution here.

## Build, install and use from source

For the source-only release, use the [detailed operator manual](docs/install-from-source.md), [complete dependency instructions](docs/dependencies.md), [client and synthetic first-analysis tutorial](docs/client-first-analysis.md), and [operations runbook](docs/operations-runbook.md). Publication is still pending. The [reader-led validation checklist](docs/reader-validation.md) makes clear which exact instructions remain unexecuted and what must close before the newcomer experience is qualified.

The combined candidate keeps all 57 Linux runtime modules unchanged. The two Windows staging helpers now require an explicit endpoint and login; see [the source integration bridge](docs/source-integration.md) for the precise controller-interface change and validation scope.
