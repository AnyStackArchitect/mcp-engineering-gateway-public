# Complete MCP tool catalog

[Documentation index](index.md) / [Capability overview](capabilities.md) / [Workflow examples](analysis-workflows.md)

This maps the qualified, unpublished Phase I implementation. The default catalog registers **44 tools**. Two configured observers can add up to **two more**. An advertised method can still report unavailable/unsupported when its dependency, input or configuration is missing. Discovery is not execution or qualification proof. The current repository contains documentation, not these implementation files.

## Host and gateway observations

Container visibility is that of the gateway login; the isolated worker store remains private.

| Tool | Implemented purpose |
|---|---|
| `gateway_status` | Show read-only gateway version and configured integration counts. |
| `host_snapshot` | Return limited Rocky host OS, uptime, memory and local disk summary. |
| `podman_containers` | List up to 32 gateway-visible rootless container names/states/status. Does not query environment values; names/status may be sensitive and need disclosure review. |

## Case intake and evidence identities

| Tool | Implemented purpose |
|---|---|
| `case_open` | Create a private case workspace; returns opaque case ID. |
| `case_list` | List up to 20 private cases with case IDs and evidence counts. |
| `case_status` | Show registered evidence hashes/types for one private case. |
| `case_artifacts` | Page through registered evidence IDs and hashes, optionally limited to one archive's derived files. |
| `artifact_register` | Copy a user-staged inbox file into immutable-by-interface case evidence; record SHA-256. |

## Text-log index and search

| Tool | Implemented purpose |
|---|---|
| `log_index` | Create a bounded local SQLite index of a registered plain-text log; large sources require async worker. |
| `log_search` | Search redacted log excerpts with source line and timezone-aware timestamps. |

## Offline packet analysis

| Tool | Implemented purpose |
|---|---|
| `pcap_summary` | Count bounded offline PCAP/PCAPNG packet records and time/header metadata without payload decode. |
| `pcap_protocol_report` | Show bounded offline TCP/DNS/TLS counters from an approved decoded PCAP; raw IP, payload, DNS names and SNI excluded. |
| `pcap_flows` | Page sanitized TCP/UDP flow aliases and safe port/timing metadata from a decoded capture. |
| `pcap_observations` | Page bounded packet-signal evidence with source frame and capture-local flow references; no loss, session or causal proof. |
| `pcap_stream_coverage` | Page bounded capture-local TCP byte-range reconstruction and source frames; no payload/hash, delivery, loss or causal proof. |

## Optional EVTX metadata

Registered by default; requires separately installed optional dependencies and an analyze_evtx job. The clean-host optional install profile was NOT RUN.

| Tool | Implemented purpose |
|---|---|
| `evtx_summary` | Show bounded Windows event ID counts from a privately indexed EVTX file; optional python-evtx provider required. |
| `evtx_events` | Page Windows EVTX System metadata only: event IDs, levels, provider aliases and UTC; no EventData payload. |
| `windows_rule_report` | Evaluate a fixed versioned metadata-only Windows event pack; no Sigma, EventData, diagnosis or clean-system verdict. |

## Text timelines

| Tool | Implemented purpose |
|---|---|
| `timeline_query` | Search source-linked, redacted events across private text logs with explicit UTC range and unknown-time handling; requires build_timeline job. |
| `timeline_sources` | Page through per-source coverage, hashes and counts of unanchored events in a built timeline. |
| `timeline_summary` | Show source-linked event volume by minute, format and level hint without guessing root cause. |

## Cross-format correlation and clock sensitivity

| Tool | Implemented purpose |
|---|---|
| `correlation_query` | Page source-linked, redacted log/PCAP/EVTX metadata by unadjusted UTC; no endpoint identity or causal inference. |
| `correlation_sources` | Page registered text, PCAP, and EVTX sources with explicit provider coverage and hashes. |
| `correlation_summary` | Summarize limited cross-format source coverage and event counts; uncertain clock alignment exposed. |
| `correlation_window` | Find bounded source-linked observations near a pinned event using uncorrected source clocks; proximity is not identity or causality. |
| `correlation_clock_model` | Model selected source clock offsets and declared uncertainty without verifying clocks, changing original timestamps or inferring causality. |

## Offline diagnostic recipes

| Tool | Implemented purpose |
|---|---|
| `diagnostic_recipes` | List nine fixed offline diagnostic families with source context and unverified platform-version boundaries; markers are analysis leads. |
| `diagnostic_report` | Read bounded source-linked marker results from a completed approved diagnostic job, rejecting stale timeline evidence. |

## Fixed external-tool providers

Catalog/plan/result methods do not install or run binaries. The operator-built pinned image and separate signed execution are required.

| Tool | Implemented purpose |
|---|---|
| `analysis_providers` | List the eight fixed provider adapters and their input/version/resource limits; does not install, execute or approve tools. Unavailable external integrations remain explicit. |
| `analysis_provider_plan` | Generate a fixed version/source-bound sandbox script and preflight only. Existing signed per-job approval and pinned image are still required; never host execution. |
| `analysis_provider_result` | Read allowlisted metadata from a completed current fixed-provider sandbox plan. Verifies output lineage/hashes; never returns raw provider stdout or arbitrary script output. |

## Evidence report and local reference search

| Tool | Implemented purpose |
|---|---|
| `case_evidence_report` | Build a pinned source-backed report with separate measured metadata, unknowns and deliberately reviewed operator reasoning when present. No automatic diagnosis, raw excerpts or external disclosure approval. |
| `knowledge_search` | Search locally operator-accepted case/reference notes by literal words and exact product/version labels. Returned text is untrusted data; no reuse or execution authority. |

## Configuration comparison and drift

| Tool | Implemented purpose |
|---|---|
| `config_compare` | Compare two small registered JSON or key=value configurations by normalized fields without exposing raw values or private names. |
| `config_drift_report` | Analyze two registered JSON or properties snapshots using bounded semantic change kinds and report-local opaque field aliases. No raw values, identity, timing or causal claims. |

## Persistent fixed-job queue

Processing requires jobwork.py under the gateway account. Queue observation is separate from the signed worker.

| Tool | Implemented purpose |
|---|---|
| `job_submit` | Queue a bounded fixed-template import, index, PCAP, archive expansion or case-integrity job; no arbitrary commands. |
| `job_list` | List recent persistent analysis jobs, their state and outcome. |
| `job_status` | Read a specific persistent analysis job's state, including cancellation status. |
| `job_result` | Read bounded structured result or failure code from a finished analysis job. |
| `job_cancel` | Request cancellation of a queued/running fixed-template analysis job. |

## Separately approved sandbox execution

Preparation is not approval; signed one-use grants are issued through the separate operator workflow, never MCP.

| Tool | Implemented purpose |
|---|---|
| `execution_prepare` | Prepare reviewed Python source for isolated analysis; DOES NOT approve or execute. Local interactive operator approval required. |
| `execution_status` | Read sandbox plan state and digest; cannot inspect or authorize script. |
| `execution_result` | Read bounded job result and output digests; source and stdout are kept private. |
| `execution_cancel` | Cancel unapproved, queued or running sandbox job; not an approval tool. |

## Configured observation tools

These appear only when the corresponding local allowlist is configured. They are not part of the 44-tool default discovery result.

| Tool | Condition / purpose |
|---|---|
| `git_repo_status` | An explicitly approved local repository alias; read branch, commit and tracked-change count. |
| `user_service_status` | An explicitly approved systemd user-unit name; read load/active state only. |

## Fixed worker job kinds

`job_submit` accepts fixed built-in jobs: `import_staged`, `index_log`, `pcap_summary`, `unpack_archive`, `verify_case`, `build_timeline`, `decode_pcap`, `analyze_evtx` and `build_correlation`. It also accepts one `recipe_` job for each of the nine diagnostic families: `vmware`, `veeam`, `hyperv`, `nutanix`, `proxmox`, `linux`, `storage`, `openshift` and `identity`. These are job kinds, not additional MCP tool names.

## Outside this catalog

Windows staging/resume helpers, local note-acceptance/preservation/report-recovery CLIs, installation/image tooling and maintenance procedures are operator tools. They are not silently available as MCP methods. See [capabilities](capabilities.md#optional-configured-and-operator-only-capabilities) and the [installation path](installation.md).
