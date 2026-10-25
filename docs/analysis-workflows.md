# Practical analysis workflows

[Documentation index](index.md) / [Capabilities and inputs](capabilities.md) / [Tool catalog](tool-catalog.md)

These examples describe implemented Phase I workflows with synthetic or independently authorized inputs. They are not executable instructions for the current docs-only repository. Source publication, a qualified installation, deliberate input staging and the relevant processor/dependencies are prerequisites. The names below are actual tool/job identifiers; returned IDs must come from that installation.

## Find a log marker and preserve its context

Use a small synthetic text log with a known phrase such as "connection timed out". Stage it deliberately, open a case and register the file. Compare the returned SHA-256/size to the original. Index it, then use literal search to inspect matching redacted excerpts and their source-line/timestamp references.

Relevant tools: `case_open`, `artifact_register`, `log_index`, `log_search`, `case_status`. Large fixed work uses `job_submit` and the gateway-account processor rather than assuming a synchronous call can process any input size. Expected outcome is a bounded source-linked match or explicit missing/partial coverage, not a diagnosis. Review excerpts before sharing them.

## Review a timeout across logs and a capture

Register synthetic application/system logs and an offline PCAP/PCAPNG sample. Build a text timeline, decode the capture and build the correlation index through fixed jobs. Check source coverage before choosing a pinned event and a bounded time window. Compare nearby text and capture observations, including packet frame references and capture-local flow aliases.

Relevant tools: `timeline_sources`, `timeline_query`, `timeline_summary`, `pcap_protocol_report`, `pcap_flows`, `pcap_observations`, `pcap_stream_coverage`, `correlation_sources`, `correlation_window`. Required fixed jobs include `build_timeline`, `decode_pcap` and `build_correlation`.

If you have a declared offset and uncertainty for a source clock, `correlation_clock_model` can show sensitivity to that assumption. It does not verify the clock or rewrite originals. A nearby TCP reset, DNS error, TLS alert or sequence-gap candidate is an observation, not proof of loss, common endpoint identity or the cause of the timeout.

## Compare configuration snapshots

Register two small JSON or key=value snapshots from the same synthetic scenario. Compare normalized fields, then inspect paged semantic changes: added/removed fields, value/type and supported structural changes. The outputs use field aliases instead of raw configuration values/names.

Relevant tools: `config_compare`, `config_drift_report`. Preserve both input hashes and the actual partial/refusal result if structure or limits are unsupported. The report does not establish when a setting changed, who changed it, or whether it caused an incident.

## Check an artifact with an existing tool

For a self-contained Git bundle, select the `git_bundle` provider with the exact Git version expected in the approved image. For a playbook, `ansible_syntax` performs offline syntax checking without executing its tasks. Generate the fixed source-bound plan, prepare execution, and use the separate operator export/review/sign/import workflow.

Relevant tools: `analysis_providers`, `analysis_provider_plan`, `execution_prepare`, `execution_status`, `execution_result`, `analysis_provider_result`. A catalog entry or generated plan neither runs the dependency nor approves work. Expected version mismatch, unsupported input and denied/expired grants remain meaningful results. A custom Python job can use an already approved image dependency, but does not automatically gain fixed-provider result semantics.

## Apply an included recipe and keep reasoning separate

After building a text timeline, inspect `diagnostic_recipes`, choose an included family and run its fixed `recipe_` job. Read `diagnostic_report` for source-linked marker observations, required evidence, alternative explanations and falsification checks. Family/product-version context must remain explicit; no vendor platform-version certification is inferred.

An eligible pinned correlation index can feed `case_evidence_report`; deliberately reviewed operator reasoning is separate from measured metadata. `knowledge_search` queries locally operator-accepted reference notes with product/version labels. Neither result authorizes execution, uploads evidence or establishes root cause.

## Check the case and plan operations deliberately

Queue `verify_case`, run the fixed-job processor and inspect its terminal result. Case integrity checks compare observed registered files with their identities; they do not guarantee storage immutability. Signed work has separate status/cancellation, resource and replay controls. Follow the matching operator procedures for coherent capture, restore, code-only update and safe retirement. Keep case data, signing trust and consumed history rather than using a reinstall to erase a refusal.
