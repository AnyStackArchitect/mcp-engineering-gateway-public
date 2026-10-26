# Qualification and release identity

[Documentation index](index.md) / [Qualified platform](platform.md) / [Reader checklist](reader-validation.md)

The baseline source-only reader rehearsal completed on 2026-10-26. **Final independent release review and publication remain pending.** Source and downloads are not yet publicly available; no hosted-CI pass or release approval is implied.

## Exact tested baseline and final documentation bridge

| Item | Tested identity |
|---|---|
| Source commit | `17adbaa784b794da8caf03fcd11532a481d84112` |
| Source tree | `9a760f59eccef35823971f65083ffed5d5f2726c` |
| Source ZIP size | 2,475,719 bytes |
| Source ZIP SHA-256 | `1a2ee0dee0ed51c754a6d3154c2a193ab685957e44b4c99b116986f781b4ed1c` |
| Runtime version | `0.52.0-dev` |
| Operator-built OCI manifest | `sha256:1819c4083f5da8e426dc367d59c2cb32b4b68a650a3a440712e3035b57885216` |

The earlier reader-status correction changed documentation and checksums only. The final destination-bound source also includes the explicit exceptions below; it is not a second fresh installation of the final archive. All 57 runtime modules, installer/provider execution behavior and image inputs remain identical to the installed/tested source17adbaa baseline. Later destination binding changes the package builder's repository/provenance literal and its test expectation, component source references, and one reader clone URL; the other 43 of 44 fenced reader command blocks remain byte-identical. Documentation, release metadata and source checksums also changed. Local distribution tests, source closure, links, disclosure/privacy checks and deterministic builds from the new remote validate this bounded delta. No fresh live installation, human signing or full native regression suite was run for the destination or wording changes. The external candidate manifest and `provenance.json` bind the exact commit/tree/archive; do not substitute a historical ZIP for the final source asset. Raw infrastructure, signing and operational evidence stays private.

Compared with the earlier qualified implementation `6aa2aaf5cc77decbe376b691c87ea30611dcc24d`, 56 runtime modules remain identical. The changed off-host `operator_sign.py` preserves visible OpenSSL terminal prompts, requires interactive streams and removes the passphrase-entry deadline. It retains grant/review expiry, canonical signatures, replay rules and cancellation, and refuses to emit a grant that expired during signing. The exact corrected signer was installed and exercised in the tests below.

## Recorded validation

- Linux-native regression: 908 scheduled, 907 passed, one intentional nonroot-profile skip; the root-only refusal check passed separately. The recorded kernel and native dependency inventory bind the supported profile; this is not a broad Linux compatibility claim.
- Windows-native distribution and installer fixtures: 23 and 82 respectively; seven source/MCP smokes and 17 fixed-provider vectors, including expected partial/refusal outcomes. Fixtures and mocks are identified separately from live tests.
- Fresh native installation from the tested artifact, interrupted preparation/rollback and collision refusal; independent public-trust enrollment; SELinux Enforcing, separate gateway/worker identities, isolation and unchanged resource limits.
- Actual SSH/MCP initialization, discovery of 44 default tools and invocation; literal Windows staging of a synthetic 119-byte log, SHA-256 verification, registration, indexing, search and queued case verification.
- Actual human encrypted-key signing in a native terminal, approved execution with verified output bytes/hash, denied execution, invalid signature refusal without state change, consumed-grant replay refusal, natural grant expiry and reboot of an observed running container. The interrupted job recovered conservatively; the native installed audit passed with three consumed nonces.
- Documentation-bound quiesced capture and isolated restore: complete file bytes/ownership/modes/xattrs, SQLite integrity and all logical rows compared against quiesced live stores. Four signed plan states and all three consumed nonces survived; public restored job/result and original-byte checks passed. The synthetic input correctly retained unverified provenance. Restored expired-grant refusal is distinguished from the earlier live replay test performed before expiry.
- Same-byte code replacement and verified owned-code/unit retirement preserved cases, keys, configuration and nonce/history state. This is not a version-changing upgrade or a generic live restore. Capture and restored copies shared the disposable disk, so the exercise establishes logical recovery, not off-drive disaster protection.
- Independent source/security/package/licensing/disclosure reviews retain their exact component/artifact scope. The prescribed disclosure-wrapper resources were unavailable; pinned official Betterleaks 1.9.0 supplied explicitly identified substitute scans of the export, archive and reachable sanitized history. Findings were reviewed individually; this is not a universal absence-of-secrets guarantee.

The reference platform remains Rocky Linux 10.2 amd64 with the [documented resources and prerequisites](platform.md). Supplementary remaining sequential signing/lifecycle tests used a bounded 6 GiB guest; that does not lower the supported resource profile or imply a 6 GiB image-build qualification. The new signing identity was enrolled on a fresh installation, not rotated over existing trust or achieved by editing audit/nonce records. Earlier failed attempts, harness defects and startup/cold-image timeouts remain retained in private evidence; they are not counted as passing tests.

## Limits and pending release gates

Public anonymous acquisition cannot pass before source/assets are published; verify exact commit, archive and checksum delivery at publication. Final independent release review and joint disposition of its findings remain required before publication. No hosted Actions were enabled or run, and public/fork code must never gain private credentials or trusted lab execution.

In-place cross-version upgrade is unsupported for this first public release. Optional EVTX installation and adding a new provider were not exercised as baseline acceptance; named desktop-client certification is not implied by the reference SSH transport tests. Full image construction still requires independently authorized exact Windows symbols; no symbol-free full image or permission to redistribute symbols, dumps or built images is supplied. Source-only MIT and component-specific Volatility terms remain explicit in the [dependency and licensing instructions](dependencies.md).

All live work was confined to disposable approved test targets. The accepted deployment remained unchanged; test disks, keys and evidence were retained, with the QA VM stopped and test listener closed. Do not infer production restore, Internet exposure, general Windows process analysis or universal data-recovery support from these results.
