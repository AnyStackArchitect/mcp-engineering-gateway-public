# Qualification and release identity

[Documentation index](index.md) / [Qualified platform](platform.md)

This page records the qualified source/runtime predecessor and distinguishes it from the new combined source/manual candidate. **Public source/assets and exact-package reader acceptance remain pending.** No download URL or hosted-CI badge is implied. [Integration identity and evidence bridge](source-integration.md) explains how the candidate package binds its exact bytes.

| Identity | Qualified predecessor (not the combined package) |
|---|---|
| Source commit | `6aa2aaf5cc77decbe376b691c87ea30611dcc24d` |
| Source tree | `105b0b029f982894eed802ebbb457007e360c442` |
| Source ZIP size | 2,311,149 bytes |
| Source ZIP SHA-256 | `1658a5dee5a75682816b03f7939c1704cdb8c4136a74f901ed8f522b098e9fe5` |
| Reported runtime version | `0.52.0-dev` |

Those identifiers describe the qualification predecessor. They are not the current combined ZIP identity; use its packaging provenance and accompanying candidate manifest. No current-main hosted pass is claimed.

The recorded default discovery result contains 44 registered tools, including optional EVTX methods that may be unavailable without their dependencies. Configured Git and user-service observers can add two methods. This count is not a claim that each operation was exercised live for every input. The [tool catalog](tool-catalog.md) and [capability inventory](capabilities.md) distinguish implementation, prerequisites and proof scope.

## Recorded validation

- Native Linux full suite: 905 discovered, 904 passed, one intentional nonroot-profile skip; the root-only refusal test passed separately.
- Distribution and installer fixtures: 21 and 82 tests respectively, with applicable native Windows/Linux runs.
- Seven named source/MCP smokes and 17 image provider vectors, including expected partial/refusal outcomes.
- Actual fresh installation from the source artifact; interrupted preparation/rollback and collision refusal; independent public-trust enrollment; nonexecuting cold-image preparation.
- MCP discovery/invocation, synthetic intake/index/search/offline packet summary and case hash verification; signed positive/negative cases, isolation/resource limits and replay checks.
- Worker interruption and conservative recovery, reboot availability, postboot execution, code-only update, populated backup/restore and safe retirement preserving operator history.
- Independent source/security/package/licensing review and exact-artifact disclosure review. The completed review classified the source-only candidate CLEAN for the exact qualified profile.

Some live lifecycle/negative cases were executed at an earlier candidate with all 57 runtime module bytes identical to the final candidate. An explicit byte bridge preserves that scope; these are not falsely described as fresh reruns of every case at the final commit. The final source artifact itself received a fresh native install and full regression run.

## Boundaries that remain explicit

Manual human-TTY signing interaction and the optional EVTX installation profile were NOT RUN. Synthetic cryptographic signing does not establish human approval. The prescribed disclosure wrapper resources were unavailable; a qualified, explicitly named equivalent using pinned official Betterleaks 1.9.0 supplied the selected-text and separately reviewed distribution-history evidence. It is not a claim that the unavailable wrapper ran or that every possible secret/disclosure class can be detected.

No hosted Actions were executed or added. Public/fork code must not gain access to private credentials or trusted self-hosted execution. No broad platform, Internet-exposure, Windows-process-analysis or general data-recovery qualification follows from these results.

Earlier timeouts, an old-kernel filesystem failure and the reproduced cold-start cleanup race were retained and addressed with bounded evidence. The qualified runtime deliberately preserves uncertainty rather than declaring cleanup from a killed process alone. Results do not establish a universal kernel fix or an off-drive disaster-recovery guarantee.

Source-only licensing review does not clear redistribution of built images, symbols or dumps. Exact preferred-form integration source and notices must be accessible before matching source assets are published. Publication, visibility and source-asset approvals are separate from technical qualification.

## Reader-instruction qualification

The detailed source-only operator manual was added after the recorded implementation qualification. Prior passes are retained at their original scope; they do not count as executing these new reader instructions. [The documentation-led checklist](reader-validation.md) records all new clean-host rows NOT RUN and identifies optional dependency, symbol-entitlement, human-signing and target-specific maintenance gaps. This new reader-experience release requirement remains open.

This corrected candidate changes only `operator_sign.py` among the 57 manifest modules: its prompt is visible and all three terminal streams must be interactive. The other 56 modules retain their qualified bytes. The two Windows staging helpers require an explicit endpoint and login; see [the source integration bridge](source-integration.md) for the precise controller-interface change and validation scope.
