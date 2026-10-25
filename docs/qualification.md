# Qualification and release identity

[Documentation index](index.md) / [Qualified platform](platform.md)

This page records the separately qualified source candidate. **That source commit and its assets are not published in this docs-only branch.** No download URL or hosted-CI badge is implied. A future source publication must identify the exact released bytes and reconcile its reader documentation through review.

| Identity | Qualified candidate |
|---|---|
| Source commit | `6aa2aaf5cc77decbe376b691c87ea30611dcc24d` |
| Source tree | `105b0b029f982894eed802ebbb457007e360c442` |
| Source ZIP size | 2,311,149 bytes |
| Source ZIP SHA-256 | `1658a5dee5a75682816b03f7939c1704cdb8c4136a74f901ed8f522b098e9fe5` |
| Reported runtime version | `0.52.0-dev` |

Those identifiers distinguish the qualified implementation from this later documentation branch and from any future release incorporating documentation changes. No current-main hosted pass is claimed.

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
