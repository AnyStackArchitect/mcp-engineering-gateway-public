# Documentation-led qualification checklist

[Index](index.md) / [Install](install-from-source.md) / [First analysis](client-first-analysis.md) / [Qualification](qualification.md)

**Baseline reader rehearsal: PASS for the tested source17adbaa artifact**, with the explicit scopes and explicit destination-delta bridge in [qualification](qualification.md). Final independent release review and public source/download verification remain pending. Historical evidence and unsuccessful attempts retain their original identities; optional and unsupported rows below are not promoted to passes.

## Traceable sequence

| ID | Instruction / required observation | Scope | Executed scope / remaining condition | Result |
|---|---|---|---|---|
| DOC-01 | Acquire source and verify commit/package/closure | Baseline staged verification; later public-delivery check | The tested staged source ZIP, commit, closure and hashes verified. Anonymous public source/download acquisition remains pending publication. | PASS staged; NOT RUN public delivery |
| DOC-02 | Supported OS/packages, exact booted kernel, doctor and complete native inventory | Baseline | Executed native package/boot/kernel/doctor/inventory checks on the documented Rocky Linux profile. | PASS |
| DOC-03 | Build pinned image, exact inventory/license review and fixed vectors | Baseline full image | Executed public-input operator image build/inventory/notices/provider vectors; the fresh signer site reused that exact verified build. Exact symbol entitlement remains an operator prerequisite; no image redistribution. | PASS scoped |
| DOC-04 | Site/config, inventory, bundle, stage, prepare/verify | Baseline | Executed fresh site/config/bundle/stage/prepare/verify using the exact tested archive. | PASS |
| DOC-05 | Independent human signer, SPKI/image activation and gateway SSH enrollment | Baseline | Human created an encrypted off-host test signer; fresh native enrollment bound its public identity and the pinned image. Prior signer/history remained preserved. | PASS |
| DOC-06 | Actual SSH protocol/client initialization/discovery/list/status | Baseline reference path | Actual reference SSH initialize/discovery/status, 44 tools. No named desktop-client certification. | PASS scoped |
| DOC-07 | Literal synthetic stage/hash/register/index/search and queue verification | Baseline | Literal Windows synthetic 119-byte log staging/hash/register/index/search and queued case verification. | PASS |
| DOC-08 | Reviewed Python, human APPROVE/DENY, negative/replay/output checks | Baseline | Actual human APPROVE/DENY, valid output hash, invalid signature and consumed-grant replay refusal; natural expiry refused. | PASS |
| DOC-09 | EVTX acquire/build/system install and metadata fixture | Optional EVTX profile | Optional EVTX build/system installation profile remains unqualified; it is not a baseline dependency. | SKIP optional; NOT RUN |
| DOC-10 | Unsupported host, collision, interrupted preparation/recovery | Baseline failure semantics | Actual interrupted preparation/rollback and collision refusal; unsupported-host checks retain fixture-only scope. No claim of live testing on every unsupported OS. | PASS scoped |
| DOC-11 | Isolation, interruption and reboot/postboot/replay | Baseline | Actual isolation/resources, running-container interruption/reboot, conservative recovery and postboot replay refusal. | PASS |
| DOC-12 | Quiesced backup and isolated restore/hash/DB validation | Baseline lifecycle | Quiesced populated capture, complete bytes/metadata/full-row comparison against live stores, isolated public-interface checks and three consumed nonces retained. Same-disk logical recovery only; no generic live overwrite/startup authorization. | PASS scoped |
| DOC-13 | Same-byte preservation mechanics and retained-state retirement | Baseline lifecycle | Same-byte code replacement and exact owned-code/unit uninstall preserved operator state, trust, keys and nonce/history. | PASS scoped |
| DOC-13U | In-place cross-version upgrade | Unsupported for first public release | Unsupported first-public-release in-place cross-version upgrade; no older supported public version pair. | SKIP unsupported; NOT RUN |
| DOC-14 | Add and test a fixed provider in a development fork | Optional developer exercise | A new provider exercise is optional and separate from baseline; no new feature was added for acceptance. | SKIP optional; NOT RUN |


Each row must record exact instruction file hash, source commit/tree/package hash, image archive/manifest/config digest, dependency inventory, source input identities, OS/kernel/filesystem/tool versions, operator/client version, start/end times, command/working-directory/identity, exit code, expected/actual observation, failures/skips and retained evidence location. Do not publish raw private logs, signing material, host inventory or customer inputs. Distinguish desk review, parser/static check, Windows-local synthetic, Linux-local, fixture, installed and human-operated proof.

## Rules for the final walkthrough

Use a newly approved disposable supported target separate from accepted deployments, and an operator who follows only the proposed source release and these reader instructions. Approve exact host identity/resources/network/actions before mutation. Keep test-only identity/trust and recoverable evidence; do not reuse publisher keys or private scripts. No undocumented fixes: if a step needs one, mark that attempt FAIL, correct the docs/source as appropriate and rerun affected/dependent rows against the new artifact. Fixture passes do not replace installed proof. Record intentional optional SKIP separately from required NOT RUN or failure.

A clean source-only release also needs public source/assets and license obligations reconciled. This local integration reconciles the lower-case reader pages with legacy upper-case operator entry pages and regenerates allowlist/checksums/package. Its exact provenance and checks are distinct from the held qualification predecessor. Further byte changes invalidate affected evidence; publication approval is still separate.

## Explicit unresolved limits

- No currently published source or assets to exercise DOC-01 publicly.
- Current image context mandates exact authorized Windows symbols. No qualified symbol-free image build is supplied. An operator without entitlement cannot complete that full profile; this needs a bounded rights/scope resolution, not a silent capability deletion.
- Optional EVTX has pinned acquisition and an isolated wheel build procedure, but a qualified system-interpreter installation/RPM and its full build closure remain missing. It is not part of base acceptance.
- Current lifecycle tooling plans live maintenance but does not automate it. [Parameterized source-bound maintenance commands](maintenance-commands.md) are supplied; the chosen values, current-ledger compatibility and actual execution still require approved target-specific rehearsal.
- Actual human signing and baseline reader walkthrough passed at the tested artifact; final destination-bound source uses the explicit qualification bridge, not a fictional second install.
- Windows OpenSSL executable distribution/provenance must be selected and verified by the operator; the project has not certified a generic binary installer or every MCP client's configuration schema.

## Review and execution are different gates

Independent documentation review can establish command names, source contracts, role boundaries and honest expected observations without changing a host. It cannot establish that these exact instructions work end to end. The tested baseline package passed the scoped rows above; the final destination-bound artifact requires closure/disclosure/review and its scoped runtime/command bridge. DOC-09 and DOC-14 are optional and must not reopen baseline scope. No publication/visibility permission is needed just to rehearse a staged proposed package in an approved isolated target. Actual public acquisition remains a later publication verification. Local source integration has been approved and performed; the bounded disposable-target rehearsal was approved and completed. Further host changes and publication remain separately gated.
