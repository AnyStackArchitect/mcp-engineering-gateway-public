# Documentation-led qualification checklist

[Index](index.md) / [Install](install-from-source.md) / [First analysis](client-first-analysis.md) / [Qualification](qualification.md)

**Current revised reader procedure: NOT RUN on a clean host.** Prior source qualification is retained, but did not execute this new manual verbatim. No new VM, credentials, live signing, deployment, reboot or lifecycle mutation was performed to write it. Source remains unpublished. Documentation is a product deliverable; the required baseline gaps must close before the source-only newcomer experience is called release-ready.

## Traceable sequence

| ID | Instruction / required observation | Scope | Exact missing prerequisite or authorization | Revised sequence |
|---|---|---|---|---|
| DOC-01 | Acquire source and verify commit/package/closure | Baseline staged verification; later public-delivery check | The combined local source/manual is now prepared. Use its exact packaging provenance and candidate manifest for staged verification; actual public unauthenticated retrieval waits for separate source/publication GO. | NOT RUN |
| DOC-02 | Supported OS/packages, exact booted kernel, doctor and complete native inventory | Baseline | Approved clean supported guest and bounded administrator package/boot actions; actual signed package availability, including userdbctl. | NOT RUN |
| DOC-03 | Build pinned image, exact inventory/license review and fixed vectors | Baseline full image | Approved isolated builder/network/budget and independently lawful exact symbols; current context requires symbols even for Linux-only use. | NOT RUN |
| DOC-04 | Site/config, inventory, bundle, stage, prepare/verify | Baseline | Same approved clean target, fresh reviewed identities/subids/paths, exact source/package/manifests and bounded root preparation approval. | NOT RUN |
| DOC-05 | Independent human signer, SPKI/image activation and gateway SSH enrollment | Baseline | Approved isolated custodian/test-only keys, live human terminal, target public trust/SSH and activation/boot approval. | NOT RUN |
| DOC-06 | Actual SSH protocol/client initialization/discovery/list/status | Baseline reference path | Approved installed target and gateway SSH identity; named desktop-client certification is optional, not a new baseline requirement. | NOT RUN |
| DOC-07 | Literal synthetic stage/hash/register/index/search and queue verification | Baseline | Approved installed target, synthetic-write permission and gateway foreground queue processor; prior mocks are insufficient. | NOT RUN |
| DOC-08 | Reviewed Python, human APPROVE/DENY, negative/replay/output checks | Baseline | Same approved target and explicit test-only live signing/execution/negative-test scope; no production trust. | NOT RUN |
| DOC-09 | EVTX acquire/build/system install and metadata fixture | Optional EVTX profile | Separate build closure, administrator RPM/path/ownership procedure and optional-profile host qualification. Does not block baseline when clearly unavailable. | NOT RUN, optional |
| DOC-10 | Unsupported host, collision, interrupted preparation/recovery | Baseline failure semantics | Approved disposable target/transactions and bounded failure-injection actions; fixture results retain narrower scope. | NOT RUN |
| DOC-11 | Isolation, interruption and reboot/postboot/replay | Baseline | Approved disposable host interruption/reboot scope with exact PID/unit, recovery plan and no unrelated workloads. | NOT RUN |
| DOC-12 | Quiesced backup and isolated restore/hash/DB validation | Baseline lifecycle | Approved maintenance/read/capture budget and separate new restore directory; live recovered startup needs an approved stopped recovery layout/current-ledger review. | NOT RUN |
| DOC-13 | Compatible code-only update and retained-state retirement | Baseline lifecycle | Approved exact prior/new manifests, stopped disposable site, rollback copies and explicit update/uninstall scope. | NOT RUN |
| DOC-14 | Add and test a fixed provider in a development fork | Optional developer exercise | Separate source-fork change/qualification request. Do not add a new feature merely to qualify baseline Phase I. | NOT RUN, optional |


Each row must record exact instruction file hash, source commit/tree/package hash, image archive/manifest/config digest, dependency inventory, source input identities, OS/kernel/filesystem/tool versions, operator/client version, start/end times, command/working-directory/identity, exit code, expected/actual observation, failures/skips and retained evidence location. Do not publish raw private logs, signing material, host inventory or customer inputs. Distinguish desk review, parser/static check, Windows-local synthetic, Linux-local, fixture, installed and human-operated proof.

## Rules for the final walkthrough

Use a newly approved disposable supported target separate from accepted deployments, and an operator who follows only the proposed source release and these reader instructions. Approve exact host identity/resources/network/actions before mutation. Keep test-only identity/trust and recoverable evidence; do not reuse publisher keys or private scripts. No undocumented fixes: if a step needs one, mark that attempt FAIL, correct the docs/source as appropriate and rerun affected/dependent rows against the new artifact. Fixture passes do not replace installed proof. Record intentional optional SKIP separately from required NOT RUN or failure.

A clean source-only release also needs public source/assets and license obligations reconciled. This local integration reconciles the lower-case reader pages with legacy upper-case operator entry pages and regenerates allowlist/checksums/package. Its exact provenance and checks are distinct from the held qualification predecessor. Further byte changes invalidate affected evidence; publication approval is still separate.

## Explicit unresolved limits

- No currently published source or assets to exercise DOC-01 publicly.
- Current image context mandates exact authorized Windows symbols. No qualified symbol-free image build is supplied. An operator without entitlement cannot complete that full profile; this needs a bounded rights/scope resolution, not a silent capability deletion.
- Optional EVTX has pinned acquisition and an isolated wheel build procedure, but a qualified system-interpreter installation/RPM and its full build closure remain missing. It is not part of base acceptance.
- Current lifecycle tooling plans live maintenance but does not automate it. [Parameterized source-bound maintenance commands](maintenance-commands.md) are supplied; the chosen values, current-ledger compatibility and actual execution still require approved target-specific rehearsal.
- Human interactive signing and the exact revised documentation-led clean-host walkthrough remain NOT RUN.
- Windows OpenSSL executable distribution/provenance must be selected and verified by the operator; the project has not certified a generic binary installer or every MCP client's configuration schema.

## Review and execution are different gates

Independent documentation review can establish command names, source contracts, role boundaries and honest expected observations without changing a host. It cannot establish that these exact instructions work end to end. Required baseline rows must pass on the actual final package; DOC-09 and DOC-14 are optional and must not reopen baseline scope. No publication/visibility permission is needed just to rehearse a staged proposed package in an approved isolated target. Actual public acquisition remains a later publication verification. Local source integration has been approved and performed; live target actions and publication remain unapproved.
