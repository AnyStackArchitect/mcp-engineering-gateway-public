# Documentation-led qualification checklist

[Index](index.md) / [Install](install-from-source.md) / [First analysis](client-first-analysis.md) / [Qualification](qualification.md)

**Current revised reader procedure: NOT RUN on a clean host.** Prior source qualification is retained, but did not execute this new manual verbatim. No new VM, credentials, live signing, deployment, reboot or lifecycle mutation was performed to write it. Source remains unpublished. Documentation is a product deliverable; these gaps must close before the source-only newcomer experience is called release-ready.

## Traceable sequence

| ID | Reader instruction / acceptance | Existing evidence, not credit for this manual | Revised exact sequence |
|---|---|---|---|
| DOC-01 | Acquire source, verify approved commit/package/closure from public delivery only | Exact source ZIP/rebuild previously PASS; actual public source unavailable | NOT RUN |
| DOC-02 | Acquire supported OS, signed prerequisites, boot exact kernel, doctor | Dedicated supported target previously PASS | NOT RUN |
| DOC-03 | Resolve all image inputs/rights, build pinned recipe, inventory full dependency/license closure | Operator-built image and17vectors previously PASS; no image redistribution | NOT RUN |
| DOC-04 | Fresh site config, inventory, plan/bundle, root-private staging | Exact fresh prepare/rollback/collision previously PASS | NOT RUN |
| DOC-05 | Independent human signer, protected key, public SPKI/image activation, SSH enrollment | Authorized synthetic cryptography/handoff PASS; human-TTY NOT RUN | NOT RUN |
| DOC-06 | Configure chosen MCP client; initialize/discover/list/status using actual SSH | Protocol44tools and SSH previously PASS; universal desktop schema not claimed | NOT RUN |
| DOC-07 | Literal synthetic tutorial: stage/hash, register/index/search, queue verification, retained IDs | Underlying flows/smokes previously PASS | NOT RUN |
| DOC-08 | Custom Python, real human APPROVE/DENY, invalid/expired/replay refusal, outputs | Synthetic signed positive/negative/replay previously PASS | NOT RUN |
| DOC-09 | Optional EVTX acquisition/build, actual fixed-interpreter installation and metadata-only fixture | Host installation NOT RUN; no qualified host RPM/path procedure | NOT RUN; separate optional profile |
| DOC-10 | Unsupported host, occupied site, interrupted prepare and conservative recovery | Installer/native cases previously PASS | NOT RUN |
| DOC-11 | Effective isolation/resources, worker interruption, reboot/postboot, replay | Exact/byte-identical runtime cases previously PASS with recorded scope | NOT RUN |
| DOC-12 | Site-specific health/log/backup/restore transcript, populated-store verification | Earlier runtime-identical populated restore PASS, same filesystem only | NOT RUN |
| DOC-13 | Exact compatible update and retained-state uninstall transcript | Earlier runtime-identical lifecycle PASS | NOT RUN |
| DOC-14 | Add/test a bounded tool in a separate source fork and rebuild | Implementation has unit/provider tests; no public SDK guarantee | NOT RUN |

Each row must record exact instruction file hash, source commit/tree/package hash, image archive/manifest/config digest, dependency inventory, source input identities, OS/kernel/filesystem/tool versions, operator/client version, start/end times, command/working-directory/identity, exit code, expected/actual observation, failures/skips and retained evidence location. Do not publish raw private logs, signing material, host inventory or customer inputs. Distinguish desk review, parser/static check, Windows-local synthetic, Linux-local, fixture, installed and human-operated proof.

## Rules for the final walkthrough

Use a newly approved disposable supported target separate from accepted deployments, and an operator who follows only the proposed source release and these reader instructions. Approve exact host identity/resources/network/actions before mutation. Keep test-only identity/trust and recoverable evidence; do not reuse publisher keys or private scripts. No undocumented fixes: if a step needs one, mark that attempt FAIL, correct the docs/source as appropriate and rerun affected/dependent rows against the new artifact. Fixture passes do not replace installed proof. Record intentional optional SKIP separately from required NOT RUN or failure.

A clean source-only release also needs public source/assets and license obligations reconciled. Before source integration, reconcile these lower-case reader pages with the candidate's existing upper-case operator docs; don't maintain contradictory duplicated manuals. Update release manifest/allowlist/checksums when authorized source integration changes bytes and regenerate package/reviews. This documentation branch intentionally does not change the held candidate or grant that integration/publication approval.

## Explicit unresolved limits

- No currently published source or assets to exercise DOC-01 publicly.
- Current image context mandates exact authorized Windows symbols. No qualified symbol-free image build is supplied. An operator without entitlement cannot complete that full profile; this needs a bounded rights/scope resolution, not a silent capability deletion.
- Optional EVTX has pinned acquisition and an isolated wheel build procedure, but a qualified system-interpreter installation/RPM and its full build closure remain missing. It is not part of base acceptance.
- Current lifecycle tooling plans live maintenance but does not automate it. Exact site/UID/unit backup/restore/update/retirement commands still require approved target-specific rehearsal.
- Human interactive signing and the exact revised documentation-led clean-host walkthrough remain NOT RUN.
- Windows OpenSSL executable distribution/provenance must be selected and verified by the operator; the project has not certified a generic binary installer or every MCP client's configuration schema.
