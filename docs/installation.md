# Installation and dependency delivery

[Documentation index](index.md) / [First use](first-use.md) / [Licensing](licensing-support.md)

**Publication and exact-package reader acceptance are pending.** This combined source candidate includes the installer and build tooling. There are no released source assets or publisher OCI images to download here. Execute installation only with the matching verified source/package and an independently approved target; the detailed manual below is the canonical procedure.

## Distribution model

The proposed source release contains reviewed source, configuration/build recipes, manifests and notices. It excludes dependency binaries, OCI layers, Windows symbols, memory dumps, credentials and private operational evidence.

An operator acquires dependencies from their public upstream distributors under applicable rights and builds the analysis image locally. The recipe pins its Python base digest, Debian snapshot repositories and hashed Volatility/pefile inputs. The bounded Windows profile also requires an exact symbol archive the operator is independently entitled to use. A hash identifies bytes; it does not grant rights. No offline archive or image from the publisher's environment is required.

Source ZIP rebuilds were byte-identical. OCI build metadata can vary: verify each build's actual archive, manifest and configuration digests rather than promising identical image bytes from every builder.

## Planned operator sequence

1. Obtain the approved source revision, source archive, checksums, notices and release attestation. Verify they all identify the same candidate. Stop if source or assets are absent or their identities disagree.
2. Have the administrator approve the dedicated target and install the documented prerequisites from trusted repositories. Boot the exact qualified kernel and run the read-only prerequisite checker.
3. Select candidate unused site identities and create a nonsecret site configuration. Collect complete identity/storage/policy inventory for that same configuration; resolve collisions or incomplete observations before building and reviewing its bound site bundle. Stage the verified source in a new root-private location.
4. Acquire authorized build inputs, build the image and verify its complete OCI identity. Review the resulting dependency inventory and intended-use rights.
5. Establish the installation's own execution-signing identity on the custodian's protected workstation. Keep its encrypted private key and passphrase there. Review the public-key identity independently; SSH login keys and execution signing serve different purposes.
6. Prepare disabled resources, compile/verify policy, and inspect the transaction. Enroll only the reviewed image and public signer, perform the nonexecuting cold image preparation and enable the signed worker's boot availability.
7. Separately enroll the gateway's approved public SSH key. Connect the MCP client and perform synthetic first-use, negative authorization and recovery checks before bringing real evidence into the installation.

In the qualified candidate these responsibilities are implemented by the `ops/deployment` tooling, `tools/doctor.py` and the image tooling. The source files are supplied in this candidate. Complete CLI syntax is in [the installation manual](install-from-source.md) and source-bound maintenance templates in [maintenance commands](maintenance-commands.md).

## Operating and retiring a site

Fixed queued jobs need the gateway-account foreground processor; the installed boot-persistent service handles signed sandbox execution. See [first use](first-use.md).

Keep health/status, private logs and case integrity checks in the operating routine. Treat excerpts and reports as disclosure-sensitive even when redaction is available. Capture coherent backups with jobs quiesced and verify a restore into an isolated location. Same-filesystem copies can prove logical restore behavior while sharing the original disk's failure domain.

Updates require an exact prior/new code manifest and a reviewed maintenance procedure. Generic upgrades from arbitrary versions, image replacement and trust rotation are not implied by a code-only update test. Roll back compatible code without rolling back replay history.

Fresh-install rollback deliberately refuses activated trust/history. Safe retirement removes only verified owned code and the site's unit files, preserving cases, keys/public trust, accounts, policy, image stores, journals and nonce/history by default. Purging retained data or identities is a separate operation. Failure must leave evidence available for review, not trigger a force-clean reinstall.

## Detailed source-only operator manual

Start with [every dependency and acquisition/build procedure](dependencies.md), then [source acquisition through activation](install-from-source.md), [configuration/accounts/trust](configuration-trust.md), [client and first analysis](client-first-analysis.md), and [operations/lifecycle](operations-runbook.md). [Reader qualification checklist](reader-validation.md) distinguishes prior mechanism evidence from the exact instructions still NOT RUN. Presence of these files does not close the unexecuted installed-acceptance gates.
