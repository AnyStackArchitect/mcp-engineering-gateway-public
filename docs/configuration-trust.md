# Configuration, accounts and independent trust

[Index](index.md) / [Install](install-from-source.md) / [First analysis](client-first-analysis.md)

These instructions target the matching source release; this checkout is documentation-only. Security-sensitive key generation/enrollment must be performed deliberately by the authorized custodian/administrator, never by chat or CI.

## Nonsecret site configuration

Start with `ops/deployment/site.example.json` from the source. Do not copy the example's hostname/IDs as if reserved for you.

| Field | Required meaning |
|---|---|
| `schema` | Integer 1 |
| `site_id`, `hostname` | Your site label and actual target hostname; planner validates syntax and inventory match |
| `profile` | Exact compatibility ID `rocky10-ssh-rootless-draft`; not a generic distro promise |
| `source_commit` | Exact selected source distribution commit, never a docs commit |
| `gateway.name/uid/gid/home` | New gateway SSH account and unused IDs, home corresponding to that account |
| `worker.name/home` | Fixed `rocky-eng-worker`, `/home/rocky-eng-worker` |
| `worker.uid/gid` | Distinct unused IDs, in supported 1000–60000 range |
| `worker.subid_start/subid_count` | Reviewed nonoverlapping subordinate-ID range; count 65,536 |
| `paths.code/config/runtime` | Fixed `/opt/rocky-eng`, `/etc/rocky-eng`, `/run/rocky-eng`; must be unused |
| `min_free_bytes` | Per-target admission floor; example 1 GiB is not total capacity sizing |
| `min_runtime_free_bytes` | Optional IPC headroom; reference 16 MiB |

See [platform](platform.md) for real resource/storage budgets. Complete inventory detects identity/path/subid collisions and unclear external identity resolution. Do not edit NSS, reuse a production worker or lower capacity gates.

The gateway's optional observer configuration is `~/.config/rocky-mcp-gateway/config.json`; the source `config.example.json` starts with `repos: {}` and `user_units: []`. Only explicitly allowlisted local repositories/user services are exposed. Keep directories 0700 and regular config files 0600, owned by the gateway, with no links. Never allowlist credential trees or another user's data. Reconnect the client after a catalog change and verify `git_repo_status`/`user_service_status` appear only when intended. Container names/status and analysis excerpts can be sensitive even without environment-value queries.

Administrator-owned `/etc/rocky-eng/execution-policy.json` binds the actual selected identities, limits, trusted public signer and pinned image. Code/config/trust are not gateway-writable. Keep worker home/state private; no gateway access to replay DB, broad sudo, shared key or shared writable socket. The source-generated unit and policy are the supported baseline; hand edits require re-review and relevant qualification.

## Operator workstation checks

In Windows PowerShell 5.1, check `$PSVersionTable.PSVersion`, `Get-Command ssh,scp,python,openssl`, `ssh -V`, `python --version`, `openssl version`. OpenSSL must support Ed25519 and encrypted PKCS8. These are availability checks, not a trust decision about an executable's distributor. Keep the same trusted interpreter/crypto executable for review and signing. Linux client instructions remain a separately qualified path.

Configure an SSH alias with your actual hostname/address, gateway User and protected SSH IdentityFile. `StrictHostKeyChecking yes`, `IdentitiesOnly yes` and `BatchMode yes` must work after authorized enrollment. Verify host-key fingerprints over an independent administrator channel before adding known_hosts; blindly accepting first-contact output is not verification. No private SSH or signing key belongs in the source, site JSON, issue, grant or host staging directory.

## Create the independent execution signer — human interactive terminal

Use a NEW protected directory on the custodian workstation, outside source/cloud sync/shared storage. On POSIX it must be owner-only0700; on Windows remove inheritance and inspect NTFS owner/ACL, allowing only custodian, SYSTEM and local Administrators. Do not copy an ACL command with a guessed username. Have the administrator verify effective access before key generation.

From that protected directory:

```text
openssl genpkey -algorithm ED25519 -aes-256-cbc -out execution-private.pem
openssl pkey -in execution-private.pem -pubout -out operator-public.pem
openssl pkey -pubin -in operator-public.pem -outform DER -out public.der
openssl dgst -sha256 public.der
```

Require interactive passphrase prompts; never pass a passphrase on the command line, environment, chat or a script. Check all exits and private-file access (POSIX0600 or reviewed NTFS ACL); stop if unrelated users can read it. Record the DER SHA-256 as the public SPKI identity and independently confirm it with the enrolling administrator. Transfer only public PEM/DER. Custodian keeps private PEM and passphrase off the analysis host and out of backups controlled by that host. Backup/escrow is their explicit separate policy.

## Review/export/sign/import a job

`execution_prepare` through MCP prepares a plan; it grants no authority. Retain returned `execution_id` and digest. In a gateway-login SSH terminal:

```sh
/usr/bin/python3 -B /opt/rocky-eng/operator_approve.py export "$EXECUTION_ID" --out "$NEW_REVIEW_PATH"
```

Set EXECUTION_ID to the actual returned ID and NEW_REVIEW_PATH to a new private file owned by the gateway. Transfer the review bundle to a new private custodian file. From the verified controller source root, in a human interactive terminal:

```text
python operator_sign.py REVIEW_BUNDLE.json --private-key PROTECTED_EXECUTION_PRIVATE.pem --out NEW_GRANT.json
```

All three filenames are placeholders for your real absolute private paths. Review exact script, input hashes, pinned image, limits, outputs and full displayed digest. Type the full digest only to approve, or `DENY`; OpenSSL separately prompts for the private-key passphrase. A signed denial is not approval. Transfer only the resulting grant into the gateway's private staging area, then as that login:

```sh
/usr/bin/python3 -B /opt/rocky-eng/operator_approve.py import "$STAGED_GRANT"
```

Poll `execution_status`/`execution_result` using the returned execution ID. Validate SUCCEEDED plus declared output hash on positive tests; DENIED for explicit denial; invalid/expired/replayed grants must refuse. Do not edit nonce DB, advance clocks or delete launch markers for a positive outcome. Existing qualification exercised authorized synthetic crypto and actual handoff; manual human-TTY interaction remains NOT RUN and must be closed by the reader-led exercise.

Loss of key/passphrase stops new approvals. Do not replace trust under the same identity or restore older replay history. Fresh activation refuses trust replacement; a new signer needs stopped-state compatibility/enrollment review. Recovery is not a hidden force flag.
