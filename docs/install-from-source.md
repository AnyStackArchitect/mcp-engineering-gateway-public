# Install the matching source release

[Index](index.md) / [Dependencies](dependencies.md) / [Configuration and trust](configuration-trust.md) / [First analysis](client-first-analysis.md)

**Use only a verified complete source candidate and a separately approved target.** Publication remains pending. This combined source/manual preserves the implementation described in [qualification](qualification.md); its exact package identities come from packaging provenance and the accompanying candidate manifest, and the completed baseline reader rehearsal is scoped to the exact tested artifact plus the explicit destination-delta qualification bridge. Administrator steps modify accounts, root-owned code, SELinux policy, images and services. Use a dedicated approved supported host, never an existing deployment.

## Roles and separate terminal sessions

| Session | Identity / shell | Owns these paths and decisions |
|---|---|---|
| Linux build/controller | Approved nonroot account, Bash; may be a separate approved builder | Clean Git source, INPUT/OUTPUT, site-bundle/package commands and rootless image build |
| Target administrator | Root on the exact dedicated supported host, Bash | Root-private STAGE/TRANSACTION, inventory, prepare/activate/audit, site lifecycle |
| Windows operator | Native PowerShell 5.1 with approved SSH key | Client configuration, synthetic sample/staging and reference protocol tutorial |
| Signing custodian | Protected interactive workstation terminal, independent authority | Private execution signer, review and deliberate signing; no private key transferred to target |

No variable or current directory automatically transfers between these sessions. Explicitly set/verify the needed values again after SSH/reconnect and transfer reviewed files through authorized transport. Linux `$INPUT`/`$OUTPUT` refer to controller paths; target `$STAGE`/`$TRANSACTION` refer to different target paths. `$SOURCE_ROOT` in the maintenance manual is the verified complete source tree on the target. Windows `$Source` is the verified controller source checkout. A technically capable operator may hold more than one role, but must keep signing authority and key custody separate from the gateway/worker.

## 1. Acquire and verify source — operator controller

The full release needs a Git checkout for the package and site-bundle builders. A GitHub-generated archive is not the project's deterministic source package and contains no `.git`. When source is published, obtain the approved **source commit**, `CHECKSUMS.txt`, release manifest, qualification summary and deterministic source package from that same release. There is no current download URL or version tag to paste here.

On a controller with trusted Git, Python and SSH, from a new workspace parent (Bash example):

```sh
git clone https://github.com/AnyStackArchitect/mcp-engineering-gateway-public.git mcp-eng-source
cd mcp-eng-source
git checkout --detach "$RELEASE_COMMIT"
git rev-parse HEAD
git status --porcelain
python3 -B ops/deployment/package.py
```

Before this block, set `RELEASE_COMMIT` to the independently approved 40-hex source commit from the release manifest. Do not use the docs commit or simply run current main. Require HEAD equality, empty status and JSON `SOURCE_CLOSURE_PASS`. The source closure checker refuses missing/extra/changed files against the public allowlist and SHA256SUMS. Checksums identify bytes; compare with an independently trusted release record rather than trusting an archive and its neighboring checksum alone. Preserve notices and `COMPONENT_LICENSES.json`; root MIT does not cover every component.

For the deterministic ZIP, use `sha256sum /absolute/path/source.zip` on Linux or `Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\absolute\path\source.zip'` on Windows and compare with the release's exact hash/size. Do not extract or execute an unknown archive. Windows Git must preserve published LF bytes (for example a fresh `git -c core.autocrlf=false clone ...`); do not normalize a working candidate merely to make verification pass.

## 2. Set up separate private paths and nonsecret configuration

Install and verify [all prerequisites](dependencies.md) before inventory. Define these absolute paths on the controller, outside the clean source checkout:

| Value | Meaning / requirement |
|---|---|
| `INPUT` | Existing private input directory with reviewed `site.json` and transferred target inventory |
| `OUTPUT` | Existing private output directory; all output filenames below must be new |
| `SSH_ALIAS` | Your verified host alias in your SSH configuration, never a publisher alias |
| `STAGE` | New root-owned 0700 directory on the target, e.g. `/root/mcp-install-unique` |
| `TRANSACTION` | New target transaction path outside STAGE, e.g. `/root/mcp-transaction-unique` |

Create `site.json` from the source `ops/deployment/site.example.json`; [the field reference](configuration-trust.md) explains every required choice. Use the actual hostname and unused identities/subids. Keep the source clean: input/output must not be added to the repo. Explicit paths are site decisions, not commands to overwrite existing locations. Never put passwords, private keys or grants in site JSON.

## 3. Collect inventory — target administrator

Copy the verified source checkout and `site.json` through your authorized transfer channel into a new private staging area. Preserve root ownership and avoid symlinks/hardlinks. From that source root, as root:

```sh
umask 077
python3 -B tools/doctor.py
python3 -B ops/deployment/site_inventory.py --site "$STAGE/site.json" --ssh-verified > "$STAGE/inventory-envelope.json"
python3 -c 'import json,sys; e=json.load(open(sys.argv[1])); assert e["inventory"]["complete"]; json.dump(e["inventory"],open(sys.argv[2],"x"))' "$STAGE/inventory-envelope.json" "$STAGE/inventory.json"
```

Run only after setting STAGE to the actual new private directory. `--ssh-verified` attests your independently verified connection; it does not probe SSH. Preserve envelope/errors even on failure. Require complete inventory and no unresolved observations. Transfer the nonsecret site JSON and inventory back into the controller's INPUT directory privately; inventory may reveal host identities and must not be published.

## 4. Package and review — clean controller source root

```sh
python3 -B ops/deployment/package.py --output "$OUTPUT/source.zip"
python3 -B ops/deployment/site_plan.py --site "$INPUT/site.json" --inventory "$INPUT/inventory.json"
python3 -B ops/deployment/site_bundle.py --site "$INPUT/site.json" --inventory "$INPUT/inventory.json" --ssh-alias "$SSH_ALIAS" --output "$OUTPUT/site-review.zip"
```

Require `DISTRIBUTION_PACKAGE_PASS` and record `sha256`, `bytes`, `commit`, `source_manifest_sha256`. The plan must have no findings and exit 0, `OFFLINE_PLAN_REVIEW_REQUIRED`; that is still a review plan, not installation acceptance. Bundle creation returns `OFFLINE_REVIEW_BUNDLE_CREATED`, its SHA-256 and `deployment_ready: false`. Inspect `bundle.json`, proposed account/service/policy/client settings and inventory binding. A review bundle contains no private trust or image. Do not edit a bound bundle in place.

Build/verify your image using [dependencies](dependencies.md). Establish your own public trust using [configuration and trust](configuration-trust.md). Copy only approved packages, site JSON, image and public PEM to STAGE. Do not transfer the private signing key. Require each staged file's independently approved hash and root-owned 0600 regular metadata, with no links. The target stage must be inaccessible to gateway/worker accounts.

## 5. Verify and prepare disabled installation — target root

Set STAGE and TRANSACTION to your approved absolute paths. Set SOURCE_MANIFEST_SHA to the **manifest** hash printed by package.py, not the ZIP hash; BUNDLE_SHA is the reviewed site-review.zip hash. Verify the staged ZIP checksum separately before extraction. In the private target staging directory:

```sh
python3 -I -B -m zipfile -e "$STAGE/source.zip" "$STAGE/unpacked"
ENTRY="$STAGE/unpacked/source/ops/deployment/deploy.py"
python3 -I -B "$ENTRY" verify-source --source-manifest-sha256 "$SOURCE_MANIFEST_SHA"
python3 -I -B "$ENTRY" inventory --source-manifest-sha256 "$SOURCE_MANIFEST_SHA" --site "$STAGE/site.json" --ssh-verified
python3 -I -B "$ENTRY" prepare --source-manifest-sha256 "$SOURCE_MANIFEST_SHA" --bundle "$STAGE/site-review.zip" --bundle-sha256 "$BUNDLE_SHA" --state "$TRANSACTION" --allow-experimental-prepare
python3 -I -B "$ENTRY" verify --source-manifest-sha256 "$SOURCE_MANIFEST_SHA" --state "$TRANSACTION"
```

Run commands individually and retain JSON, stderr and exit code; stop on any failure. The explicit experimental flag is the actual compatibility gate, not a reason to suppress findings. Prepare creates fresh accounts, code, policy and labels, but leaves worker disabled, without image/public trust. Verify must validate the exact transaction. Inspect the journal before activation; an empty shell return is insufficient. Collisions require a new reviewed site/target, not deletion of existing accounts/files. For failed preparation preserve the transaction; only the installer's conservative rollback can determine unchanged fresh resources it may remove. Never reuse a failed state path blindly.

## 6. Enroll exact image and public signer — target root

Set OCI_SHA, OCI_MANIFEST, OCI_CONFIG and PUBLIC_SPKI to the actual approved identities; manifest/config values include `sha256:`. The image verifier produces OCI identities; the OpenSSL DER hash is the public SPKI. Review boot activation with the administrator first:

```sh
python3 -I -B "$ENTRY" activate --source-manifest-sha256 "$SOURCE_MANIFEST_SHA" --state "$TRANSACTION" --image "$STAGE/operator-built.oci.tar" --archive-sha256 "$OCI_SHA" --manifest-digest "$OCI_MANIFEST" --config-digest "$OCI_CONFIG" --public-key "$STAGE/operator-public.pem" --public-spki-sha256 "$PUBLIC_SPKI" --enable-at-boot
```

Require successful transaction verification and the expected disabled-to-activated state. Activation prepares a nonrunning cold container and verifies removal before enabling the signed worker; it does not authorize a workload. If it fails after enrolling trust/image, leave the worker stopped/disabled and preserve everything. Do not delete trust/history, force reload or reuse rollback as an uninstaller. [Recovery](operations-runbook.md) explains the limit.

The administrator separately authorizes the **gateway** SSH public key in that login's owner-only home/.ssh/authorized_keys (0700 directories/0600 file, matching owner, restored SELinux labels). Follow your existing approved sshd/key enrollment procedure, not a copied root/worker key. SSH access and signing trust are separate. Verify the host key independently and test login under the gateway identity; do not enable password/root login or weaken sshd/network policy to get a pass.

## 7. Prove useful operation and retain receipts

Follow [client and first analysis](client-first-analysis.md), then run as root after actual workload/recovery creates the expected state:

```sh
python3 -I -B "$ENTRY" audit --source-manifest-sha256 "$SOURCE_MANIFEST_SHA" --state "$TRANSACTION"
```

Require exact code/image/public trust, UID/domain, resource and IPC checks. Do not fabricate missing runtime directories to make audit pass. Complete the [documentation-led acceptance checklist](reader-validation.md), including negative authorization, replay, recovery, boot and lifecycle. A successful service start or fixture test is not clean-host acceptance. Keep installation inputs/journals/receipts private for maintenance, without private signing material.
