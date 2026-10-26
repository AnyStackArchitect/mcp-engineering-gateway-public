# Dependencies: acquire, build and verify

[Index](index.md) / [Installation](install-from-source.md) / [Trust](configuration-trust.md) / [Validation ledger](reader-validation.md)

**Source is not published yet.** Commands here target the matching complete combined source candidate. They are bound to its source tooling and pinned image inputs. The off-host signing terminal interface has a focused correction; the updated package's affected regression and exact-package reader-led checks must be recorded separately from predecessor results. Source presence is not permission to provision or install a host. Do not substitute a different source or dependency version to work around a refusal.

## Who installs what

| Dependency | Used by / reference | Acquisition and acceptance |
|---|---|---|
| Rocky Linux 10.2 amd64 | Dedicated analysis host, 2 vCPU/8 GiB/40 GiB reference | [Official Rocky downloads](https://rockylinux.org/download), signed release checksums; verify the selected installer/image by Rocky's published procedure. Boot the pinned kernel below. No OS image is bundled. |
| Python 3.12.15, Podman 5.8.2, systemd 257 | Observed native runtime | Signed Rocky repositories; doctor accepts minimum 3.12/5.8.2/257 but a higher version is not automatically qualified. Retain installed RPM versions and dependency transaction. |
| OpenSSH server/client, host keys and authorized login | Host transport | Signed Rocky repositories; the OS administrator owns sshd policy, host-key publication and access restrictions. No key or sshd configuration is distributed. |
| ACL, SELinux, libsepol CIL, setools, account/subid tools | Installer and isolation | Explicit host packages below; their dependency closure is resolved by DNF with signature checks. No `secilc` CLI is required. |
| Git, archive/hash utilities, curl, timeout | Source acquisition, verification and bounded build | Signed Rocky repositories. Git is needed for controller package/bundle builders; a source ZIP is not a Git checkout. |
| Rootless Podman dependencies | Namespace/storage/cgroup setup | DNF resolves Podman's platform dependencies. Do not substitute Docker or disable SELinux. Complete site inventory and actual image/workload tests validate the selected setup. |
| Windows PowerShell 5.1, native OpenSSH, Python, OpenSSL Ed25519 | Measured operator workstation | [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell), [OpenSSH installation](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse), [Python Windows downloads](https://www.python.org/downloads/windows/), [OpenSSL source](https://openssl-library.org/source/). Use administrator-approved signed/provenance-checked distributions; OpenSSL does not provide a project-approved Windows binary here. No exact third-party Windows OpenSSL installer has been qualified. Verify commands below. |
| MCP client with SSH stdio support | Interactive analysis | Choose a client you trust and use its own configuration documentation. The protocol/transport was qualified; no named desktop client's settings schema is certified. The reference transport test in [first analysis](client-first-analysis.md) does not need a paid client. |
| Python container base and Debian packages | Sandbox and fixed providers | Exact digest/snapshot below. Podman builds the closure rather than installing these tools on the analysis host. |
| Volatility 3 **2.28.2**, pefile **2024.8.26** | Banner/Windows-memory adapters | Hash-pinned wheels in `ci/provider-requirements.txt`, official PyPI; VSL and MIT respectively. See rights below. These are not host Python prerequisites. |
| Exact Windows symbols | Current image context and bounded Windows adapter | Separate entitlement and exact artifact hash required; no symbols supplied. The current context builder requires this input even if you intend only Linux tools. See the explicit limitation below. |
| python-evtx **0.8.1**, hexdump **3.3** | Optional host EVTX indexing/System metadata | Separate optional host profile, NOT RUN/unqualified. Exact acquisition/build procedure below. Omit it for the qualified base profile; advertised EVTX tools then return unavailable. |

No memory dump or customer input is needed for the synthetic first analysis. Do not download a real dump just to follow it. Compiler/build helpers for optional source packages belong on an isolated build account, never in the live gateway or worker account.

## Host package installation — administrator mutation

Only on a newly approved dedicated host. In an administrator terminal with existing approved sudo access, from any directory (in an already-authorized root terminal, omit sudo; do not install or grant sudo merely for this manual):

```sh
sudo dnf install -y python3 podman acl policycoreutils-python-utils python3-setools setools-console libsepol shadow-utils-subid openssh-clients openssh-server openssl unzip tar curl git coreutils util-linux grubby
sudo dnf install -y kernel-6.12.0-211.68.1.el10_2 kernel-core-6.12.0-211.68.1.el10_2 kernel-modules-6.12.0-211.68.1.el10_2 kernel-modules-core-6.12.0-211.68.1.el10_2
sudo grubby --set-default /boot/vmlinuz-6.12.0-211.68.1.el10_2.x86_64
sudo systemctl reboot
```

Reboot disconnects sessions and affects every workload on that host; do not run on a shared/accepted deployment. Require signed Rocky repositories and enabled package signature verification; never add `--nogpgcheck`. If a package/version is unavailable, stop and record it rather than using a random RPM or removing the kernel gate. DNF may install additional dependencies; preserve the transaction and `rpm -qa` inventory. `grubby` is a bootloader utility supplied by the OS profile; if absent or the bootloader differs, stop for platform qualification rather than guessing an alternative boot command.

The administrator must establish SSH access under the site network policy before installation: verify sshd through `sudo systemctl status sshd`; enable/start it with `sudo systemctl enable --now sshd` only when that host/service/network action is approved. Restrict inbound SSH to intended operators using your existing network controls; no blanket firewall-open or public exposure instruction is supplied.

After reconnecting with independently verified host identity, run from the approved source root:

```sh
uname -r
python3 --version
podman --version
systemctl --version
getenforce
cat /sys/fs/cgroup/cgroup.controllers
python3 -B tools/doctor.py
```

Expect the exact kernel `6.12.0-211.68.1.el10_2.x86_64`, Enforcing, CPU/memory/pids controllers and doctor JSON `status: PASS_PREREQUISITES`, exit 0. `BLOCKED` exits 2. Doctor checks tool presence, setools and actual CIL symbols, not only package names. Native inventory additionally invokes `/usr/bin/userdbctl` for the accepted systemd NSS profile; doctor alone does not check it. As administrator, run `command -v userdbctl` and `rpm -qf /usr/bin/userdbctl`. Require the actual binary and its trusted signed OS package. If absent, use `sudo dnf provides /usr/bin/userdbctl` to identify the owning package from your signed Rocky repositories, review that result, then `sudo dnf install -y APPROVED_OWNING_PACKAGE` with the exact returned package name (a placeholder, not a literal package). Recheck ownership/presence and retain its RPM version. Do not disable NSS/systemd identities or invent a package mapping to pass. Inventory must return `OBSERVED_REVIEW_REQUIRED`, `inventory.complete: true`, no collector errors and the accepted local provider/NSS observations; any incomplete or ambiguous observation blocks preparation. It is read-only and does not prove a site is installable. Site inventory still must establish unused accounts, paths, local identity resolution, storage and native policy acceptance.

## Operator workstation acquisition and checks

On Windows, PowerShell 5.1 is the inbox Windows PowerShell executable; use its actual version output rather than assuming PowerShell7 has identical behavior. Install native OpenSSH Client through the Windows Optional Features procedure in [Microsoft's instructions](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse); administrator PowerShell can query `Get-WindowsCapability -Online -Name OpenSSH.Client*` and, only if approved and absent, install `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`. Require Installed state and `ssh -V`/`Get-Command scp`; this is an operator-workstation change, not a gateway installation step. Review signed Windows update-source policy first.

Obtain Git from [Git for Windows](https://git-scm.com/downloads/win) and Python from its [official Windows releases](https://www.python.org/downloads/windows/). Verify publisher signatures/download hashes offered for the selected installers before running them under your administrator's policy. Select a private development workspace, command-line access to the chosen executables and LF-preserving Git clone. Require `git --version`, `python --version`, `python -c "import ssl,hashlib,json,zipfile; print('CONTROLLER_IMPORTS_OK')"` and the source closure checker. Gateway Python3.12.15 and controller Python are different environments; no universal Windows installer/version matrix is qualified. Record the actual controller versions in reader acceptance.

If your organization does not supply a trusted OpenSSL executable, an upstream source-build option is documented in [OpenSSL's Windows build instructions](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5/NOTES-WINDOWS.md). Select an approved maintained release from the official source page, verify its published checksum/signature independently, and review that release's INSTALL.md/NOTES-WINDOWS.md. The native x64 MSVC route needs [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/), [Strawberry Perl](https://strawberryperl.com/) and [NASM](https://www.nasm.us/), each independently acquired/verified under its license. From the matching x64 Developer Command Prompt in that release's source root, the upstream sequence is `perl Configure VC-WIN64A`, `nmake`, `nmake test`, then administrator-approved `nmake install`. Choose an isolated approved installation prefix using that release's configuration instructions; do not overwrite a system crypto installation. This alternative is **upstream-documented, not project-executed or a pinned qualified Windows toolchain**. Retain compiler/Perl/NASM/source/OpenSSL identities and test results before accepting it for signing. No unsigned third-party binary mirror is prescribed. Verify `openssl version` and the interactive protected-key procedure on your approved test controller; do not use a generated fixture key in production.

## Public container inputs and their complete closure

The recipe `ci/Containerfile.preparation` uses:

- Base `docker.io/library/python@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe`; [Docker Official Python source](https://github.com/docker-library/python) and [Python license](https://docs.python.org/3/license.html).
- Debian trixie and trixie-security snapshots at `20261017T000000Z` on [snapshot.debian.org](https://snapshot.debian.org/). Apt still verifies repository signatures; only historical metadata expiry is disabled in the recipe. `ci/verify_snapshot.py` verifies the expected snapshot metadata.
- Apt packages `git`, `ansible-core`, `sleuthkit`, `e2fsprogs`, `xfsprogs` plus the base and Apt-resolved dependency closure. [The full reference binary/source inventory](dependency-inventory.md) records every observed Debian row. Snapshot selection is fixed; do not claim an unversioned `apt install` against today's repositories is equivalent.
- [Volatility wheel](https://pypi.org/project/volatility3/2.28.2/) SHA-256 `0461d6dd71b9ddbaf70c96e079c06efdf174ac65383b3dcf10dd165181fbd3c3` and [pefile wheel](https://pypi.org/project/pefile/2024.8.26/) SHA-256 `76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f`. The recipe uses `--require-hashes --only-binary=:all:`; a missing matching artifact is a stop, not permission for an unhashed substitute.

Git, Ansible, Sleuth Kit, XFS/e2fs and the base libraries have their own component licenses; the project MIT license does not cover them all. Apt installs their copyright files under `/usr/share/doc/`; common license texts reside under `/usr/share/common-licenses/`. Keep complete texts, versions and applicable preferred-form/corresponding source before conveying a built image. The source-only project does not convey these binaries or clear image redistribution. [Debian source retrieval](https://www.debian.org/doc/manuals/debian-reference/ch02.en.html) and the snapshot source-package pages identify exact source versions; a package list alone does not fulfill source delivery obligations.

### Windows symbols — rights gate, not an automatic download

Review [the upstream corpus README](https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/v0.0.1/README.md), [VSL 1.0](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/LICENSE.txt) and applicable [Microsoft symbol terms](https://learn.microsoft.com/en-us/legal/windows-sdk/microsoft-symbol-server-license-terms). Establish independent entitlement for your intended acquisition, local use and build before downloading. Review the exact artifact's applicable terms; an upstream link or the project MIT license does not confer permission or accept any agreement on your behalf. If permission is unclear, stop the full image/install path. Public availability is not permission to republish symbols or an image containing them. The distribution supplies only source/build instructions, without these symbols, memory dumps or built images; do not add them to source archives, repository history or release assets.

If entitled, acquire **only** `symbols_win-10_19041-2025_03.zip` from the [official v0.0.1 release](https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1), store privately as `windows.zip`, and verify 789,065 bytes and SHA-256 `abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e`. Do not fetch a dump or substitute current symbols. The current image context tool refuses absent/different symbols. **Without entitlement there is no qualified symbol-free image path in this candidate**; the basic source/log functions can be explored independently, but a full installed signed-provider profile remains blocked. A documentation change cannot remove this product/rights decision.

### Build — nonroot on an approved dedicated Linux amd64 builder

Use the recorded 2 vCPU / 8 GiB total-RAM reference host envelope and at least 20 GiB free build space for the qualified image-build path. The command below limits the build container to 4 GiB; that limit excludes the host OS, Podman and other host processes. A builder with only 4 GiB total RAM has not been qualified. Supplementary 6 GiB signing/lifecycle checks did not qualify image construction at that size. Runtime host requirements remain separately defined in [the platform profile](platform.md); this build envelope is not a throughput or retention-sizing guarantee. Network access is needed to Docker Hub/its registry and CDN, `snapshot.debian.org`, `pypi.org`/`files.pythonhosted.org`, and the authorized symbol download. Installed sandbox jobs remain offline. Resolve approved registry authentication/rate limits through your administrator; do not use publisher credentials.

In the source root, use new absolute paths outside it. Set `SYMBOLS`, `CONTEXT`, `OUTPUT` and `REVISION` to your authorized symbol file, nonexistent context, new private output directory and verified source commit. Do not run with literal placeholders:

```sh
test -n "$SYMBOLS" && test -n "$CONTEXT" && test -n "$OUTPUT" && test -n "$REVISION"
test ! -e "$CONTEXT"
umask 077
mkdir "$OUTPUT"
python3 -B tools/image.py context --symbols "$SYMBOLS" --output "$CONTEXT"
python3 -B tools/image.py verify-context --context "$CONTEXT"
timeout --signal=TERM --kill-after=30s 45m podman build --format oci --build-arg DISTRIBUTION_REVISION="$REVISION" --arch amd64 --jobs 2 --cpu-period 100000 --cpu-quota 200000 --memory 4g --memory-swap 4g --pull=always --tag localhost/rocky-ci-sandbox:phase1-candidate "$CONTEXT"
podman save --format oci-archive --output "$OUTPUT/operator-built.oci.tar" localhost/rocky-ci-sandbox:phase1-candidate
python3 -B tools/image.py verify --archive "$OUTPUT/operator-built.oci.tar"
```

Run each command only after the previous succeeds. Expect `CONTEXT_PREPARED`, then `PASS_CONTEXT_CLOSURE`; retain the final verifier JSON containing `archive_sha256`, `manifest_digest` and `config_digest`. A nonzero build/timeout is failure, not an artifact. Never prune shared storage to recover space. The `localhost` tag is a local output name, not a registry dependency; preserve its canonical alias in the saved archive for fresh activation. OCI bytes may vary with builder metadata; record your actual digests, not the publisher's prior internal-build hash.

Collect the actual image inventory without network or writable root, from the source root:

```sh
podman run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 512m --pids-limit 64 --cpus 1 -v "$PWD/ci/image_inventory.py:/inventory.py:ro,Z" localhost/rocky-ci-sandbox:phase1-candidate python3 -B /inventory.py > "$OUTPUT/image-inventory.json"
```

This executes code in your selected builder image and may relabel the mounted inventory file; use only a dedicated build checkout, not an installed runtime. Require exit 0, actual package versions and notice metadata. Review full license files too: this bounded tool records Debian notice hashes rather than delivering every Debian text. No redistribution clearance follows from the tool. Qualify fixed-provider known answers and installed isolation on the exact resulting image.

## Optional EVTX host profile — instructions reviewed, installation NOT RUN

Required only for EVTX indexing, `evtx_summary`, `evtx_events` and the bounded Windows System-metadata report. This does not enable full EventData or Sigma. [python-evtx 0.8.1](https://pypi.org/project/python-evtx/0.8.1/) is Apache-2.0; [hexdump 3.3](https://pypi.org/project/hexdump/3.3/) states public domain. Review the actual downloaded files and notices, including any conflicting metadata. The selected hexdump input is source-only, so its build executes upstream code.

On an approved isolated Linux Python 3.12 build account, from the source root, set `EVTX_WORK` to a new private directory outside source. The host administrator first installs signed `python3-pip` and `python3-setuptools` RPMs (and records their exact closure); do not mutate the live gateway Python as a build environment:

```sh
umask 077
mkdir "$EVTX_WORK"
mkdir "$EVTX_WORK/inputs"
curl --fail --location --proto '=https' --tlsv1.2 --output "$EVTX_WORK/inputs/python_evtx-0.8.1-py3-none-any.whl" 'https://files.pythonhosted.org/packages/32/12/f16a7a2f118a07649633b8f72803b932c8d9f0d24a2822cc08a1879ddf6f/python_evtx-0.8.1-py3-none-any.whl'
curl --fail --location --proto '=https' --tlsv1.2 --output "$EVTX_WORK/inputs/hexdump-3.3.zip" 'https://files.pythonhosted.org/packages/55/b3/279b1d57fa3681725d0db8820405cdcb4e62a9239c205e4ceac4391c78e4/hexdump-3.3.zip'
printf '%s  %s\n' '46336b854dbe0a1e75873ae30db5f583c9d2262ff1d21bdb6b1e624ecfa18ddb' "$EVTX_WORK/inputs/python_evtx-0.8.1-py3-none-any.whl" 'd781a43b0c16ace3f9366aade73e8ad3a7bd5137d58f0b45ab2d3f54876f20db' "$EVTX_WORK/inputs/hexdump-3.3.zip" | sha256sum --check -
python3 -m zipfile -l "$EVTX_WORK/inputs/hexdump-3.3.zip"
```

These fixed URLs and hashes were checked against official PyPI version metadata. Curl only retrieves bytes; it does not run Python packaging metadata. Require both checksum lines OK before inspecting the archives and their license/build code in a disposable review directory. Do not use `pip download` for this review boundary: source-package metadata preparation can execute code or fetch build dependencies. After explicit source/backend review, continue in the source root:

```sh
python3 -m venv --system-site-packages "$EVTX_WORK/build-env"
"$EVTX_WORK/build-env/bin/python" -m pip --isolated --no-cache-dir wheel --no-deps --no-build-isolation --no-index --find-links "$EVTX_WORK/inputs" --wheel-dir "$EVTX_WORK/wheels" -r ci/optional-evtx-requirements.txt --require-hashes
sha256sum "$EVTX_WORK"/wheels/*.whl
```

This build executes reviewed upstream code. `--no-index`, `--no-build-isolation`, `--isolated` and `--no-cache-dir` prevent pip from selecting an inherited index/config/cache or automatically resolving an isolated build environment; they are not OS network confinement for arbitrary build code. Run the build with outbound network blocked by the separately approved build environment, with all reviewed build requirements already present. No such network-setting change is performed by these commands. Source hashes in the requirements bind input bytes, not generated wheel bytes. Record the new wheel hashes, full license texts, build interpreter and setuptools/pip RPM versions. Missing build backend or further dependency means stop and extend the reviewed closure; do not allow an automatic internet build dependency fetch.

The source input hashes are python-evtx `46336b854dbe0a1e75873ae30db5f583c9d2262ff1d21bdb6b1e624ecfa18ddb` (wheel) or `e96cea25536a3de5074af7f1bdbf011084d09c2e00664ab754d979820ed75fea` (sdist), and hexdump `d781a43b0c16ace3f9366aade73e8ad3a7bd5137d58f0b45ab2d3f54876f20db`.

**Live installation is a separate unqualified administrator step.** Prefer an administrator-built RPM for the exact wheels rather than `sudo pip` or `--break-system-packages`. Its reviewed payload must place `Evtx`, `hexdump` and their metadata on the fixed `/usr/bin/python3` site path visible to the gateway; the candidate has no venv/path-selection switch. Establish the RPM/path/ownership/SELinux procedure on a disposable supported host and retain it before advertising this optional profile as installable. No project-supplied host RPM or qualified generic installer currently exists. This is an explicit remaining dependency-installation gap, not a claimed successful path.

After that approved installation, under the actual gateway login:

```sh
/usr/bin/python3 -I -B -c 'import Evtx.Evtx, hexdump; from importlib.metadata import version; assert version("python-evtx")=="0.8.1"; assert version("hexdump")=="3.3"; print("EVTX_IMPORTS_OK")'
```

Then index an authorized synthetic EVTX input and verify metadata, unavailable/error cases and no EventData disclosure. Imports alone are insufficient. Until the installation and fixture pass, record this profile NOT RUN and keep it out of base acceptance.
