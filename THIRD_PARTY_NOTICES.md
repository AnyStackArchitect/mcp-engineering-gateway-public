# Third-party notices and dependency inventory

The project license is in [LICENSE](LICENSE). That MIT license does not replace
licenses for third-party software, base-image contents, symbols or test data.
This file records researched dependency terms; it is not complete prebuilt-image
redistribution clearance. No third-party binary, OCI image, Windows symbol pack,
crash dump or downloaded fixture is licensed for redistribution by this document.

| Component | Version or scope | Terms and release requirement |
| --- | --- | --- |
| Python | Digest-pinned Python base image; host Python 3.12+ | PSF and incorporated licenses. Preserve installed Python notices and license acknowledgements. Docker-library packaging scripts are separately MIT-licensed; that does not license the complete image. |
| Debian packages | Snapshot-selected base and added packages | Package-specific terms. Retain all installed copyright/license files and identify exact source-package versions, including Debian patches and build material. |
| Git | Exact image package version | GPL-2.0 with file-specific exceptions. A redistributed binary needs a compliant corresponding-source delivery arrangement and notices. |
| ansible-core | Exact snapshot package version | GPL-3.0 and file-specific terms. Preserve notices and satisfy corresponding-source obligations for redistributed binaries. |
| Sleuth Kit | Exact snapshot package version | Mixed IPL/CPL, permissive and standalone GPL-2.0 components. Use the installed package copyright inventory; do not label the entire package BSD or MIT. |
| e2fsprogs | Exact snapshot package version | GPL-2.0 utilities with LGPL, BSD and MIT library components. Preserve exact component notices and applicable source obligations. |
| xfsprogs | Exact snapshot package version | Exact installed copyright/license closure remains to be verified from the built image and matching source package. |
| Volatility3 | 2.28.2 | Volatility Software License (VSL) 1.0. Preserve its license and copyright. Its definition of Additions explicitly includes purpose-built execution/result-parsing wrappers; the owner-approved supplemental scope is in COMPONENT_LICENSES.json; actual freely accessible source remains pending before external distribution. |
| pefile | 2024.8.26 | MIT; copyright 2004-2024 Ero Carrera. Include its full copyright/license when redistributing its code or wheel. |
| python-evtx | Optional 0.8.1 | Apache-2.0. Preserve license, attribution and applicable NOTICE material; identify modifications. Its dependency hexdump must also be pinned and inventoried if installed. |
| Windows symbols | Operator-supplied exact pack only | Redistribution NOT CLEARED. Availability and a matching hash do not prove rights. Do not publish an image containing symbol bytes without applicable permission. |
| Third-party test corpora | Separately acquired optional fixtures | Not included as approved redistributed data. Public availability is not a redistribution license; track each fixture separately. |

## Authoritative sources

- [Python 3.12 license and incorporated notices](https://docs.python.org/3.12/license.html)
- [Docker-library Python packaging license](https://github.com/docker-library/python/blob/master/LICENSE)
- [Debian copyright and source guidance](https://www.debian.org/releases/trixie/amd64/ch01s08.en.html)
- [Git COPYING](https://github.com/git/git/blob/master/COPYING)
- [Ansible COPYING](https://github.com/ansible/ansible/blob/v2.19.0/COPYING)
- [Sleuth Kit license overview](https://www.sleuthkit.org/sleuthkit/licenses.php)
- [e2fsprogs NOTICE](https://github.com/tytso/e2fsprogs/blob/master/NOTICE)
- [Debian xfsprogs package and copyright/source links](https://www.debian.org/Packages/stable/admin/xfsprogs)
- [Volatility3 2.28.2 VSL](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/LICENSE.txt)
- [pefile 2024.8.26 MIT license](https://github.com/erocarrera/pefile/blob/v2024.8.26/LICENSE)
- [python-evtx 0.8.1 Apache license](https://github.com/williballenthin/python-evtx/blob/v0.8.1/LICENSE.TXT)
- [python-evtx 0.8.1 dependency metadata](https://github.com/williballenthin/python-evtx/blob/v0.8.1/pyproject.toml)
- [Microsoft symbol-server license terms](https://learn.microsoft.com/en-us/legal/windows-sdk/microsoft-symbol-server-license-terms)
- [Volatility test-data v0.0.1 README](https://github.com/volatilityfoundation/volatility3-test-data/blob/v0.0.1/README.md)

See [licensing and distribution gates](docs/LICENSING.md) before conveying source
or publishing images. This inventory records upstream terms reviewed on
2026-10-25; exact installed package notices control the individual artifacts.

The exact upstream Volatility3v2.28.2 VSL text is retained in [licenses/VOLATILITY3-2.28.2.txt](licenses/VOLATILITY3-2.28.2.txt). The test-data v0.0.1 corpus README also states VSL terms; selected symbol rights-chain remains unresolved. The supplemental owner adapter grant is implemented in COMPONENT_LICENSES.json; actual public source availability remains pending. No symbol bytes, test dumps or provider binaries are conveyed in this source package.

[Component-specific supplemental terms](docs/COMPONENT_LICENSING.md) preserve MIT grants, cover identical listed content in preserved distribution history, and document generated-script notice/source obligations. They do not license symbols or approve image publication.
