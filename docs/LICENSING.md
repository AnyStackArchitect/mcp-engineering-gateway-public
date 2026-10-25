# Source-specific licensing and distribution gates

The root [MIT license](../LICENSE) remains unchanged. It covers the original work
to which the owner applies it; it does not grant rights in third-party software,
symbols or fixtures. [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) identifies
researched components and their upstream terms. Source-only licensing and the recorded operator-image inventory were reviewed;
operator entitlement, public preferred-form source access and binary/image
redistribution remain separate gates. No blanket redistribution clearance is claimed.

## Volatility adapter scope: owner-approved supplemental terms

Volatility3 2.28.2 uses VSL 1.0, whose Additions scope includes purpose-built
execution/result-parsing wrappers. The owner explicitly approved precise
component-specific supplemental VSL terms. [COMPONENT_LICENSES.json](../COMPONENT_LICENSES.json)
and [component licensing](COMPONENT_LICENSING.md) implement the owner grant using
exact file hashes and semantic selectors, including identical covered content in
preserved preparation history. Root MIT and prior MIT grants are preserved; no
runtime bytes or capabilities change. Generic/non-Volatility code remains MIT.
Upstream VSL and copyright notices remain intact.

Actual freely accessible preferred-form source remains PRIVATE/PENDING separately
approved public visibility at the exact released revision. A private push is
insufficient. Acquiring Volatility separately does not remove the wrapper-source
condition. Symbol-use entitlement and image publication are separate unresolved
rights gates; no approval is inferred from the owner's supplemental grant.

## Source release and operator-built dependencies

The source package should contain original source, reviewed build recipes and
configuration, notices and pinned dependency identities. Do not insert cached
wheels, executables, OCI layers or downloaded test data into the ZIP. Operators
can acquire dependencies directly from their upstream distributors and build
locally, subject to their applicable terms. This approach avoids conveying those
binary dependencies as part of the source ZIP; it does not cancel the VSL wrapper
source condition or authorize otherwise restricted symbol uses.

## Windows symbols and test data

Symbol redistribution is **NOT CLEARED for this product**. The official
[test-data v0.0.1 README](https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/v0.0.1/README.md)
does state corpus licensing and copyright and links VSL1.0. An absent root LICENSE
file does not mean the corpus has no stated terms. Those upstream terms and the
exact artifact's complete rights chain must both be evaluated, especially for
Microsoft-derived symbols; this candidate does not infer that one party's grant
overrides another party's restrictions.

Microsoft symbol-server terms describe specified internal debugging/testing uses
and restrict sharing or publishing Symbol Items. Do not publish symbol bytes,
Windows dumps or images containing those items merely because an upstream URL is
public. Any different or additional license accompanying a particular artifact
must be reviewed for that exact artifact.

An operator may supply a symbol archive acquired from the original source only
where independently entitled to acquire and use it. They must review the relevant
terms and intended use. Hash verification establishes identity, not entitlement;
a confirmation flag does not grant rights. Keep acquisition opt-in and avoid any
silent download of crash dumps. Pin the expected symbol hash before the build.

Without authorized symbols, retain the Windows-memory adapter and its explicit
unavailable/refusal behavior. Do not report positive Windows-memory acceptance or
full image equivalence. That acceptance remains NOT RUN until the authorized
pack is provided and the resulting image is qualified. Optional fixture downloads
require separate rights/provenance entries and must remain outside release assets
unless cleared.

## Prebuilt OCI image publication gate

No prebuilt image is cleared by the top-level MIT license or by this document.
Before publishing one, retain and review:

1. Exact OCI archive, manifest and configuration digests, architecture, base digest,
   build recipe/input hashes and complete installed package versions.
2. Full installed Debian copyright/license files and common-license texts, Python
   license/acknowledgements, and every wheel's license/NOTICE metadata. License-file
   hashes alone do not deliver the required notices to recipients.
3. Exact corresponding source for copyleft binaries and libraries, including
   applicable Debian patches/build material, and a compliant delivery method.
   Generic upstream homepages and a list of package names are insufficient proof.
4. Transitive dependencies, including base-image packages, rather than only the
   explicitly requested packages. Inspect actual xfsprogs notices and the optional
   python-evtx/hexdump closure.
5. Explicit symbol/fixture rights dispositions and the VSL adapter-source decision.

The image inventory tool is useful evidence gathering; it is not rights approval.
Publishing an image needs a new review of its exact built contents and source
closure, even if a local operator build worked.

## Current disposition

| Gate | Result |
| --- | --- |
| Existing root MIT retained | PASS |
| Direct upstream license research | PASS for the identified source documents |
| VSL adapter scope and supplemental owner grant | IMPLEMENTED; actual public source availability PENDING |
| Windows symbol redistribution | NOT CLEARED |
| Recorded reference operator-image inventory and notice capture | Reviewed at the qualified predecessor; not a new image build |
| Binary/image corresponding-source delivery and redistribution clearance | NOT CLEARED by this source-only candidate |
| Public test-fixture redistribution | NOT CLEARED unless individually documented |

These gates limit publication claims. They do not reopen accepted private
operation or authorize a new signing, credential, host or service action.

## Optional host-provider acquisition pins

`ci/optional-evtx-requirements.txt` records official PyPI hashes for python-evtx0.8.1 and its selected hexdump3.3 dependency. Source-only hexdump build, exact installed environment and its own license files still require review; pinning availability does not clear redistribution or prove host installation. No provider package is redistributed in this source ZIP.

## Exact upstream license reference

[licenses/VOLATILITY3-2.28.2.txt](../licenses/VOLATILITY3-2.28.2.txt) preserves the
exact upstream VSL text and copyright. That reference file does not itself change
MIT or grant rights in owner code. The separately approved supplemental owner
grant is in [component licensing](COMPONENT_LICENSING.md). Public-source availability
remains pending. Generated script redistribution needs accompanying notices and
preferred-form source as described there; no script bytes were changed.
