# Component-specific supplemental licensing

The owner explicitly approved precise supplemental VSL terms for the existing
Volatility integration. [COMPONENT_LICENSES.json](../COMPONENT_LICENSES.json)
provides the exact file hashes, semantic selectors and line spans. The
[root MIT license](../LICENSE) remains unchanged. Runtime Python bytes and
functionality are unchanged.

## Owner supplemental grant

Copyright (c) 2026 Eric Black.

Eric Black grants recipients an additional license under Volatility Software License version 1.0 for the owner-authored portions precisely identified here. This supplemental grant does not revoke, narrow, replace or make conditional any MIT permissions previously granted, and grants no rights on behalf of third-party owners.

The additional license is [VSL 1.0](../licenses/VOLATILITY3-2.28.2.txt).
Upstream copyright and VSL notices remain intact. This is not a statement that
all original project code has become VSL-only. The same supplemental grant applies
to identical identified content in preserved distribution history, including older
preparation commits with the same listed file hashes but no metadata. No history
is rewritten and no prior MIT permission is withdrawn.

## Scope and mixed files

`windows_memory_runner.py` and `scripts/qualify_windows_memory.py` are dedicated
Volatility integration/qualification files covered in full. In `provider_runner.py`,
only the Volatility descriptor and banner execution/parsing branch are covered.
In `providerplans.py`, coverage is restricted to Volatility descriptors, Windows
version/symbol validation, Windows template selection, Volatility-specific input/
result declarations and validation, and source-bound banner offsets. In
`scripts/qualify_provider_plans.py`, coverage is restricted to the Volatility
probe/version check, synthetic memory fixtures/vectors and known-answer assertions.

Generic execution and bounded_command, source hashing, capacity/broker plumbing,
and Git, Ansible, Sleuth Kit and XFS implementations retain MIT. In mixed lines,
the JSON semantic selector controls scope; a line span does not relicense the
unrelated expression beside it. Source changes invalidate the hash binding and
require scope review. A dependency recipe or generic inventory is not covered
merely because it names Volatility. Tests and other generic support not identified
in the map retain their existing terms.

## Public source remains pending

The owner grant is implemented. Actual public preferred-form source availability
remains PRIVATE/PENDING a separately approved public visibility/release GO.
The prepared source location is the distribution repository and branch recorded
in COMPONENT_LICENSES.json. It is not claimed freely accessible yet. At external
distribution, the exact released revision must provide the covered editable source,
this scope map, VSL text and notices through a freely accessible source location.
A private push does not satisfy this condition. Do not distribute covered additions
externally before that condition is met. This owner declaration does not adjudicate
every possible upstream derivative-work question or remove upstream obligations.

## Generated scripts and notices

The Windows-memory script combines the dedicated adapter with the generic MIT
bounded_command function. The banner script contains covered Volatility portions
alongside generic and other-provider MIT code. Signed template bytes and equality
checks remain unchanged.

Redistribute a generated script with COMPONENT_LICENSES.json, this document, the
MIT license, full VSL text/copyright notices, and the exact freely accessible
preferred-form source revision (or required editable source), preserving the
source-to-generated-script mapping. Use accompanying files; do not alter validated
or signed template bytes or weaken security checks to inject inline notices.
Licensing is not permission to disclose private CONFIG values, paths, evidence,
case data or results.

## Separate rights and validation gates

This approval does not establish symbol acquisition/use entitlement, symbol/dump
redistribution, image publication, binary corresponding-source completion or
clean-host acceptance. Operator-only acquisition/build remains conditional on
independent rights for the intended use; do not infer the owner can grant rights
held by Microsoft or other parties. No image was built by this declaration.
See [licensing gates](LICENSING.md) and [third-party notices](../THIRD_PARTY_NOTICES.md).
