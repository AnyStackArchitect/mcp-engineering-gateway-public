# Licensing and support expectations

[Documentation index](index.md) / [Installation model](installation.md)

## Project and dependency rights

The existing [MIT license](../LICENSE), copyright 2026 Eric Black, is preserved. It covers the original work to which it applies; it does not grant rights in every dependency, symbol, fixture or analysis input.

The qualified source candidate includes precise owner-approved supplemental Volatility Software License 1.0 terms for designated Volatility integration code. Those terms preserve the original MIT permissions and are scoped through a component-license map; they do not relicense the whole project or grant rights on behalf of third parties. The matching source release must include that map, upstream license text and third-party notices. This docs-only branch does not include the adapter code or its full source-release licensing bundle.

Acquiring Volatility separately does not remove applicable integration-source obligations. Approved public preferred-form source access must precede matching source-asset publication. Review the exact published component map and notices when source is released.

The distribution model is **source-only, with independently acquired operator dependencies**. No prebuilt image, Windows symbol archive or memory dump is cleared for project redistribution. Operators must establish rights for their own intended use; availability at a public URL and a matching hash do not establish entitlement. Internal qualification rights do not grant blanket rights for customer or production forensic use.

Publishing an image later would require a separate rights review of its exact contents, full notices and applicable corresponding-source delivery obligations. The MIT project license, package inventory or successful tool run is not that review.

## Support and contributions

This is a technical release intended for users who can administer the qualified Linux environment and inspect analysis behavior. The repository makes no support SLA, response-time commitment, managed-service offering or universal recovery guarantee. The license's warranty terms apply.

Repository issues and pull requests are available to people with access. For a useful report, identify the relevant commit/artifact, qualified platform, expected/actual result and a minimal synthetic reproduction. Keep production credentials, private case material, customer inputs and dumps out of issues and comments. A concise bounded observation is more useful than an unreviewed raw evidence upload.

Source contributions will be reviewed once the implementation is published. Propose one clearly bounded change, its dependency/license implications and validation evidence. Do not enable workflows or route untrusted public/fork changes to trusted self-hosted runners. Documentation review can proceed now without uploading the held source candidate.
