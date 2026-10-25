# Extension and developer guide

[Documentation index](index.md) / [Capabilities](capabilities.md) / [Future direction](direction.md)

The intended audience includes technically capable users who want to bring their own tools into an evidence-oriented workflow. Phase I supplies a foundation to inspect and extend. **Source publication is pending:** today readers can review this design and define an integration's requirements; cloning this docs branch does not supply the implementation or an extension SDK.

## Two development paths

**Operator-reviewed analysis:** the existing execution workflow accepts bounded Python source for an approved container image. A developer can prepare analysis using tools already present in that image, then have the independent custodian review and sign the exact plan. This does not install a binary on the host, approve a job automatically or permit sandbox networking.

**A fixed provider in a development fork:** add a narrowly defined provider with a validated input format, exact tool-version policy, bounded command invocation and structured result semantics. Add its dependency to a reviewed image recipe when needed. Build and qualify a new candidate in a separate disposable environment before proposing its use. This is a source change, not hot-loading a plugin into an accepted installation.

Changing an enrolled image, policy or trust is a separate reviewed migration. Fresh activation intentionally refuses unexpected existing state; it is not a tool for force-swapping images. Old signed plans must not be treated as approval for changed code or dependencies.

## Candidate code map

These file names describe the qualified, unpublished implementation; none is supplied by this docs-only branch. They are an orientation map for later source review, not a stable public plugin API.

| Area | Source responsibilities |
|---|---|
| `gateway.py` | MCP tool declarations, request validation and dispatch |
| `providerplans.py` | Fixed provider catalog, input/version/hash-bound plan generation, exact template/result checks |
| `provider_runner.py` and dedicated runners | Bounded tool invocation and narrowly interpreted provider results |
| `sandboxwork.py` and `podman_policy.py` | Execution lifecycle, startup/cleanup certainty and container constraints |
| `execution_broker.py`, `execution_policy.py`, `approvalwork.py` | Identity separation, protected handoff and signed authorization |
| `outputcopy.py` and `outputwork.py` | Declared safe outputs and evidence registration |
| `ci/Containerfile.preparation`, image inventory and deployment tooling | Dependency build, package identities and installation boundary |

## Define the contract before writing an adapter

Describe the question the tool answers, accepted input type/size and required version. State what its successful output cannot establish. Choose declared outputs and CPU/memory/time/scratch bounds that fit the existing policy. Establish dependency, adapter and symbol/fixture rights independently; the project's MIT license does not license every tool.

Use fixed argument lists, validated configuration and immutable input identities. Preserve originals. Return a small structured result bound to the source/version and keep potentially sensitive raw output in private evidence. Retain meaningful partial, rejected and unavailable outcomes. The current fixed-provider result path verifies the exact recognized template; arbitrary scripts do not automatically become recognized provider results.

Keep the authority boundary: neither an MCP request nor a provider planner may issue a signing grant. Do not add broad host execution, a shared private key, network access, shared replay state or automatic downloads as an integration shortcut.

## Validate and propose the change

Use synthetic/authorized fixtures with known expected results, unsupported inputs, wrong versions/hashes, resource exhaustion, output refusal and failure/recovery cases. Test the actual packaged image and real gateway/worker path in an isolated supported installation, not only a mocked command. Recheck applicable unit/regression suites, dependency inventory, disclosure and licensing after the change. Document new runtime divergences and limits.

Open a focused proposal and reviewable change once source is available. Public or fork pull-request code must never run on a trusted lab self-hosted runner or receive private credentials. This documentation branch adds no workflows. Phase II may build further integrations through this discipline; no automatic compatibility guarantee is implied.
