# Documentation

[Repository overview](../README.md)

**Current state:** combined local source candidate, not a published release. The implementation and reviewed reader manual are present together; exact-package documentation-led clean-host acceptance remains pending. Public source/assets and deployment actions still require separate approval.

## Read in order

1. [Capabilities and inputs](capabilities.md), [complete tool catalog](tool-catalog.md) and [practical workflows](analysis-workflows.md): implemented functions, actual names and concrete uses.
2. [Architecture and security](architecture.md): gateway, fixed-job processor, isolated worker and signer.
3. [Qualified platform](platform.md): the tested host, prerequisites and resource envelope.
4. [Installation path](installation.md): source verification, operator-built dependencies, enrollment and maintenance.
5. [First use](first-use.md): the synthetic evidence workflow and execution approval boundary.
6. [Extensions](extensions.md): two ways to develop analysis work and the controls to retain.
7. [Qualification](qualification.md): exact candidate identity, evidence scope and unexecuted profiles.
8. [Future direction](direction.md): Phase II intent, separated from implemented behavior.
9. [Licensing and support](licensing-support.md): rights, contribution and reporting expectations.

## When source publication is approved

Installation will require the matching source, notices, manifests and dependency instructions. Readers should be able to verify the released commit and archive identities before running anything. File names mentioned in these pages refer to this source tree. Upper-case legacy operator pages redirect to the canonical lower-case reader manual, while component licensing, security and supplemental failure cases retain their detailed source-specific material.

## Source-only operator manual

- [All required and optional dependencies](dependencies.md), with [complete reference image closure](dependency-inventory.md).
- [Acquire/verify source and install](install-from-source.md): roles, working directories, bound inputs, prepare, activate and audit.
- [Configuration, accounts and independent trust](configuration-trust.md).
- [Connect an MCP client and complete the first synthetic analysis](client-first-analysis.md).
- [Health, private logs, troubleshooting, backup/restore, update and safe retirement](operations-runbook.md).
- [Traceable documentation-led qualification checklist and open limits](reader-validation.md).

These pages and implementation now share the combined source candidate. The exact revised reader walkthrough has not been executed and must be qualified against this final source package.

- [Parameterized site maintenance commands](maintenance-commands.md): correct user manager, capture/isolated restore and plan-verified code-only update/retirement, with explicit unexecuted/destructive boundaries.

- [Combined candidate provenance and prior-runtime bridge](source-integration.md).
