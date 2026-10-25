# MCP Engineering Gateway

Evidence-based technical analysis and independently approved tool execution through the Model Context Protocol (MCP).

Phase I provides a complete, bounded workflow for collecting analysis inputs, preserving their identity, inspecting them through tools, and running separately approved work in an isolated container. This is a **technical release for engineers, investigators and developers** who want to understand the system and explore adding their own analysis tools. Operating it requires Linux administration, dependency review and explicit control of signing trust.

**Availability: documentation preparation, 25 October 2026.** This branch contains the reader documentation and existing project license. The qualified source candidate is held separately; its source, installer and release assets have **not been published to this repository**. Cloning this documentation branch does not provide an installable gateway. There is no download or installation command to run here yet.

## What Phase I delivers

- Private cases, deliberate file intake, SHA-256 identities and integrity checks.
- Bounded log indexing/search, offline packet inspection and evidence-linked analysis workflows.
- Fixed provider plans for selected tools, with explicit input/version/resource limits and structured results.
- Operator-reviewed Python execution in a pinned, rootless container. A separate signer authorizes each job; chat cannot approve it.
- Installation preparation, trust enrollment, operational guidance and lifecycle procedures that preserve cases and replay history.

The qualified candidate exposes 44 MCP tools. Its capabilities include partial and refused results as meaningful outcomes: a successful command does not establish root cause, validate every input format or prove a general recovery capability. See [capabilities and boundaries](docs/capabilities.md) and [qualification](docs/qualification.md).

## Find your path

| You want to... | Read |
|---|---|
| Understand the workflow and trust model | [Architecture and security](docs/architecture.md) |
| Decide whether your environment fits | [Qualified platform and preparation](docs/platform.md) |
| Understand the future installation path | [Installation and dependency delivery](docs/installation.md) |
| Follow a small synthetic analysis | [First use](docs/first-use.md) |
| Add your own analysis work | [Extension and developer guide](docs/extensions.md) |
| Understand Phase II intentions | [Future direction](docs/direction.md) |
| Check licensing and support expectations | [Licensing and support](docs/licensing-support.md) |

[Documentation index](docs/index.md)

## Technical foundation and future direction

The initial qualified deployment is a dedicated Rocky Linux 10.2 amd64 host, using the exact tested running kernel, SELinux Enforcing and cgroup v2. Access uses authenticated SSH stdio. Dependencies are operator-acquired and the analysis image is operator-built; no publisher image, Windows symbols or memory dumps are offered for download.

Phase II is intended to add further analysis-tool integrations on this foundation. Phase I already provides the execution and evidence boundaries to study and extend once source is published. There is no stable plugin SDK, automatic tool-installation service or dated integration roadmap being promised. New tools require their own design, rights review and validation.

The original project [MIT license](LICENSE) is preserved. Dependency and integration terms also matter; consult [licensing](docs/licensing-support.md) before planning a tool integration.
