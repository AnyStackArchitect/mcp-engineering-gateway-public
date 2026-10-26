# Qualified platform and preparation

[Documentation index](index.md) / [Installation path](installation.md)

The initial profile is intentionally specific. The combined candidate supplies source, but the baseline reader walkthrough passed within the [recorded qualification scope](qualification.md), while final independent release review and public delivery remain pending. This page defines the supported profile; the linked dependency/install manual supplies commands.

| Component | Qualified reference |
|---|---|
| Analysis host | Dedicated Rocky Linux 10.2, Linux amd64/x86-64 |
| Running kernel | `6.12.0-211.68.1.el10_2.x86_64` |
| Native runtime observed | Python 3.12.15, Podman 5.8.2, systemd 257 |
| Host enforcement | SELinux Enforcing; cgroup v2 CPU/memory/PID controllers |
| Reference VM resources | 2 vCPU, 8 GiB RAM, 40 GiB disk |
| Access | Trusted authenticated SSH stdio; no new public web listener |

Allow at least 20 GiB free initial working space **plus** evidence, derived data, images and backups. The reference is a qualification envelope, not a throughput or retention-sizing promise. Measure your workload and choose backup storage/failure domains explicitly.

The candidate's prerequisite checker examines the running kernel and blocks other unqualified releases, including numerically newer ones. Installing a kernel package without booting it does not meet that check. The original cloud-image kernel experienced a filesystem shutdown during qualification; its root cause was not established. Qualification on the selected kernel is not a universal kernel-fix claim.

## Administrator prerequisites

The host needs trusted OS package repositories; OpenSSH; Python; rootless Podman; ACL tools; account/subordinate-ID helpers; policycoreutils utilities; the native SELinux `libsepol.so.2` CIL API; and Python setools. The standalone `secilc` executable is not required by the actual linker. Strict policy compilation and enforcement are still required.

Choose unused gateway/worker accounts, IDs and a nonoverlapping subordinate-ID range. The candidate uses fixed installation paths under `/opt/rocky-eng`, `/etc/rocky-eng` and `/run/rocky-eng`. Occupied paths, unclear identity sources and policy drift require review; the installer must not erase them to proceed. The qualified worker layout uses `rocky-eng-worker` and its private home. No existing account, preloaded image, publisher key or workstation directory is an installation dependency.

Worker aggregate limits are 200% CPU, 3 GiB memory-high / 4 GiB memory-max, zero swap and 512 tasks; individual sandbox jobs have tighter limits. Raising these values is a new qualification decision.

## Clients and unsupported environments

Qualification used a native Windows operator workstation, OpenSSH transport and a test MCP client. It verified discovery and invocation, not every MCP desktop application's configuration schema. Consult the actual client's documentation and verify a live connection rather than assuming a server entry is sufficient.

ARM64, macOS-hosted gateways, general Windows-hosted gateways, arbitrary Linux distributions and multi-tenant deployments are not qualified. Linux client interoperability needs its own qualification; it should not be inferred from the Linux server tests.
