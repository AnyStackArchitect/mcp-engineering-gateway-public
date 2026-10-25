# Security boundaries

SSH stdio authenticates the gateway login. Distinct worker UID and kernel-checked IPC separate chat-facing requests from execution authority. Root-owned policy/code, a public-only pinned signer, one-use short-lived grants and worker-private replay state enforce execution. Rootless Podman uses no network, read-only inputs/root filesystem, reduced capabilities and resource/output bounds. SELinux Enforcing and cgroup controls remain mandatory.

Private cases/logs can contain secrets even after best-effort redaction. Keep inputs, full traces, keys, databases, signer material and nonce/execution history out of Git/CI/public issues. A fixture's synthetic signing key is not a production identity. An assistant cannot approve its own execution or disclosure.

The host administrator, operator workstation and filesystem owner remain trust boundaries. This is a single-operator dedicated host profile, not an Internet upload endpoint or hostile multi-tenant service. No HTTP listener, automatic remediation, external alerts or telemetry is added. A compromised same-UID owner or administrator is not defeated by a case manifest.

Report suspected defects privately to the repository owner through a channel agreed before sharing details; do not post credentials/customer evidence in public issues. Preserve actual failures, source hashes and safe reproduction steps. Do not run a live exploit, upload evidence or change trust as part of reporting.
