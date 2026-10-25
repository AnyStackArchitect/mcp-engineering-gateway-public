# Local validation and future CI

No GitHub Actions workflows are shipped in this candidate. Do not enable hosted execution during preparation. Use `python -B tools/check.py --output OUTSIDE_REPO` locally. Windows and nonroot Linux are separate profiles; platform skips remain explicit.

Before adding public CI: use disposable GitHub-hosted runners only, contents:read, pinned action SHAs, no persisted checkout credentials, bounded timeouts/concurrency and minimal short-retention metadata. Never attach a lab/self-hosted runner, private environment/secrets or trusted signing access to public/fork code. Do not use pull_request_target to check out untrusted code. Expensive image/native qualification remains deliberate exact-candidate manual approval. Archived private/live workflows are not distribution templates.

## Native Windows controller fixtures

Use native Windows PowerShell5.1 with its inbox modules and an existing approved compiler environment (Add-Type uses the Windows .NET C# compiler). These fixtures compile local fake ssh/scp executables and use synthetic bytes/text identities only; no real SSH, authentication, signing or host deployment occurs. Do not run the separate OpenSSH end-to-end script without its live-target approval. Do not weaken execution policy to run tests.

From the verified source root in a fresh PowerShell5.1 terminal, select a NEW private QA directory outside source:

```powershell
$env:RUNNER_TEMP = 'C:\YOUR_NEW_PRIVATE_QA_DIRECTORY'
New-Item -ItemType Directory -Path $env:RUNNER_TEMP -ErrorAction Stop | Out-Null
& .\windows\tests\Test-ExplicitEndpoint.ps1
& .\windows\tests\Test-LegacyScpReservation.ps1
& .\windows\tests\Test-ResumableClient.ps1
```

Require each fixture's PASS and successful exit. Endpoint tests cover24cases with no actual network: missing/empty/malformed identities refuse before transport, and explicit identities resolve the canonical or explicitly selected install path. Other fixtures cover binary hashes, reservations, interruptions, resume, refusals and collisions. They remove only their newly created synthetic child directories; keep failed receipts, and never point RUNNER_TEMP at unrelated data. Actual installed SSH staging remains a required reader-led acceptance check.
