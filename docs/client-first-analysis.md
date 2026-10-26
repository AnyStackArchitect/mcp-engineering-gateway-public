# Connect a client and complete the first analysis

[Index](index.md) / [Install](install-from-source.md) / [Trust/signing](configuration-trust.md) / [Tool catalog](tool-catalog.md)

This executable tutorial is for a newly approved installation of the matching source release. **The baseline reader sequence passed for the tested source artifact; see the exact scope and final documentation-only bridge in [qualification](qualification.md).** Use a verified complete source checkout and a separately approved installed target; reading this tutorial grants no host or signing approval. The snippets follow implemented schemas and use synthetic inputs only. Run on the measured Windows PowerShell 5.1 controller unless a section explicitly says otherwise. Do not execute host mutations merely to review the document.

## 1. Configure SSH stdio in your client

Use the site review bundle's `bundle.json.client.command` and `.args` in your MCP client's own documented settings schema. The transport is equivalent to:

```text
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -l YOUR_GATEWAY_LOGIN YOUR_VERIFIED_HOST_ALIAS /usr/bin/python3 -B -u /opt/rocky-eng/gateway.py
```

Replace login/alias with those approved for this installation. The gateway runs under the gateway account via SSH; it is not a public HTTP server. No worker/root login or new listener is needed. Client schemas differ, so no universal `mcpServers` JSON is promised. The transport command/arguments are the integration contract. Verify initialization/discovery, tools/list and an actual gateway_status invocation in the client; a saved settings entry alone proves nothing.

For the source's legacy protocol path use initialize protocol `2025-11-25`, client capabilities `{}`, then notifications/initialized, tools/list and tools/call on that session. The modern reference below uses `server/discover` and protocol `2026-07-28`, with the same metadata on each request. Retain JSON-RPC IDs and inspect errors. `scripts/smoke_stdio.py` in source tests both paths locally; its temporary/local environment is not proof of your SSH client connection.

## 2. Reference transport checks — PowerShell

In a fresh PowerShell terminal, set these variables to your actual values. `$Source` is the clean verified **source** checkout, not this documentation checkout. `$Key` is a protected SSH login key, not the execution-signing PEM. This setup does not generate keys:

```powershell
$Source = 'C:\YOUR_PRIVATE_WORKSPACE\mcp-eng-source'
$GatewayLogin = 'YOUR_GATEWAY_LOGIN'
$HostAlias = 'YOUR_VERIFIED_HOST_ALIAS'
$Key = 'C:\YOUR_PROTECTED_SSH_DIRECTORY\id_ed25519'
$SshArgs = @('-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
  '-o','StrictHostKeyChecking=yes','-i',$Key,'-l',$GatewayLogin,$HostAlias,
  '/usr/bin/python3','-B','-u','/opt/rocky-eng/gateway.py')
$Meta = @{'io.modelcontextprotocol/protocolVersion'='2026-07-28';
          'io.modelcontextprotocol/clientCapabilities'=@{}}
function Invoke-GatewayRequest([string]$Method, [hashtable]$Params) {
  $Params['_meta'] = $Meta
  $Request = @{jsonrpc='2.0'; id=1; method=$Method; params=$Params}
  $Wire = $Request | ConvertTo-Json -Depth 12 -Compress
  $Lines = @($Wire | & ssh @SshArgs)
  if ($LASTEXITCODE -ne 0) { throw 'SSH transport failed; preserve stderr' }
  if ($Lines.Count -ne 1) { throw 'Unexpected stdout; expected one JSON-RPC response' }
  $Response = $Lines[0] | ConvertFrom-Json
  if ($Response.id -ne 1 -or $Response.error -or $Response.result.isError) {
    throw 'Gateway request refused; inspect the private response'
  }
  $Response.result
}
function Invoke-GatewayTool([string]$Name, [hashtable]$Arguments) {
  $Result = Invoke-GatewayRequest 'tools/call' @{name=$Name; arguments=$Arguments}
  $Result.content[0].text | ConvertFrom-Json
}
$Discovery = Invoke-GatewayRequest 'server/discover' @{}
$Catalog = Invoke-GatewayRequest 'tools/list' @{}
$Status = Invoke-GatewayTool 'gateway_status' @{}
$Discovery
$Catalog.tools.name
$Status
```

Use a fresh terminal without StrictMode changes for this reference snippet. Each modern request opens its own SSH stdio invocation and includes the required metadata; persistent client sessions are validated separately in step1. Require one valid response, no error/isError and expected status/version. The default catalog has44 tools; explicitly configured observers can add2. Optional EVTX declarations do not prove its provider installed. Unexpected stdout/login banner is a transport failure; do not filter arbitrary lines and call it a pass. Do not resubmit a mutation after an uncertain response; inspect retained IDs/state first.

## 3. Make and deliberately stage a safe input

From the same controller terminal, choose a new private local sample directory; no customer data or credentials:

```powershell
$SampleDir = Join-Path $env:LOCALAPPDATA ('McpFirstUse-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $SampleDir -ErrorAction Stop | Out-Null
$Sample = Join-Path $SampleDir 'first-use.log'
$Text = "2026-01-01T00:00:00Z synthetic start`n2026-01-01T00:00:01Z synthetic-example timeout`n2026-01-01T00:00:02Z synthetic end`n"
[IO.File]::WriteAllBytes($Sample, [Text.Encoding]::ASCII.GetBytes($Text))
$ExpectedHash = (Get-FileHash -LiteralPath $Sample -Algorithm SHA256).Hash.ToLowerInvariant()
$Destination = 'first-use-' + [guid]::NewGuid().ToString('N') + '.log'
$Staged = & (Join-Path $Source 'windows\Send-RockyEvidence.ps1') -Path $Sample -KeyPath $Key -RemoteHost $HostAlias -RemoteUser $GatewayLogin -RemoteInstallDir '/opt/rocky-eng' -DestinationName $Destination
if ($Staged.Status -ne 'STAGED' -or $Staged.SHA256 -ne $ExpectedHash -or $Staged.Bytes -ne (Get-Item -LiteralPath $Sample).Length -or $Staged.File -ne $Destination) { throw 'Staging outcome mismatch; stop before registering' }
```

Run the reviewed helper under your allowed PowerShell policy; do not disable execution policy to bypass a block. It requires adjacent `RockyBinaryStream.cs`, ssh/scp and the installed transfer bridge. Supply **every** connection/install parameter as shown. `RemoteHost` and `RemoteUser` are required; the supported install-directory default is `/opt/rocky-eng`, and this tutorial still passes it explicitly. Missing endpoint/login arguments fail before transport. Require the helper's actual STAGED result, matching byte count/hash and safe basename before continuing. Upload is not case import. Its receiver enforces private owner/mode, quotas and collisions; do not loosen metadata or overwrite a prior destination. For interruption use the separate `Send-RockyEvidenceResume.ps1` source instructions with the retained token and unchanged original; do not remove busy locks.

## 4. Open, register, index and search

Continue only after verified STAGED, retaining the real returned identifiers:

```powershell
$Case = Invoke-GatewayTool 'case_open' @{}
$CaseId = $Case.case_id
$Artifact = Invoke-GatewayTool 'artifact_register' @{case_id=$CaseId; filename=$Destination}
if ($Artifact.sha256 -ne $ExpectedHash -or $Artifact.bytes -ne (Get-Item -LiteralPath $Sample).Length) {
  throw 'Input identity mismatch; stop'
}
$ArtifactId = $Artifact.artifact_id
$Index = Invoke-GatewayTool 'log_index' @{case_id=$CaseId; artifact_id=$ArtifactId}
$Matches = Invoke-GatewayTool 'log_search' @{case_id=$CaseId; artifact_id=$ArtifactId; query='synthetic-example'}
$CaseStatus = Invoke-GatewayTool 'case_status' @{case_id=$CaseId}
$Index
$Matches
$CaseStatus
```

Require `lines_indexed`3, one marker match at source line2, the UTC timestamp and original SHA-256/byte count. Case status must retain the artifact across fresh SSH invocations. Inspect source locators/coverage and preserve the response privately. A timeout marker is synthetic evidence, not a diagnosis. Redaction is best-effort; never publish an unreviewed result just because the tool redacts common patterns.

## 5. Verify through the fixed job queue

In a **second** authenticated gateway terminal, start the installed foreground processor:

```text
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -l YOUR_GATEWAY_LOGIN YOUR_VERIFIED_HOST_ALIAS /usr/bin/python3 -B /opt/rocky-eng/jobwork.py --loop
```

Keep it connected; `--once` processes at most one job and exits. Run as gateway, never root or sandbox-worker. In the first PowerShell terminal:

```powershell
$Job = Invoke-GatewayTool 'job_submit' @{case_id=$CaseId; kind='verify_case'}
$JobId = $Job.job_id
$JobStatus = Invoke-GatewayTool 'job_status' @{job_id=$JobId}
$JobStatus
```

Observe at intervals of at least 2 seconds using job_status, up to a bounded deadline; each gateway process/session enforces 60 tool calls per 60 seconds in memory; a fresh SSH process has a fresh limiter, so this is not an account-wide quota. Require a terminal successful state and invoke `job_result` with `@{job_id=$JobId}`; inspect the actual verification outcome/hashes, not state alone. QUEUED with no processor is expected. Preserve failed/cancelled results, do not resubmit blindly. The foreground fixed processor does not persist across disconnect/boot; the separate signed worker service does.

## 6. Try another built-in path, then approved Python

For packets, use an authorized **offline** PCAP/PCAPNG file, stage/register it identically and call pcap_summary with actual case/artifact IDs. Packet decoding is the fixed `decode_pcap` job before the protocol/flow tools; no live capture or payload recovery is implied. For JSON/properties, stage/register two synthetic snapshots then use config_compare/config_drift_report with before/after artifact IDs and format. [Catalog](tool-catalog.md) and [workflows](analysis-workflows.md) describe the other groups and limits.

For your first custom analysis, prepare a synthetic script through execution_prepare with actual case_id, no inputs, declared `result.txt`, timeout10seconds, memory256MiB and disk8MiB:

```json
{"script":"from pathlib import Path\nPath('/output/result.txt').write_text('synthetic-only')\n","artifact_ids":[],"output_names":["result.txt"],"timeout_seconds":10,"memory_mib":256,"disk_mib":8}
```

This JSON is an **arguments fragment**: add the actual case_id before calling execution_prepare. It is not a grant. Complete the interactive export/review/sign/import [procedure](configuration-trust.md); then inspect execution_status/result for SUCCEEDED and the declared output hash. Exercise a fresh DENY plan and consumed-grant replay refusal separately. No real signing or live workload is authorized merely by reading these instructions. Manual human-terminal execution remains an open validation item.

## Completion and retention

Record source/package/image/SPKI identities, host/tool versions, command exits, returned case/artifact/job/execution IDs, original and output hashes, expected/actual observations and failures. Keep the synthetic local/staged originals and case records until acceptance review. Stop only your own foreground queue terminal when drained. Do not delete nonce/history, trust, cases or worker state as tutorial cleanup. Use the [operations runbook](operations-runbook.md) for maintenance and the [traceable acceptance checklist](reader-validation.md) before calling the installation qualified.
