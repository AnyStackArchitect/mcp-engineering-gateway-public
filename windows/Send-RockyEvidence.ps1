#Requires -Version 5.1
<#
.SYNOPSIS
Stage a local Windows evidence file into the analysis host's private MCP intake inbox.
.DESCRIPTION
Uses the installed OpenSSH ssh/scp programs and a fixed, non-root remote helper.
No MCP tool transports raw bytes. Does not run arbitrary remote commands, replace
existing evidence, register a case automatically, or upload to a cloud service.
The remote gateway must be installed first; this script is NOT a deployment test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$KeyPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RemoteHost,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RemoteUser,
    [string]$RemoteInstallDir = '/opt/rocky-eng',
    [string]$DestinationName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($RemoteHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') {
    throw 'RemoteHost must be a configured hostname/IP alias (no shell metacharacters).'
}
if ($RemoteUser -cnotmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw 'RemoteUser is invalid.'
}
if ($RemoteInstallDir -cnotmatch '^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or
    $RemoteInstallDir -match '(^|/)\.\.(/|$)') {
    throw 'RemoteInstallDir must be a safe fixed POSIX absolute path without spaces.'
}
if (-not (Get-Command ssh -ErrorAction SilentlyContinue) -or
    -not (Get-Command scp -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH ssh/scp must be available in PATH.'
}
$file = Get-Item -LiteralPath $Path -ErrorAction Stop
$key = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
if ($file.PSIsContainer -or $key.PSIsContainer) {
    throw 'Path and KeyPath must both refer to files.'
}
if ([string]::IsNullOrWhiteSpace($DestinationName)) {
    $DestinationName = $file.Name
}
if ($DestinationName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
    $DestinationName -eq '.' -or $DestinationName -eq '..') {
    throw 'DestinationName is unsafe. Choose a simple ASCII name with -DestinationName.'
}
# Exact file-size cap is intentionally a property of the server, not a client
# bypass. Client preflight still avoids a needless multi-gigabyte upload.
$size = [int64]$file.Length
if ($size -gt 8GB) { throw 'File exceeds initial maximum of 8 GiB.' }
$sha = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$uploadToken = '.upload-' + ([Guid]::NewGuid().ToString('N').ToLowerInvariant())
$target = "${RemoteUser}@${RemoteHost}"
$remoteHelper = "$RemoteInstallDir/transfer_bridge.py"
$sshBase = @('-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
             '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10',
             '-i', $key.FullName)
$scpBase = @('-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
             '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10',
             '-i', $key.FullName)
$stagePath = $null
$uploaded = $false
$scpStarted = $false
$scpSucceeded = $false
try {
    # Advisory size-aware preflight, followed by a durable server-side
    # reservation; only begin makes the capacity commitment atomic.
    $raw = & ssh @sshBase $target 'python3' '-u' $remoteHelper 'prepare' '--size' ([string]$size)
    if ($LASTEXITCODE -ne 0) { throw 'Remote evidence inbox preparation failed.' }
    $response = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($response.status -ne 'READY' -or
        $response.inbox -cnotmatch '^/[A-Za-z0-9._/-]+$' -or
        $response.inbox -match '(^|/)\.\.(/|$)' -or
        $response.inbox -cnotmatch '/\.local/share/rocky-mcp-gateway/inbox$') {
        throw 'Remote helper returned an unexpected inbox location.'
    }
    if ($size -gt [int64]$response.max_artifact_bytes -or
        $size -gt [int64]$response.safe_available_bytes) {
        throw 'Remote staging limit or reserved free-space capacity is insufficient.'
    }
    # 'prepare' only reports available capacity. A separate authenticated
    # 'begin' must persist the whole upload reservation BEFORE any SCP byte
    # can be written; never fall back to old unreserved SCP if begin fails.
    $uploaded = $true # abort even if begin committed but its SSH reply was lost
    $raw = & ssh @sshBase $target 'python3' '-u' $remoteHelper 'begin' `
        '--temp' $uploadToken '--size' ([string]$size) '--sha256' $sha
    if ($LASTEXITCODE -ne 0) { throw 'Remote evidence capacity reservation failed.' }
    $started = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($started.status -cne 'SESSION_CREATED' -or
        [int64]$started.bytes_staged -ne 0 -or
        [int64]$started.declared_size -ne $size -or
        $started.expected_sha256 -cne $sha) {
        throw 'Remote evidence reservation acknowledgment is invalid.'
    }
    $stagePath = $response.inbox + '/' + $uploadToken
    $remoteFile = "${target}:$stagePath"
    # SCP may truncate the pre-created 0600 partial before writing, but the
    # sidecar reservation already accounts for its full declared size.
    $scpStarted = $true
    & scp @scpBase '--' $file.FullName $remoteFile
    if ($LASTEXITCODE -ne 0) { throw 'Evidence file transfer failed.' }
    $scpSucceeded = $true
    # Detect mutation on the local source while the transfer was running.
    $after = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($after -ne $sha -or ([int64](Get-Item -LiteralPath $file.FullName).Length) -ne $size) {
        throw 'Local evidence changed during transfer; staging refused.'
    }
    $raw = & ssh @sshBase $target 'python3' '-u' $remoteHelper 'finalize' `
        '--temp' $uploadToken '--filename' $DestinationName `
        '--size' ([string]$size) '--sha256' $sha
    if ($LASTEXITCODE -ne 0) { throw 'Remote evidence hash/finalization failed.' }
    $result = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($result.status -ne 'STAGED' -or $result.sha256 -ne $sha -or
        [int64]$result.bytes -ne $size -or $result.filename -ne $DestinationName) {
        throw 'Remote evidence finalization response failed verification.'
    }
    $uploaded = $false
    Write-Output ([pscustomobject]@{
        Status = 'STAGED'; File = $DestinationName; Bytes = $size; SHA256 = $sha
        NextAction = 'Use case_open, then job_submit(kind=import_staged,filename=<staged file>)'
    })
}
finally {
    if ($uploaded) {
        if ($scpStarted -and -not $scpSucceeded) {
            # A failing local SCP process does not prove the remote SFTP
            # writer has closed its file descriptor. Deleting the reservation
            # now could free committed capacity while a remote writer remains.
            # Retain its private prefix and full reservation instead.
            Write-Warning ("Interrupted SCP was NOT finalized or auto-aborted. " +
                           "Reserved upload token: $uploadToken. Confirm the remote " +
                           "writer has stopped, then explicitly abort the token or " +
                           "resume using Send-RockyEvidenceResume.ps1 and this token.")
        }
        else {
            # Begin denied or SCP completed and closed cleanly. Only our
            # randomly chosen temporary token may be removed.
            try {
                & ssh @sshBase $target 'python3' '-u' $remoteHelper 'abort' '--temp' $uploadToken |
                    Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Warning 'Remote temporary-file cleanup failed.' }
            }
            catch {
                Write-Warning 'Could not clear a failed transfer; inspect the private Rocky inbox.'
            }
        }
    }
}
