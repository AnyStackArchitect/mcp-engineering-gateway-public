#Requires -Version 5.1
<#
.SYNOPSIS
Stage a binary evidence file via resumable authenticated SSH to Rocky.
.DESCRIPTION
Uses fixed non-root transfer_bridge.py actions and SHA-256-pinned sessions.
Evidence bytes go directly to ssh.exe StandardInput via .NET, never through
PowerShell's text pipeline. Interrupted sessions intentionally remain private.
Supply the printed -ResumeToken with the same file to continue a later run.
The original ordinary SCP client is unaffected.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$KeyPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RemoteHost,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RemoteUser,
    [string]$RemoteInstallDir = '/opt/rocky-eng',
    [string]$DestinationName,
    [string]$ResumeToken,
    [ValidateRange(0,5)][int]$MaxRetries = 2,
    [ValidateRange(30,7200)][int]$AppendTimeoutSeconds = 1800
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-InputName([string]$Value) {
    if ($Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
        $Value -eq '.' -or $Value -eq '..') {
        throw 'Evidence filename is unsafe; choose a simple ASCII destination.'
    }
}
function Quote-WindowsArgument([string]$Value) {
    if ($null -eq $Value -or $Value.Contains([char]0)) { throw 'Invalid SSH argument.' }
    $result = '"'
    $slashes = 0
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq '\') { $slashes++; continue }
        if ($c -eq '"') {
            $result += ('\' * (2 * $slashes + 1)) + '"'
            $slashes = 0
            continue
        }
        $result += ('\' * $slashes) + $c
        $slashes = 0
    }
    return $result + ('\' * (2 * $slashes)) + '"'
}
function Format-Hash([byte[]]$Digest) {
    return (($Digest | ForEach-Object { $_.ToString('x2') }) -join '')
}
function Get-StreamSha256([System.IO.Stream]$Stream) {
    $algo = [System.Security.Cryptography.SHA256]::Create()
    try {
        [void]$Stream.Seek(0, [System.IO.SeekOrigin]::Begin)
        return Format-Hash ($algo.ComputeHash($Stream))
    }
    finally { $algo.Dispose() }
}
function Get-PrefixSha256([System.IO.Stream]$Stream, [long]$Count) {
    if ($Count -lt 0 -or $Count -gt $Stream.Length) {
        throw 'Remote offset exceeds local evidence length.'
    }
    $algo = [System.Security.Cryptography.SHA256]::Create()
    try {
        [void]$Stream.Seek(0, [System.IO.SeekOrigin]::Begin)
        $buffer = New-Object byte[] (1024 * 1024)
        [long]$done = 0
        while ($done -lt $Count) {
            $want = [int][Math]::Min([long]$buffer.Length, $Count - $done)
            $got = $Stream.Read($buffer, 0, $want)
            if ($got -le 0) {
                throw 'Local source became shorter during prefix verification.'
            }
            [void]$algo.TransformBlock($buffer, 0, $got, $buffer, 0)
            $done += $got
        }
        [void]$algo.TransformFinalBlock([byte[]]@(), 0, 0)
        return Format-Hash ($algo.Hash)
    }
    finally { $algo.Dispose() }
}
if ($RemoteHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') {
    throw 'RemoteHost contains invalid characters.'
}
if ($RemoteUser -cnotmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw 'RemoteUser contains invalid characters.'
}
if ($RemoteInstallDir -cnotmatch '^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or
    $RemoteInstallDir -match '(^|/)\.\.(/|$)') {
    throw 'RemoteInstallDir must be a simple absolute POSIX path.'
}
if (-not [string]::IsNullOrEmpty($ResumeToken) -and
    $ResumeToken -cnotmatch '^\.upload-[a-f0-9]{32}$') {
    throw 'ResumeToken is invalid.'
}
$sshCommand = @(Get-Command 'ssh.exe' -CommandType Application -ErrorAction Stop)[0]
$file = Get-Item -LiteralPath $Path -ErrorAction Stop
$key = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
if ($file.PSIsContainer -or $key.PSIsContainer) {
    throw 'Evidence and SSH identity paths must be files.'
}
if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    ($key.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Evidence and SSH identity cannot be reparse points.'
}
if ([string]::IsNullOrWhiteSpace($DestinationName)) { $DestinationName = $file.Name }
Assert-InputName $DestinationName
$helper = "$RemoteInstallDir/transfer_bridge.py"
$target = $RemoteUser + '@' + $RemoteHost
$ssh = $sshCommand.Source
$sshBase = @('-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
             '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
             '-o', 'ClearAllForwardings=yes', '-i', $key.FullName)

function Invoke-RemoteJson([string[]]$ActionArgs) {
    # Only restricted fixed remote fields are used, no shell interpolation.
    $argv = @($sshBase) + @($target, 'python3', '-u', $helper) + @($ActionArgs)
    $response = & $ssh @argv
    if ($LASTEXITCODE -ne 0) { throw 'Authenticated remote evidence action failed.' }
    $json = (@($response) -join [Environment]::NewLine).Trim()
    if ($json.Length -eq 0 -or $json.Length -gt 8192) {
        throw 'Remote evidence response is missing or oversized.'
    }
    try { return $json | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Remote evidence response was not valid JSON.' }
}
function Assert-RemoteSession($State, [long]$ExpectedSize, [string]$ExpectedSha) {
    if ($null -eq $State -or
        $State.expected_sha256 -cne $ExpectedSha -or
        [long]$State.declared_size -ne $ExpectedSize) {
        throw 'Resume session does not match the local evidence identity.'
    }
    [long]$offset = $State.bytes_staged
    if ($offset -lt 0 -or $offset -gt $ExpectedSize -or
        [long]$State.remaining_bytes -ne $ExpectedSize - $offset -or
        $State.prefix_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $State.ready_for_case_import -ne $false) {
        throw 'Remote resume state is invalid.'
    }
    if ($State.status -cnotin @('PARTIAL', 'COMPLETE_UNVERIFIED')) {
        throw 'Remote resume state cannot be used for evidence staging.'
    }
    return $offset
}
# The open FileShare.Read handle blocks ordinary Windows write access during
# hashing, upload and finalization. It is disposed on every exit path.
$source = [System.IO.File]::Open($file.FullName, [IO.FileMode]::Open,
                                 [IO.FileAccess]::Read, [IO.FileShare]::Read)
$token = $null
try {
    [long]$size = $source.Length
    if ($size -gt 8GB) { throw 'Evidence exceeds the initial 8 GiB server limit.' }
    $sha = Get-StreamSha256 $source
    if ([string]::IsNullOrEmpty($ResumeToken)) {
        $pre = Invoke-RemoteJson @('prepare', '--size', ([string]$size))
        if ($pre.status -cne 'READY' -or
            [long]$pre.safe_available_bytes -lt $size -or
            [long]$pre.max_artifact_bytes -lt $size) {
            throw 'Remote reserved-capacity preflight refused this upload.'
        }
        $token = '.upload-' + ([Guid]::NewGuid().ToString('N').ToLowerInvariant())
        $started = Invoke-RemoteJson @('begin', '--temp', $token,
                                       '--size', ([string]$size), '--sha256', $sha)
        if ($started.status -cne 'SESSION_CREATED' -or
            [long]$started.bytes_staged -ne 0 -or
            $started.expected_sha256 -cne $sha) {
            throw 'Remote evidence session was not initialized safely.'
        }
        Write-Host "Rocky evidence resume token: $token"
    }
    else {
        $token = $ResumeToken
        Write-Host "Resuming Rocky evidence session: $token"
    }
    $helperCode = Join-Path $PSScriptRoot 'RockyBinaryStream.cs'
    if (-not (Test-Path -LiteralPath $helperCode -PathType Leaf)) {
        throw 'RockyBinaryStream.cs must be adjacent to this PowerShell client.'
    }
    if (-not ('RockyBinaryStream' -as [type])) {
        Add-Type -Path $helperCode -ErrorAction Stop
    }

    $completed = $false
    for ([int]$attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $status = Invoke-RemoteJson @('status', '--temp', $token)
        [long]$offset = Assert-RemoteSession $status $size $sha
        # Remote offset alone never authorizes continuation.
        if ((Get-PrefixSha256 $source $offset) -cne $status.prefix_sha256) {
            throw 'Remote prefix hash differs from local evidence; refusing resume.'
        }
        if ($offset -eq $size) { $completed = $true; break }
        # A begun session already owns a durable reservation for its
        # unfinished bytes. 'prepare --size' reports capacity available to
        # NEW sessions only and must never refuse this session's own bytes.
        # The remote append still atomically checks real free space and
        # all concurrent reservations at every physical write.
        $remoteCommand = "python3 -u $helper append --temp $token --offset $offset"
        $binaryArgs = (@($sshBase) + @($target, $remoteCommand) |
                       ForEach-Object { Quote-WindowsArgument ([string]$_) }) -join ' '
        try {
            $raw = [RockyBinaryStream]::Append(
                $ssh, $binaryArgs, $source, $offset,
                $AppendTimeoutSeconds * 1000)
            $ack = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($ack.status -cnotin @('PARTIAL', 'COMPLETE_UNVERIFIED') -or
                [long]$ack.bytes_staged -ne $size) {
                throw 'Remote append did not acknowledge the complete length.'
            }
            $completed = $true
            break
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                throw 'SSH append failed after permitted retries; use the displayed ResumeToken.'
            }
            Write-Warning 'SSH append interrupted; verifying remote prefix before retry.'
        }
    }
    if (-not $completed) { throw 'Binary transfer did not reach its full declared size.' }
    if ((Get-StreamSha256 $source) -cne $sha -or $source.Length -ne $size) {
        throw 'Local evidence changed while transferring; finalization refused.'
    }
    $final = Invoke-RemoteJson @('finalize', '--temp', $token,
                                 '--filename', $DestinationName,
                                 '--size', ([string]$size), '--sha256', $sha)
    if ($final.status -cne 'STAGED' -or
        $final.sha256 -cne $sha -or
        [long]$final.bytes -ne $size -or
        $final.filename -cne $DestinationName -or
        $final.ready_for_case_import -ne $true) {
        throw 'Remote evidence finalization returned invalid metadata.'
    }
    [pscustomobject]@{
        Status = 'STAGED'; File = $DestinationName; Bytes = $size
        SHA256 = $sha; UploadToken = $token
        NextAction = 'Use case_open then job_submit(kind=import_staged,filename=<staged file>)'
    }
}
catch {
    if ($null -ne $token) {
        Write-Warning ("Upload not confirmed STAGED. " +
                       "Use -ResumeToken $token with the same file, or abort that remote token.")
    }
    throw
}
finally { $source.Dispose() }
