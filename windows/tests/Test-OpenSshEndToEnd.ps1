#Requires -Version 5.1
<#
Runs the shipped Windows clients through native Windows OpenSSH to actual
Ubuntu OpenSSH/Python processes in a disposable WSL1 distribution. WSL1 is
explicit: this is not a Rocky kernel, filesystem, deployment, or power-loss test.
Only a metadata report leaves the fixture. All keys and the distribution die
with this job; no tunnel, external SSH endpoint, or permanent credential exists.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ReportPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'This fixture runs only on a disposable GitHub-hosted runner.'
}

function Assert-CI([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Real OpenSSH qualification failed: $Message" }
}
function Quote-Native([string]$Value) {
    # WSL parses its leading mode switches before CommandLineToArgvW and does
    # not remove quotes there. Keep simple arguments bare; paths with spaces
    # and empty key passphrases still require the Windows quoting below.
    # https://github.com/microsoft/WSL/blob/4609b0c1b5453313b3c73d3520de8fa8c98e7010/src/windows/common/WslClient.cpp
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $quoted = '"'; $slashes = 0
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq '\') { $slashes++; continue }
        if ($c -eq '"') { $quoted += ('\' * (2 * $slashes + 1)) + '"' }
        else { $quoted += ('\' * $slashes) + $c }
        $slashes = 0
    }
    return $quoted + ('\' * (2 * $slashes)) + '"'
}
function Invoke-Native([string]$Exe, [string[]]$Arguments,
                       [int]$TimeoutSeconds = 90, [switch]$AllowFailure) {
    $operation = [IO.Path]::GetFileName($Exe)
    # Only the fixed leading option identifies the operation. Do not log full
    # command lines, which can contain paths, session tokens, or SSH identities.
    if ($Arguments.Count -gt 0 -and $Arguments[0] -cmatch '^--?[A-Za-z][A-Za-z-]{0,31}$') {
        $operation += ' (' + $Arguments[0] + ')'
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Exe
    $start.Arguments = (($Arguments | ForEach-Object { Quote-Native $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw ('Native CI command timed out: ' + $operation)
        }
        $result = [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = ($output.Result -replace "`0", '')
            Stderr = ($errors.Result -replace "`0", '')
        }
        if (-not $AllowFailure -and $result.ExitCode -ne 0) {
            $details = ($result.Stdout + $result.Stderr)
            if ($details.Length -gt 4000) { $details = $details.Substring($details.Length - 4000) }
            throw ($operation + ' failed: ' + $details)
        }
        return $result
    }
    finally { $process.Dispose() }
}
function Convert-ToWslPath([string]$WindowsPath) {
    $absolute = [IO.Path]::GetFullPath($WindowsPath)
    Assert-CI ($absolute -match '^[A-Za-z]:\\') 'A local Windows drive path is required.'
    return '/mnt/' + $absolute.Substring(0, 1).ToLowerInvariant() + '/' + $absolute.Substring(3).Replace('\', '/')
}
function Restrict-Key([string]$KeyFile) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $KeyFile -AclObject $acl
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$unique = [Guid]::NewGuid().ToString('N')
$fixture = Join-Path $env:RUNNER_TEMP ('Rocky Real SSH ' + $unique)
$distro = 'RockyGatewayCI' + $unique
$alias = 'rocky-ci-' + $unique
$badAlias = 'rocky-ci-bad-' + $unique
$sshDirectory = Join-Path $env:USERPROFILE '.ssh'
$configPath = Join-Path $sshDirectory 'config'
$hadConfig = Test-Path -LiteralPath $configPath -PathType Leaf
[byte[]]$oldConfig = @()
if ($hadConfig) { $oldConfig = [IO.File]::ReadAllBytes($configPath) }
$oldPath = $env:PATH
$imported = $false
$configChanged = $false
$failure = $null
$report = [ordered]@{
    status = 'RUNNING'; checkout_sha = $env:GITHUB_SHA
    platform = 'Windows PowerShell 5.1 -> native Windows OpenSSH -> Ubuntu userspace on WSL1'
    rootfs_sha256 = 'e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86'
    checks = @(); registrations = @(); cleanup_completed = $false
    rocky01_qualified = $false; real_linux_kernel_qualified = $false
    host_power_loss_proven = $false; raw_evidence_in_report = $false
}
try {
    [void](New-Item -ItemType Directory -Path $fixture -Force)
    [void](New-Item -ItemType Directory -Path $sshDirectory -Force)
    $nativeBin = Join-Path $env:WINDIR 'System32\OpenSSH'
    $ssh = Join-Path $nativeBin 'ssh.exe'
    $keygen = Join-Path $nativeBin 'ssh-keygen.exe'
    $wsl = Join-Path $env:WINDIR 'System32\wsl.exe'
    Assert-CI (Test-Path -LiteralPath $ssh -PathType Leaf) 'Native Windows OpenSSH is unavailable.'
    $env:PATH = $nativeBin + ';' + $oldPath
    # PATH can contain the native OpenSSH directory more than once. Match
    # Get-Command's first selected executable, exactly as the shipped client does.
    $selectedSsh = @(Get-Command ssh.exe -CommandType Application -ErrorAction Stop)[0]
    $selectedScp = @(Get-Command scp.exe -CommandType Application -ErrorAction Stop)[0]
    Assert-CI ($selectedSsh.Source -eq $ssh) 'ssh.exe resolves to a substitute.'
    Assert-CI ($selectedScp.Source -eq (Join-Path $nativeBin 'scp.exe')) 'scp.exe resolves to a substitute.'
    $version = Invoke-Native $ssh @('-V')
    Assert-CI ($version.Stderr -match 'OpenSSH_for_Windows') 'The binary does not identify as native Windows OpenSSH.'
    $report.client = $version.Stderr.Trim()
    $report.powershell = $PSVersionTable.PSVersion.ToString()
    Assert-CI ($PSVersionTable.PSVersion.Major -eq 5) 'Qualification must use Windows PowerShell 5.1.'
    Write-Output 'CI: native Windows PowerShell and OpenSSH binaries identified.'

    $keys = Join-Path $fixture 'keys with spaces'
    [void](New-Item -ItemType Directory -Path $keys)
    $key = Join-Path $keys 'authorized identity'
    $badKey = Join-Path $keys 'unauthorized identity'
    foreach ($keyPath in @($key, $badKey)) {
        $null = Invoke-Native $keygen @('-q', '-t', 'ed25519', '-N', '', '-f', $keyPath)
        Restrict-Key $keyPath
    }
    $archive = Join-Path $fixture 'ubuntu-base.tar.gz'
    $tar = Join-Path $fixture 'ubuntu-base.tar'
    # Canonical's fixed release and published SHA256SUMS are cited in the workflow.
    $rootfs = 'https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-amd64.tar.gz'
    $null = Invoke-Native 'curl.exe' @('--fail', '--location', '--retry', '3', '--max-time', '180', '--output', $archive, $rootfs) 220
    Assert-CI ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -eq $report.rootfs_sha256) 'Ubuntu rootfs SHA-256 does not match the pinned release.'
    $compressed = [IO.File]::OpenRead($archive)
    $expanded = [IO.File]::Create($tar)
    $gzip = New-Object IO.Compression.GzipStream($compressed, [IO.Compression.CompressionMode]::Decompress)
    try { $gzip.CopyTo($expanded) }
    finally { $gzip.Dispose(); $expanded.Dispose(); $compressed.Dispose() }
    $installDirectory = Join-Path $fixture 'distro'
    [void](New-Item -ItemType Directory -Path $installDirectory)
    # Also attempt cleanup if WSL partially registers the distribution then fails.
    $imported = $true
    Write-Output 'CI: Ubuntu rootfs SHA-256 verified; importing with WSL --import and --version 1.'
    $null = Invoke-Native $wsl @('--import', $distro, $installDirectory, $tar, '--version', '1') 240
    Write-Output 'CI: pinned Ubuntu userspace imported with explicit WSL version 1.'
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $setup = Join-Path $fixture 'prepare_ssh_fixture.sh'
    # Windows checkout settings may yield CRLF; normalize only this test copy.
    $setupText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'prepare_ssh_fixture.sh')).Replace("`r`n", "`n")
    [IO.File]::WriteAllText($setup, $setupText, (New-Object Text.UTF8Encoding $false))
    $null = Invoke-Native $wsl @('--distribution', $distro, '--user', 'root', '--exec', '/bin/bash',
        (Convert-ToWslPath $setup), (Convert-ToWslPath $repo), (Convert-ToWslPath ($key + '.pub')), ([string]$port)) 600
    Write-Output 'CI: disposable loopback-only OpenSSH endpoint started.'
    $hostKey = (Invoke-Native $wsl @('--distribution', $distro, '--user', 'root', '--exec',
        '/bin/cat', '/run/rocky-ssh-ci/host_ed25519.pub')).Stdout.Trim()
    Assert-CI ($hostKey -match '^ssh-ed25519 [A-Za-z0-9+/=]+ ') 'Cannot read the independently generated host public key.'
    $known = Join-Path $fixture 'known_hosts'
    $hostLabel = 'rocky-ci-host-' + $unique
    $badHostLabel = 'rocky-ci-wrong-host-' + $unique
    $wrongHostKey = [IO.File]::ReadAllText($badKey + '.pub').Trim()
    [IO.File]::WriteAllText($known, "$hostLabel $hostKey`n$badHostLabel $wrongHostKey`n", (New-Object Text.UTF8Encoding $false))
    $knownConfigPath = $known.Replace('\', '/')
    $testConfig = ''
    foreach ($item in @(@($alias, $hostLabel), @($badAlias, $badHostLabel))) {
        $testConfig += @"
Host $($item[0])
    HostName 127.0.0.1
    Port $port
    HostKeyAlias $($item[1])
    UserKnownHostsFile "$knownConfigPath"
    GlobalKnownHostsFile none
    UpdateHostKeys no
    ProxyCommand none
    ProxyJump none
    ControlMaster no
    LogLevel ERROR

"@
    }
    $prefix = [Text.Encoding]::UTF8.GetBytes($testConfig)
    [IO.File]::WriteAllBytes($configPath, [byte[]]($prefix + $oldConfig))
    $configChanged = $true
    $baseArgs = @('-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes',
        '-o', 'ConnectTimeout=10', '-i', $key, ('engci@' + $alias))
    $endpoint = '/opt/rocky-ssh-ci/windows/tests/ssh_ci_endpoint.py'
    $bridge = '/opt/rocky-ssh-ci/transfer_bridge.py'
    function Read-Control([string[]]$ActionArgs) {
        return (Invoke-Native $ssh ($baseArgs + @('python3', '-u', $endpoint) + $ActionArgs)).Stdout | ConvertFrom-Json
    }
    function Read-Bridge([string[]]$ActionArgs) {
        return (Invoke-Native $ssh ($baseArgs + @('python3', '-u', $bridge) + $ActionArgs)).Stdout | ConvertFrom-Json
    }
    $identity = Read-Control @('identity')
    Assert-CI ($identity.uid -gt 0) 'Remote transfer ran as root.'
    Assert-CI ($identity.bridge_sha256 -eq (Get-FileHash -LiteralPath (Join-Path $repo 'transfer_bridge.py')).Hash.ToLowerInvariant()) 'Remote bridge bytes differ from this checkout.'
    $report.server = $identity
    $report.checks += 'authenticated_native_openssh_and_exact_bridge'
    Write-Output 'CI: authenticated native Windows SSH reached the exact nonroot Python bridge.'

    $source = Join-Path $fixture 'binary evidence with spaces.bin'
    [byte[]]$payload = New-Object byte[] (5 * 1024 * 1024 + 257)
    (New-Object Random 513).NextBytes($payload)
    $payload[0] = 0; $payload[1] = 255; $payload[2] = 10; $payload[3] = 13
    [IO.File]::WriteAllBytes($source, $payload)
    $sha = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.payload_bytes = $payload.Length
    $report.payload_sha256 = $sha
    function Run-Client([string]$Destination, [string]$Token = '', [string]$IdentityFile = $key,
                        [string]$HostAlias = $alias, [switch]$Legacy) {
        $resultPath = Join-Path $fixture ([Guid]::NewGuid().ToString('N') + '.json')
        $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $PSScriptRoot 'Invoke-OpenSshClient.ps1'), '-SourceFile', $source,
            '-IdentityFile', $IdentityFile, '-HostAlias', $HostAlias, '-Destination', $Destination,
            '-ResultPath', $resultPath)
        if ($Token) { $arguments += @('-Token', $Token) }
        if ($Legacy) { $arguments += '-Legacy' }
        $native = Invoke-Native 'powershell.exe' $arguments 180 -AllowFailure
        $value = if (Test-Path -LiteralPath $resultPath) { Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json } else { $null }
        return [pscustomobject]@{ Native = $native; Value = $value }
    }
    function Assert-Staged($Result) {
        Assert-CI ($Result.Native.ExitCode -eq 0) ('Client failed: ' + $Result.Native.Stdout + $Result.Native.Stderr)
        Assert-CI ($Result.Value.result.Status -eq 'STAGED' -and $Result.Value.result.SHA256 -eq $sha -and
            $Result.Value.result.Bytes -eq $payload.Length) 'The shipped client did not return the exact staged identity.'
    }
    Add-Type -Path (Join-Path $repo 'windows\RockyBinaryStream.cs') -ErrorAction Stop
    function Send-Bytes([string]$Token, [byte[]]$Bytes) {
        $argv = $baseArgs + @("python3 -u $bridge append --temp $Token --offset 0")
        $arguments = (($argv | ForEach-Object { Quote-Native $_ }) -join ' ')
        $stream = New-Object IO.MemoryStream(,$Bytes)
        try { return [RockyBinaryStream]::Append($ssh, $arguments, $stream, 0, 60000) | ConvertFrom-Json }
        finally { $stream.Dispose() }
    }
    function Begin-Session([string]$Token) {
        $null = Read-Bridge @('prepare', '--size', ([string]$payload.Length))
        $result = Read-Bridge @('begin', '--temp', $Token, '--size', ([string]$payload.Length), '--sha256', $sha)
        Assert-CI ($result.status -eq 'SESSION_CREATED') 'A real upload reservation was not created.'
    }

    $before = Read-Control @('inspect')
    $denied = Run-Client 'unauthorized.bin' -IdentityFile $badKey
    Assert-CI ($denied.Native.ExitCode -ne 0 -and ($denied.Native.Stdout + $denied.Native.Stderr) -match 'Permission denied') 'An unauthorized key was not rejected by OpenSSH.'
    $wrongHost = Run-Client 'wrong-host.bin' -HostAlias $badAlias
    Assert-CI ($wrongHost.Native.ExitCode -ne 0 -and ($wrongHost.Native.Stdout + $wrongHost.Native.Stderr) -match 'HOST IDENTIFICATION HAS CHANGED|Host key verification failed') 'A mismatched host key was not rejected.'
    $after = Read-Control @('inspect')
    Assert-CI (@($before.trace).Count -eq @($after.trace).Count) 'Rejected authentication reached the transfer bridge.'
    $report.checks += 'wrong_identity_and_pinned_host_key_refused'

    $null = Read-Control @('arm-drop')
    $automatic = Run-Client 'automatic-retry.bin'
    Assert-Staged $automatic
    $state = Read-Control @('inspect')
    $drop = @($state.trace | Where-Object { $_.event -eq 'forced_disconnect' })
    Assert-CI ($drop.Count -eq 1 -and $drop[0].partial_bytes -eq 2MB -and $drop[0].bridge_signal -eq 'SIGKILL') 'The real forced disconnect did not happen.'
    $append = @($state.trace | Where-Object { $_.event -eq 'bridge' -and $_.action -eq 'append' -and $_.token -eq $automatic.Value.result.UploadToken })
    Assert-CI ($append.Count -eq 2 -and $append[0].offset -eq 0 -and $append[1].offset -eq 2MB) 'The shipped client did not resume the persisted offset after real SSH termination.'
    Assert-CI ($state.artifacts.'automatic-retry.bin'.sha256 -eq $sha) 'Binary content changed during transport recovery.'
    $report.forced_disconnect = $drop[0]
    $report.checks += 'real_ssh_session_kill_then_automatic_prefix_verified_retry'
    Write-Output 'CI: real SSH session termination and automatic binary resume passed.'

    $manualToken = '.upload-' + [Guid]::NewGuid().ToString('N')
    Begin-Session $manualToken
    [byte[]]$partial = New-Object byte[] 27001
    [Array]::Copy($payload, $partial, $partial.Length)
    $partialAck = Send-Bytes $manualToken $partial
    Assert-CI ($partialAck.status -eq 'PARTIAL' -and $partialAck.bytes_staged -eq $partial.Length) 'A partial real SSH upload did not persist.'
    $manual = Run-Client 'explicit-resume.bin' $manualToken
    Assert-Staged $manual
    Assert-CI ($manual.Value.process_id -ne $automatic.Value.process_id) 'Explicit resume was not a new PowerShell process.'
    $report.checks += 'explicit_resume_from_new_powershell_process'

    $badToken = '.upload-' + [Guid]::NewGuid().ToString('N')
    Begin-Session $badToken
    [byte[]]$badPrefix = [Text.Encoding]::ASCII.GetBytes('different remote prefix')
    $null = Send-Bytes $badToken $badPrefix
    $refused = Run-Client 'bad-prefix.bin' $badToken
    Assert-CI ($refused.Native.ExitCode -ne 0 -and ($refused.Native.Stderr + $refused.Native.Stdout) -match 'Remote prefix hash differs') 'The shipped client resumed a foreign prefix.'
    $unchanged = Read-Bridge @('status', '--temp', $badToken)
    Assert-CI ($unchanged.bytes_staged -eq $badPrefix.Length) 'Refused prefix was overwritten.'
    $report.checks += 'prefix_hash_mismatch_refused_before_append'

    $fullBadToken = '.upload-' + [Guid]::NewGuid().ToString('N')
    Begin-Session $fullBadToken
    [byte[]]$wrongPayload = $payload.Clone()
    $wrongPayload[$wrongPayload.Length - 1] = [byte]($wrongPayload[$wrongPayload.Length - 1] -bxor 1)
    $null = Send-Bytes $fullBadToken $wrongPayload
    $finalize = Invoke-Native $ssh ($baseArgs + @('python3', '-u', $bridge, 'finalize', '--temp', $fullBadToken,
        '--filename', 'bad-digest.bin', '--size', ([string]$payload.Length), '--sha256', $sha)) 90 -AllowFailure
    Assert-CI ($finalize.ExitCode -ne 0 -and $finalize.Stderr -match 'digest/identity verification failed') 'Remote full-file digest mismatch was not rejected.'
    $report.checks += 'full_file_digest_mismatch_refused'

    $collision = Run-Client 'automatic-retry.bin'
    Assert-CI ($collision.Native.ExitCode -ne 0) 'Existing destination was overwritten.'
    $state = Read-Control @('inspect')
    Assert-CI ($state.artifacts.'automatic-retry.bin'.sha256 -eq $sha) 'Collision damaged the original destination.'
    Assert-CI ($state.artifacts.PSObject.Properties.Name -notcontains 'bad-prefix.bin' -and
        $state.artifacts.PSObject.Properties.Name -notcontains 'bad-digest.bin') 'Rejected evidence was finalized.'
    $collisionToken = @($state.trace | Where-Object { $_.event -eq 'bridge' -and $_.action -eq 'begin' })[-1].token
    foreach ($token in @($badToken, $fullBadToken, $collisionToken)) { $null = Read-Bridge @('abort', '--temp', $token) }
    $report.checks += 'non_overwriting_finalize_and_explicit_failed_session_cleanup'

    $legacy = Run-Client 'ordinary-scp.bin' -Legacy
    Assert-Staged $legacy
    $state = Read-Control @('inspect')
    $sftpEvents = @($state.trace | Where-Object { $_.event -eq 'sftp' })
    Assert-CI ($sftpEvents.Count -eq 1 -and $state.artifacts.'ordinary-scp.bin'.sha256 -eq $sha) 'Ordinary Windows scp did not use actual SFTP and preserve bytes.'
    Assert-CI ($state.session_count -eq 0) 'Finalized or explicitly aborted session reservations remain.'
    $report.checks += 'ordinary_windows_scp_over_real_authenticated_sftp'
    foreach ($name in @('automatic-retry.bin', 'explicit-resume.bin', 'ordinary-scp.bin')) {
        $entry = Read-Control @('register', '--filename', $name, '--size', ([string]$payload.Length), '--sha256', $sha)
        Assert-CI ($entry.status -eq 'REGISTERED_AND_VERIFIED') 'Gateway/worker case registration failed.'
        $report.registrations += $entry
    }
    $report.checks += 'three_real_gateway_worker_imports_and_vault_verifications'
    $report.status = 'PASS'
}
catch { $failure = $_; $report.status = 'FAIL'; $report.failure = $_.Exception.Message }
finally {
    $cleanupErrors = @()
    $env:PATH = $oldPath
    if ($configChanged) {
        try {
            if ($hadConfig) { [IO.File]::WriteAllBytes($configPath, $oldConfig) }
            else { Remove-Item -LiteralPath $configPath -Force }
        }
        catch { $cleanupErrors += 'Could not restore the temporary SSH config.' }
    }
    if ($imported) {
        try {
            $null = Invoke-Native $wsl @('--terminate', $distro) 45 -AllowFailure
            $null = Invoke-Native $wsl @('--unregister', $distro) 90
        }
        catch { $cleanupErrors += 'Could not unregister the disposable WSL fixture.' }
    }
    try { if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force } }
    catch { $cleanupErrors += 'Could not remove all temporary fixture files.' }
    $report.cleanup_completed = ($cleanupErrors.Count -eq 0)
    if ($cleanupErrors.Count -gt 0) { $report.status = 'FAIL'; $report.cleanup_errors = $cleanupErrors }
    [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
}
if ($null -ne $failure) { throw $failure }
Assert-CI ($report.status -eq 'PASS' -and $report.cleanup_completed) 'Fixture cleanup did not complete.'
Write-Output ($report | ConvertTo-Json -Depth 12)
