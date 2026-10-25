#Requires -Version 5.1
# Windows CI only. MockSsh.cs is a LOCAL fake executable, NOT an
# authenticated network or production Rocky service.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Windows resume CI failure: $Message" }
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$client = Join-Path $repo 'windows\Send-RockyEvidenceResume.ps1'
$fixtureRoot = Join-Path $env:RUNNER_TEMP ('Rocky Binary Resume CI ' + [Guid]::NewGuid().ToString('N'))
$bin = Join-Path $fixtureRoot 'bin'
$store = Join-Path $fixtureRoot 'remote synthetic evidence'
$keys = Join-Path $fixtureRoot 'keys with spaces'
foreach ($dir in @($bin, $store, $keys)) {
    [void](New-Item -ItemType Directory -Path $dir -Force)
}
$previousPath = $env:PATH
$previousRoot = $env:ROCKY_TEST_UPLOAD_ROOT
$previousDrop = $env:ROCKY_TEST_DROP_ONCE
try {
    $mock = Join-Path $bin 'ssh.exe'
    Add-Type -Path (Join-Path $PSScriptRoot 'MockSsh.cs') -OutputAssembly $mock -OutputType ConsoleApplication -ErrorAction Stop
    Assert (Test-Path -LiteralPath $mock -PathType Leaf) 'Cannot compile fake SSH executable.'
    $env:PATH = $bin + ';' + $previousPath
    $env:ROCKY_TEST_UPLOAD_ROOT = $store
    $key = Join-Path $keys 'ci ssh identity'
    [System.IO.File]::WriteAllText($key, 'synthetic-only; not a private key')
    $sourceFile = Join-Path $fixtureRoot 'binary source sample.bin'
    [byte[]]$payload = New-Object byte[] (3 * 1024 * 1024 + 19)
    $rng = New-Object System.Random 513
    $rng.NextBytes($payload)
    $payload[0] = 0
    $payload[1] = 255
    $payload[2] = 10
    $payload[3] = 13
    [System.IO.File]::WriteAllBytes($sourceFile, $payload)
    $sha = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()

    function Run-Client([string]$Destination, [string]$Token = '', [int]$Retries = 2) {
        $arguments = @{
            Path = $sourceFile
            KeyPath = $key
            RemoteHost = 'rocky.example'
            RemoteUser = 'engtest'
            RemoteInstallDir = '/opt/rocky-eng'
            DestinationName = $Destination
            MaxRetries = $Retries
            AppendTimeoutSeconds = 60
        }
        if (-not [string]::IsNullOrEmpty($Token)) { $arguments.ResumeToken = $Token }
        return & $client @arguments
    }

    # Force ssh.exe to consume only 37 binary bytes, return nonzero, then
    # require the real client to hash the remote prefix and retry remaining.
    $env:ROCKY_TEST_DROP_ONCE = '1'
    $originalInputEncoding = [Console]::InputEncoding.WebName
    $first = Run-Client 'first-synthetic.bin'
    Assert ([Console]::InputEncoding.WebName -eq $originalInputEncoding) 'Windows input encoding was not restored after binary transfer.'
    Assert ($first.Status -eq 'STAGED') 'Automatic SSH interruption recovery did not stage.'
    Assert ($first.SHA256 -eq $sha) 'Automatic recovery returned wrong SHA256.'
    Assert (((Get-FileHash -LiteralPath (Join-Path $store 'first-synthetic.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) -eq $sha) 'Binary payload mutated.'
    Assert (Test-Path -LiteralPath (Join-Path $store 'dropped.flag')) 'Interruption was not triggered.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $store ($first.UploadToken + '.session')))) 'Session metadata remained after successful finalize.'

    # A new PowerShell invocation can resume an existing private token, not
    # just retry within the same process.
    $env:ROCKY_TEST_DROP_ONCE = '0'
    $manual = '.upload-' + ('a' * 32)
    $prefixLength = 27001
    $partial = New-Object byte[] $prefixLength
    [Array]::Copy($payload, 0, $partial, 0, $prefixLength)
    [IO.File]::WriteAllBytes((Join-Path $store $manual), $partial)
    [IO.File]::WriteAllText((Join-Path $store ($manual + '.session')), ($payload.Length.ToString() + '|' + $sha))
    $resumed = Run-Client 'manual-resume.bin' $manual
    Assert ($resumed.Status -eq 'STAGED') 'Explicit resume token did not finalize.'
    Assert (((Get-FileHash -LiteralPath (Join-Path $store 'manual-resume.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) -eq $sha) 'Manual resume mutated binary evidence.'

    # An already staged foreign prefix must be refused even with the expected
    # file size and full-file digest copied into its session metadata.
    $bad = '.upload-' + ('b' * 32)
    $badBytes = [Text.Encoding]::ASCII.GetBytes('tampered preexisting prefix')
    [IO.File]::WriteAllBytes((Join-Path $store $bad), $badBytes)
    [IO.File]::WriteAllText((Join-Path $store ($bad + '.session')), ($payload.Length.ToString() + '|' + $sha))
    $rejected = $false
    try { $null = Run-Client 'should-never-exist.bin' $bad 0 }
    catch {
        if ($_.Exception.Message -match 'Remote prefix hash differs') { $rejected = $true }
        else { throw }
    }
    Assert $rejected 'Mismatched remote prefix was not explicitly rejected.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $store 'should-never-exist.bin'))) 'Tampered evidence was finalized.'
    Assert ([IO.File]::ReadAllBytes((Join-Path $store $bad)).Length -eq $badBytes.Length) 'Tampered prefix changed.'

    # Finalize cannot overwrite an existing verified destination.
    $dup = '.upload-' + ('c' * 32)
    [IO.File]::WriteAllBytes((Join-Path $store $dup), $payload)
    [IO.File]::WriteAllText((Join-Path $store ($dup + '.session')), ($payload.Length.ToString() + '|' + $sha))
    $duplicateRejected = $false
    try { $null = Run-Client 'first-synthetic.bin' $dup 0 }
    catch { $duplicateRejected = $true }
    Assert $duplicateRejected 'Existing staged evidence was overwritten.'
    Assert (((Get-FileHash -LiteralPath (Join-Path $store 'first-synthetic.bin') -Algorithm SHA256).Hash.ToLowerInvariant()) -eq $sha) 'Original destination changed.'

    $unsafeRejected = $false
    try {
        $null = & $client -Path $sourceFile -KeyPath $key -RemoteHost 'badhost;touch /tmp/unsafe' -RemoteUser 'engtest'
    }
    catch { $unsafeRejected = $true }
    Assert $unsafeRejected 'Unsafe remote hostname syntax accepted.'
    Assert ([Console]::InputEncoding.WebName -eq $originalInputEncoding) 'Windows console input encoding was not restored after all transfers.'
    Write-Output 'PASS: Windows PowerShell 5.1 binary stdin, forced drop/retry, manual resume, SHA256 mismatch refusal, destination collision and safe SSH arguments'
}
finally {
    $env:PATH = $previousPath
    $env:ROCKY_TEST_UPLOAD_ROOT = $previousRoot
    $env:ROCKY_TEST_DROP_ONCE = $previousDrop
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}
