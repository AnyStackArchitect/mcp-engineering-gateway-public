#Requires -Version 5.1
# Windows hosted CI only: two local fake programs, NO SSH authentication/network.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Legacy SCP reservation fixture: $Message" }
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$client = Join-Path $repo 'windows\Send-RockyEvidence.ps1'
$work = Join-Path $env:RUNNER_TEMP ('Rocky SCP Test ' + [Guid]::NewGuid().ToString('N'))
$bin = Join-Path $work 'bin'
$store = Join-Path $work 'synthetic staging'
$keys = Join-Path $work 'key with spaces'
foreach ($folder in @($bin, $store, $keys)) {
    [void](New-Item -ItemType Directory -Path $folder -Force)
}
$oldPath = $env:PATH
$oldRoot = $env:ROCKY_LEGACY_CI_ROOT
$oldDeny = $env:ROCKY_LEGACY_DENY_BEGIN
$oldDrop = $env:ROCKY_LEGACY_DROP_SCP
$oldAvailable = $env:ROCKY_LEGACY_SAFE_BYTES
try {
    $ssh = Join-Path $bin 'ssh.exe'
    $scp = Join-Path $bin 'scp.exe'
    Add-Type -Path (Join-Path $PSScriptRoot 'MockLegacyScp.cs') -OutputAssembly $ssh -OutputType ConsoleApplication -ErrorAction Stop
    [IO.File]::Copy($ssh, $scp)
    $env:PATH = $bin + ';' + $oldPath
    $env:ROCKY_LEGACY_CI_ROOT = $store
    $env:ROCKY_LEGACY_DENY_BEGIN = '0'
    $env:ROCKY_LEGACY_DROP_SCP = '0'
    $env:ROCKY_LEGACY_SAFE_BYTES = '104857600'
    $key = Join-Path $keys 'synthetic SSH identity'
    [IO.File]::WriteAllText($key, 'not a credential')
    $source = Join-Path $work 'synthetic evidence with spaces.bin'
    [byte[]]$bytes = New-Object byte[] (1024 * 1024 + 103)
    $rng = New-Object System.Random 1818
    $rng.NextBytes($bytes)
    $bytes[0] = 0
    $bytes[1] = 255
    $bytes[2] = 10
    $bytes[3] = 13
    [IO.File]::WriteAllBytes($source, $bytes)
    $sha = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $events = Join-Path $store 'events.txt'
    function Clear-Events {
        if (Test-Path -LiteralPath $events) { Remove-Item -LiteralPath $events -Force }
    }
    function Read-Events {
        if (-not (Test-Path -LiteralPath $events)) { return @() }
        return @(Get-Content -LiteralPath $events)
    }
    function Assert-NoPartial {
        $items = @(Get-ChildItem -LiteralPath $store -Force | Where-Object { $_.Name -match '^\.upload-' })
        Assert ($items.Count -eq 0) 'Upload placeholder or reservation was stranded.'
    }
    function Invoke-Client([string]$Destination) {
        return & $client -Path $source -KeyPath $key -RemoteHost 'rocky.example' -RemoteUser 'engtest' -RemoteInstallDir '/opt/rocky-eng' -DestinationName $Destination
    }
    Clear-Events
    $ok = Invoke-Client 'synthetic-first.bin'
    Assert ($ok.Status -eq 'STAGED') 'Reserved SCP did not finalize.'
    Assert ($ok.SHA256 -eq $sha) 'Verified hash changed.'
    $final = Join-Path $store 'synthetic-first.bin'
    Assert (((Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash.ToLowerInvariant()) -eq $sha) 'SCP mutated binary bytes.'
    Assert (((Read-Events) -join ',') -eq 'PREPARE,BEGIN,SCP,FINALIZE') 'SCP did not reserve before bytes.'
    Assert-NoPartial

    Clear-Events
    $env:ROCKY_LEGACY_DENY_BEGIN = '1'
    $denied = $false
    try { $null = Invoke-Client 'denied.bin' } catch { $denied = $true }
    $env:ROCKY_LEGACY_DENY_BEGIN = '0'
    Assert $denied 'Denied reservation was not fatal.'
    Assert (((Read-Events) -join ',') -eq 'PREPARE,BEGIN,ABORT') 'Denied reservation copied bytes or leaked cleanup.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $store 'denied.bin'))) 'Denied staging created final evidence.'
    Assert-NoPartial

    Clear-Events
    $env:ROCKY_LEGACY_DROP_SCP = '1'
    $failed = $false
    try { $null = Invoke-Client 'partial.bin' } catch { $failed = $true }
    $env:ROCKY_LEGACY_DROP_SCP = '0'
    Assert $failed 'Interrupted SCP was not refused.'
    Assert (((Read-Events) -join ',') -eq 'PREPARE,BEGIN,SCP,SCP_INTERRUPTED') 'Failed SCP prematurely freed uncertain remote writer reservation.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $store 'partial.bin'))) 'Partial upload finalized.'
    $sidecars = @(Get-ChildItem -LiteralPath $store -Force | Where-Object { $_.Name -match '^\.upload-[a-f0-9]{32}\.session$' })
    Assert ($sidecars.Count -eq 1) 'Interrupted SCP did not retain exactly one durable reservation.'
    $retainedToken = $sidecars[0].Name.Substring(0, $sidecars[0].Name.Length - '.session'.Length)
    $retainedPrefix = Join-Path $store $retainedToken
    Assert ([IO.File]::ReadAllBytes($retainedPrefix).Length -eq 37) 'Interrupted partial prefix was not retained.'
    # The synthetic SCP process has terminated; only now may an operator
    # explicitly release this reservation through the fixed SSH helper.
    $null = & $ssh '-T' '-o' 'BatchMode=yes' '-o' 'IdentitiesOnly=yes' '-o' 'StrictHostKeyChecking=yes' '-o' 'ClearAllForwardings=yes' '-i' $key 'engtest@rocky.example' 'python3' '-u' '/opt/rocky-eng/transfer_bridge.py' 'abort' '--temp' $retainedToken
    Assert ($LASTEXITCODE -eq 0) 'Explicit post-writer abort did not succeed.'
    Assert (((Read-Events) -join ',') -eq 'PREPARE,BEGIN,SCP,SCP_INTERRUPTED,ABORT') 'Retained reservation was not manually released.'
    Assert-NoPartial

    Clear-Events
    $collided = $false
    try { $null = Invoke-Client 'synthetic-first.bin' } catch { $collided = $true }
    Assert $collided 'Duplicate destination succeeded.'
    Assert (((Read-Events) -join ',') -eq 'PREPARE,BEGIN,SCP,FINALIZE,ABORT') 'Collision cleanup/order wrong.'
    Assert (((Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash.ToLowerInvariant()) -eq $sha) 'Destination changed after collision.'
    Assert-NoPartial

    Clear-Events
    $env:ROCKY_LEGACY_SAFE_BYTES = '50'
    $blocked = $false
    try { $null = Invoke-Client 'no-capacity.bin' } catch { $blocked = $true }
    $env:ROCKY_LEGACY_SAFE_BYTES = '104857600'
    Assert $blocked 'Capacity rejection was ignored.'
    Assert (((Read-Events) -join ',') -eq 'PREPARE') 'Rejected preflight began SCP.'
    Assert-NoPartial

    Clear-Events
    $unsafe = $false
    try { $null = & $client -Path $source -KeyPath $key -RemoteHost 'badhost;invalid' -RemoteUser 'engtest' -RemoteInstallDir '/opt/rocky-eng' }
    catch { $unsafe = $true }
    Assert $unsafe 'Unsafe host syntax accepted.'
    $observed = @(Read-Events)
    Assert ($observed.Count -eq 0) 'Unsafe host invoked remote executable.'
    Write-Output 'PASS: Windows legacy SCP reserves before copy; verified binary, declined begin, interrupted SCP cleanup, destination collision and capacity refusal'
}
finally {
    $env:PATH = $oldPath
    $env:ROCKY_LEGACY_CI_ROOT = $oldRoot
    $env:ROCKY_LEGACY_DENY_BEGIN = $oldDeny
    $env:ROCKY_LEGACY_DROP_SCP = $oldDrop
    $env:ROCKY_LEGACY_SAFE_BYTES = $oldAvailable
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
