param([Parameter(Mandatory=$true)][string]$FixtureDirectory)
$ErrorActionPreference = 'Stop'
# Read public, pinned fixture FILES only. Never query a host event channel or Message.
$fixtures = @(
    @{name='security.evtx'; bytes=2166784; sha='5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d'; count=2261},
    @{name='system.evtx'; bytes=1118208; sha='ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e'; count=1601}
)
$publicProviders = @('Microsoft-Windows-Security-Auditing','Microsoft-Windows-Kernel-Boot','Microsoft-Windows-FailoverClustering','Service Control Manager','Microsoft-Windows-Hyper-V-Worker','Microsoft-Windows-Hyper-V-VMMS','Microsoft-Windows-Eventlog')
$references = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'evtx_native_reference.json') | ConvertFrom-Json).fixtures
if ($references.Count -ne 2) { throw 'Native reference fixture inventory mismatch' }
$results = @()
foreach ($fixture in $fixtures) {
    $path = Join-Path $FixtureDirectory $fixture.name
    $item = Get-Item -LiteralPath $path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $fixture.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $fixture.sha) { throw 'Public EVTX fixture integrity mismatch' }
    $rows = [Collections.Generic.List[string]]::new()
    $successCount = 0
    Get-WinEvent -Path $path -Oldest -ErrorAction Stop | ForEach-Object {
        $event = $_
        try {
            $provider = $event.ProviderName
            if ($provider -and $publicProviders -cnotcontains $provider) {
                $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($provider))
                $provider = 'provider-' + [Convert]::ToHexString($hash).ToLowerInvariant().Substring(0,12)
            }
            $channel = if (@('System','Security','Application') -ccontains $event.LogName) { $event.LogName } else { '' }
            $time = if ($null -eq $event.TimeCreated) { 'UNTIMED' } else { ([DateTimeOffset]$event.TimeCreated.ToUniversalTime()).ToUnixTimeMilliseconds().ToString([Globalization.CultureInfo]::InvariantCulture) }
            $rows.Add(('{0}|{1}|{2}|{3}|{4}' -f $event.RecordId,$event.Id,$time,$channel,$provider))
            if ($channel -ceq 'Security' -and $provider -ceq 'Microsoft-Windows-Security-Auditing' -and $event.Id -eq 4624) { $successCount++ }
        } finally { $event.Dispose() }
    }
    if ($rows.Count -ne $fixture.count) { throw 'Native EVTX record count mismatch' }
    $rows.Sort([StringComparer]::Ordinal)
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($rows -join "`n") + "`n"))).ToLowerInvariant()
    $reference = @($references | Where-Object { $_.fixture -ceq $fixture.name })
    if ($reference.Count -ne 1 -or $reference[0].records -ne $rows.Count -or $reference[0].native_metadata_sha256 -cne $digest) { throw 'Native metadata reference mismatch' }
    $reference = $reference[0]
    $identities = [Collections.Generic.List[string]]::new()
    $times = [Collections.Generic.List[long]]::new()
    foreach ($row in ($rows | Sort-Object { [long](($_ -split '\|',2)[0]) })) {
        $fields = $row.Split('|')
        $identities.Add(($fields[0],$fields[1],$fields[3],$fields[4] -join '|'))
        $times.Add([long]$fields[2])
    }
    $identityHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($identities -join "`n") + "`n"))).ToLowerInvariant()
    if ($identityHash -cne $reference.identity_sha256 -or $reference.record_order -cne 'ascending_record_number' -or $reference.utc_unit -cne 'epoch_milliseconds') { throw 'Native record identity reference mismatch' }
    $memory = [IO.MemoryStream]::new([Convert]::FromBase64String($reference.utc_zlib_base64))
    $zlib = [IO.Compression.ZLibStream]::new($memory,[IO.Compression.CompressionMode]::Decompress)
    $reader = [IO.StreamReader]::new($zlib)
    try { $expectedTimes = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose(); $zlib.Dispose(); $memory.Dispose() }
    if ($expectedTimes.Count -ne $times.Count) { throw 'Native timestamp reference inventory mismatch' }
    for ($i=0; $i -lt $times.Count; $i++) {
        if ($expectedTimes[$i] -ne $times[$i]) { throw 'Native timestamp reference mismatch' }
    }
    $results += @{fixture=$fixture.name; records=$rows.Count; metadata_sha256=$digest; logon_success_records=$successCount}
}
# Bounded metadata digest and counts only; never XML, names, messages or raw rows.
$results | ConvertTo-Json -Compress
