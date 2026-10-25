#Requires -Version 5.1
# Local process fixture only. Compiled transport traps never authenticate or use a network.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:RUNNER_TEMP) { throw 'Set RUNNER_TEMP to an approved private fixture directory.' }
$base = (Resolve-Path -LiteralPath $env:RUNNER_TEMP).Path
$work = Join-Path $base ('EndpointContract-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $work)
$bin = Join-Path $work 'bin'
[void](New-Item -ItemType Directory -Path $bin)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ok = $false
try {
  $trap = @'
using System;
using System.IO;
public class EndpointTransportTrap {
  public static int Main(string[] args) {
    File.AppendAllText(Environment.GetEnvironmentVariable("MCP_ENDPOINT_EVENTS"), string.Join("\n", args)+"\n");
    return 70; // stop before any protocol/state operation; no sockets or network API
  }
}
'@
  $ssh = Join-Path $bin 'ssh.exe'
  Add-Type -TypeDefinition $trap -OutputAssembly $ssh -OutputType ConsoleApplication
  [IO.File]::Copy($ssh, (Join-Path $bin 'scp.exe'))
  $sample = Join-Path $work 'synthetic-input.bin'
  $key = Join-Path $work 'synthetic-identity.txt'
  [IO.File]::WriteAllBytes($sample,[byte[]]@(0,1,10,13,255))
  [IO.File]::WriteAllText($key,'synthetic fixture text, not a credential')
  $events = Join-Path $work 'transport-events.txt'
  $request = Join-Path $work 'request.json'
  $child = @'
$ErrorActionPreference='Stop'
$j=Get-Content -LiteralPath $env:MCP_ENDPOINT_REQUEST -Raw | ConvertFrom-Json
$p=@{}
foreach ($field in $j.parameters.PSObject.Properties) { $p[$field.Name]=$field.Value }
& $j.client @p
'@
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
  $results = @()
  foreach ($name in @('Send-RockyEvidence.ps1','Send-RockyEvidenceResume.ps1')) {
    $client = Join-Path (Join-Path $repo 'windows') $name
    $cases = @(
      @{id='missing-host'; user='engtest'},
      @{id='missing-user'; host='analysis.example'},
      @{id='missing-both'},
      @{id='empty-host'; host=''; user='engtest'},
      @{id='space-host'; host=' '; user='engtest'},
      @{id='malformed-host'; host='badhost;invalid'; user='engtest'},
      @{id='empty-user'; host='analysis.example'; user=''},
      @{id='space-user'; host='analysis.example'; user=' '},
      @{id='malformed-user'; host='analysis.example'; user='baduser;invalid'},
      @{id='bad-install'; host='analysis.example'; user='engtest'; install='/bad;invalid'},
      @{id='canonical-default'; host='analysis.example'; user='engtest'; expected='/opt/rocky-eng/transfer_bridge.py'},
      @{id='explicit-override'; host='analysis.example'; user='engtest'; install='/opt/example-gateway'; expected='/opt/example-gateway/transfer_bridge.py'}
    )
    foreach ($case in $cases) {
      if (Test-Path -LiteralPath $events) { Remove-Item -LiteralPath $events }
      $parameters=@{Path=$sample;KeyPath=$key;DestinationName='synthetic.bin'}
      if ($case.ContainsKey('host')) { $parameters.RemoteHost=$case.host }
      if ($case.ContainsKey('user')) { $parameters.RemoteUser=$case.user }
      if ($case.ContainsKey('install')) { $parameters.RemoteInstallDir=$case.install }
      if ($name -eq 'Send-RockyEvidenceResume.ps1') { $parameters.MaxRetries=0 }
      @{client=$client;parameters=$parameters} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $request -Encoding UTF8
      $info=New-Object Diagnostics.ProcessStartInfo
      $info.FileName=Join-Path $PSHOME 'powershell.exe'
      $info.Arguments='-NoProfile -NonInteractive -EncodedCommand '+$encoded
      $info.UseShellExecute=$false
      $info.CreateNoWindow=$true
      $info.RedirectStandardOutput=$true
      $info.RedirectStandardError=$true
      $info.EnvironmentVariables['PATH']=$bin+';'+$env:PATH
      $info.EnvironmentVariables['MCP_ENDPOINT_REQUEST']=$request
      $info.EnvironmentVariables['MCP_ENDPOINT_EVENTS']=$events
      $process=New-Object Diagnostics.Process
      $process.StartInfo=$info
      [void]$process.Start()
      $stdout=$process.StandardOutput.ReadToEndAsync()
      $stderr=$process.StandardError.ReadToEndAsync()
      if (-not $process.WaitForExit(20000)) { $process.Kill(); throw 'Synthetic controller process exceeded bounded timeout.' }
      $exit=$process.ExitCode
      [void]$stdout.Result
      [void]$stderr.Result
      $process.Dispose()
      if ($exit -eq 0) { throw ($name+': unexpected success for '+$case.id) }
      $invoked=Test-Path -LiteralPath $events
      if ($case.ContainsKey('expected')) {
        if (-not $invoked -or -not (@(Get-Content -LiteralPath $events) -contains $case.expected)) {
          throw ($name+': incorrect installed helper path for '+$case.id)
        }
      } elseif ($invoked) { throw ($name+': invalid/missing endpoint invoked transport for '+$case.id) }
      $results+=@{client=$name;case=$case.id;exit=$exit;transport_trap_invoked=$invoked;status='PASS'}
    }
  }
  if ($results.Count -ne 24) { throw 'Expected all24 endpoint contract cases.' }
  @{status='PASS';cases=$results.Count;actual_network_calls=0;results=$results} | ConvertTo-Json -Depth 5 -Compress
  $ok=$true
} finally {
  # Delete only this fixture's checked, newly created child of the explicit private base.
  $resolved=[IO.Path]::GetFullPath($work)
  $prefix=[IO.Path]::GetFullPath($base).TrimEnd('\')+'\'
  if ($ok -and $resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'EndpointContract-*') {
    Remove-Item -LiteralPath $resolved -Recurse -Force
  } else { Write-Warning ('Retained fixture evidence: '+$resolved) }
}
