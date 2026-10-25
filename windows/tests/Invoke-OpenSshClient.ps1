#Requires -Version 5.1
# Separate process proves an operator can resume after the previous client exits.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceFile,
    [Parameter(Mandatory=$true)][string]$IdentityFile,
    [Parameter(Mandatory=$true)][string]$HostAlias,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][string]$ResultPath,
    [string]$Token,
    [int]$Retries = 2,
    [switch]$Legacy
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'This fixture runs only on a disposable GitHub-hosted runner.'
}
try {
    $client = Join-Path $PSScriptRoot '..\Send-RockyEvidenceResume.ps1'
    $arguments = @{
        Path = $SourceFile; KeyPath = $IdentityFile; RemoteHost = $HostAlias
        RemoteUser = 'engci'; RemoteInstallDir = '/opt/rocky-ssh-ci'
        DestinationName = $Destination
    }
    if ($Legacy) { $client = Join-Path $PSScriptRoot '..\Send-RockyEvidence.ps1' }
    else {
        $arguments.MaxRetries = $Retries
        $arguments.AppendTimeoutSeconds = 60
        if ($Token) { $arguments.ResumeToken = $Token }
    }
    $result = & $client @arguments
    $envelope = @{ process_id = $PID; result = $result } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($ResultPath, $envelope, (New-Object Text.UTF8Encoding $false))
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
