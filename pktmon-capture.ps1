param(
    [ValidateSet('start', 'stop', 'status')]
    [string]$Action = 'status',
    [int]$Port = 80,
    [string]$IpAddress = '',
    [string]$OutputDirectory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$statePath = Join-Path $OutputDirectory 'pktmon-capture.state.json'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This action requires an elevated PowerShell window.'
    }
}

function Invoke-Pktmon {
    param([string[]]$Arguments)
    & pktmon @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "pktmon failed with exit code $LASTEXITCODE"
    }
}

if ($Action -eq 'status') {
    & pktmon status
    exit $LASTEXITCODE
}

Assert-Administrator

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "Output directory does not exist: $OutputDirectory"
}

if ($Action -eq 'start') {
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        throw "A capture state file already exists: $statePath"
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $etlPath = Join-Path $OutputDirectory "nc-$stamp.etl"
    $pcapPath = Join-Path $OutputDirectory "nc-$stamp.pcapng"
    $filterArguments = @('filter', 'add', "NC-TCP-$Port")
    if ($IpAddress) {
        $filterArguments += @('-i', $IpAddress)
    }
    $filterArguments += @('-t', 'TCP', '-p', "$Port")

    Invoke-Pktmon @('filter', 'remove')
    Invoke-Pktmon $filterArguments
    Invoke-Pktmon @('start', '--capture', '--pkt-size', '0', '--file-name', $etlPath, '--file-size', '1024', '--log-mode', 'circular')

    [pscustomobject]@{
        Port = $Port
        IpAddress = $IpAddress
        EtlPath = $etlPath
        PcapPath = $pcapPath
        StartedAt = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding ASCII

    Write-Output "Capture started: TCP port $Port"
    Write-Output "ETL: $etlPath"
    Write-Output "Stop with: .\pktmon-capture.ps1 -Action stop"
    exit 0
}

if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "No capture state file found: $statePath"
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
Invoke-Pktmon @('stop')
Invoke-Pktmon @('etl2pcap', $state.EtlPath, '--out', $state.PcapPath)
Invoke-Pktmon @('filter', 'remove')
Remove-Item -LiteralPath $statePath -Force

Write-Output "Capture stopped. PCAPNG: $($state.PcapPath)"
