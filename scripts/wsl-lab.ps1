param(
    [ValidateSet('Bootstrap', 'Build', 'Test', 'Doctor', 'Run', 'Suite', 'Status', 'Down')]
    [string]$Action = 'Doctor',
    [string]$Distro = 'PNID-Lab',
    [ValidateSet('route-withdrawal', 'route-policy', 'firewall-drop', 'dns-failure', 'backend-down', 'link-loss', 'packet-loss', 'gateway-overload')]
    [string]$Scenario = 'route-withdrawal',
    [string]$Output = ('results/wsl-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
)
$ErrorActionPreference = 'Stop'
$projectDirectory = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$distributionText = (& wsl.exe --list --quiet | Out-String).Replace([char]0, '')
if ($LASTEXITCODE -ne 0 -or -not ($distributionText -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq $Distro })) {
    throw "The dedicated $Distro distribution must exist. See README Windows setup."
}
$linuxArguments = switch ($Action) {
    'Bootstrap' { @('bash', 'scripts/bootstrap-linux.sh') }
    'Build' { @('go', 'build', '-trimpath', '-o', 'bin/netlab-agent', './cmd/netlab-agent') }
    'Test' { @('make', 'test') }
    'Doctor' { @('python3', '-m', 'netlab', 'doctor') }
    'Run' { @('python3', '-m', 'netlab', 'run', '--scenario', $Scenario, '--output', $Output) }
    'Suite' { @('python3', '-m', 'netlab', 'suite', '--output', $Output) }
    'Status' { @('python3', '-m', 'netlab', 'status') }
    'Down' { @('python3', '-m', 'netlab', 'down') }
}
& wsl.exe -d $Distro -u root --cd $projectDirectory --exec @linuxArguments
exit $LASTEXITCODE
