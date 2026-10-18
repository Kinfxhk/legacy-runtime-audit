# Build script for legacy-runtime-audit.
# Runs the assert-based test suite in the current host, then packages the
# scanner + docs into dist/legacy-runtime-audit-v1.0.0.zip.
# Invoked by CI under both `pwsh` and `powershell` (no dotnet required).

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root  = $PSScriptRoot
$tests = Join-Path $root 'tests\Audit.Tests.ps1'
$dist  = Join-Path $root 'dist'
$zip   = Join-Path $dist 'legacy-runtime-audit-v1.0.0.zip'

Write-Host "Running tests under PowerShell $($PSVersionTable.PSVersion) ..." -ForegroundColor Cyan
try {
  & $tests
}
catch {
  Write-Host "BUILD FAILED: $_" -ForegroundColor Red
  exit 1
}

Write-Host "Packaging $zip ..." -ForegroundColor Cyan
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Path $dist -Force | Out-Null

$payload = @(
  (Join-Path $root 'src\Invoke-LegacyRuntimeAudit.ps1'),
  (Join-Path $root 'README.md'),
  (Join-Path $root 'LICENSE'),
  (Join-Path $root 'THIRD-PARTY-NOTICES.md')
)
foreach ($f in $payload) {
  if (-not (Test-Path $f)) { throw "Missing required file: $f" }
  Copy-Item -Path $f -Destination $dist -Force
}

Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip -Force
if (-not (Test-Path $zip)) { throw "Zip was not created: $zip" }

$size = (Get-Item $zip).Length
Write-Host "OK: $zip ($size bytes)" -ForegroundColor Green
exit 0
