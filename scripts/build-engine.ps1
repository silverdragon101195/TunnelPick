<#
.SYNOPSIS
  Builds the Go engine and test tools into engine\bin and stages WinDivert next to them.

.DESCRIPTION
  Go is taken from PATH, or from $env:TUNNELPICK_GO, or from %USERPROFILE%\tools\go-*\go\bin.
  WinDivert is downloaded once into third_party\windivert (excluded from git). Windows Defender
  may flag the WinDivert archive; add an exclusion for that folder before the first run.
#>
param([switch]$SkipWinDivert)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$engine = Join-Path $root 'engine'
$bin = Join-Path $engine 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  $cand = @($env:TUNNELPICK_GO) + (Get-ChildItem "$env:USERPROFILE\tools\go-*\go\bin" -ErrorAction SilentlyContinue | ForEach-Object FullName)
  $dir = $cand | Where-Object { $_ -and (Test-Path (Join-Path $_ 'go.exe')) } | Select-Object -First 1
  if (-not $dir) { throw 'Go toolchain not found. Install Go 1.27+ or set TUNNELPICK_GO to its bin folder.' }
  $env:Path = "$dir;$env:Path"
}

if (-not $SkipWinDivert) { & (Join-Path $PSScriptRoot 'get-windivert.ps1') -Destination $bin }

Push-Location $engine
try {
  go vet ./...
  if ($LASTEXITCODE) { throw 'go vet failed' }
  foreach ($tool in 'tunnelpick-engine', 'tp-probe', 'tp-itest', 'wdprobe') {
    go build -trimpath -o (Join-Path $bin "$tool.exe") "./cmd/$tool"
    if ($LASTEXITCODE) { throw "build of $tool failed" }
  }
} finally { Pop-Location }
Write-Host "Engine built into $bin"
