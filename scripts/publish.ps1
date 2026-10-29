<#
.SYNOPSIS
  Builds everything and assembles the portable folder .\dist: copy it anywhere and run TunnelPick.exe.

.DESCRIPTION
  dist\TunnelPick.exe           the WPF app (single file, framework-dependent: needs the .NET 10 Desktop Runtime)
  dist\engine\...               the engine executable plus WinDivert.dll / WinDivert64.sys
  dist\data\                    created at run time: configs, rules, logs, the Chrome VPN profile

  The two executables are Authenticode-signed with the Hoshizora code-signing
  certificate by running the signing script (WSL + signtool). The script is taken from
  $env:TUNNELPICK_SIGN_SCRIPT, else from the Hoshizora certificate folder. Without it the package is
  built unsigned; -SkipSign does that on purpose.
#>
param([switch]$SkipSign)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'

& (Join-Path $PSScriptRoot 'build-engine.ps1')

# The build output is replaced; dist\data (configs, rules, the Chrome VPN profile) belongs to the user and stays.
if (Test-Path $dist) { Get-ChildItem $dist -Force | Where-Object Name -ne 'data' | Remove-Item -Recurse -Force }
New-Item -ItemType Directory -Force (Join-Path $dist 'engine') | Out-Null

# Properties\PublishProfiles\win-x64.pubxml: Release, win-x64, framework-dependent, single file, output to dist.
dotnet publish (Join-Path $root 'src\TunnelPick.App\TunnelPick.App.csproj') -p:PublishProfile=win-x64
if ($LASTEXITCODE) { throw 'dotnet publish failed' }
# Symbols are embedded in TunnelPick.exe; the referenced library's loose .pdb is not needed.
Remove-Item (Join-Path $dist '*.pdb') -Force

$bin = Join-Path $root 'engine\bin'
foreach ($f in 'tunnelpick-engine.exe', 'WinDivert.dll', 'WinDivert64.sys') {
  Copy-Item (Join-Path $bin $f) (Join-Path $dist 'engine') -Force
}
Copy-Item (Join-Path $root 'third_party\windivert\pkg\WinDivert-2.2.2-A\LICENSE') (Join-Path $dist 'engine\WinDivert-LICENSE.txt') -Force

$signScript = if ($env:TUNNELPICK_SIGN_SCRIPT) { $env:TUNNELPICK_SIGN_SCRIPT } else { 'F:\OneDrive\Guidelines\Certificates\codesign\tunnelpick-codesign.sh' }
if ($SkipSign) {
  Write-Host 'Signing skipped: the package is unsigned.'
} elseif (-not (Test-Path $signScript)) {
  Write-Warning "Signing script not found ($signScript): the package is unsigned."
} else {
  # The script is a bash script run in WSL, which maps the Windows path itself.
  $wslPath = (wsl -d Ubuntu wslpath -u ($signScript.Replace([char]92, '/'))).Trim()
  wsl -d Ubuntu $wslPath
  if ($LASTEXITCODE) { throw 'signing failed' }
}
Write-Host "Package ready in $dist"
