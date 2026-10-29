<#
.SYNOPSIS
  Downloads WinDivert 2.2.2 (LGPL-3.0 or GPL-2.0) and copies the x64 DLL and driver to -Destination.

.DESCRIPTION
  The archive is cached in third_party\windivert and never committed. The expected SHA-256 pins the
  official v2.2.2 release asset. Windows Defender reports this archive as potentially unwanted
  software on some machines; the script does not work around that, it stops and says so.
#>
param([Parameter(Mandatory)][string]$Destination)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$cache = Join-Path $root 'third_party\windivert'
$zip = Join-Path $cache 'WinDivert-2.2.2-A.zip'
$pkg = Join-Path $cache 'pkg'
$sha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
$url = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'

$x64 = Join-Path $pkg 'WinDivert-2.2.2-A\x64'
if (-not (Test-Path (Join-Path $x64 'WinDivert64.sys'))) {
  New-Item -ItemType Directory -Force $cache | Out-Null
  if (-not (Test-Path $zip)) { Invoke-WebRequest $url -OutFile $zip }
  try { $actual = (Get-FileHash $zip -Algorithm SHA256).Hash } catch {
    throw "Cannot read $zip. Windows Defender probably quarantined it. Add a Defender exclusion for '$cache' and run again."
  }
  if ($actual -ne $sha256) { Remove-Item $zip; throw "WinDivert archive hash mismatch: $actual" }
  Expand-Archive $zip -DestinationPath $pkg -Force
}
New-Item -ItemType Directory -Force $Destination | Out-Null
foreach ($name in 'WinDivert.dll', 'WinDivert64.sys') {
  $src = Join-Path $x64 $name
  $dst = Join-Path $Destination $name
  # A loaded driver keeps its .sys locked, so an identical file is left alone.
  if ((Test-Path $dst) -and ((Get-FileHash $src).Hash -eq (Get-FileHash $dst).Hash)) { continue }
  Copy-Item $src $dst -Force
}
$sig = Get-AuthenticodeSignature (Join-Path $Destination 'WinDivert64.sys')
if ($sig.Status -ne 'Valid') { throw "WinDivert64.sys signature is $($sig.Status)" }
