<#
.SYNOPSIS
  Runs the per-process redirection integration test (needs one UAC approval).

.DESCRIPTION
  Builds the engine and test tools, starts tp-itest elevated, and plays the role of the normal-user
  side for the Chrome check: Chrome relaunches itself de-elevated, so the browsers must be started by
  a non-elevated process. Output goes to engine\bin\itest.out.txt.
#>
param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$engine = Join-Path $root 'engine'
$bin = Join-Path $engine 'bin'

if (-not $SkipBuild) { & (Join-Path $PSScriptRoot 'build-engine.ps1') }

$sync = Join-Path ([IO.Path]::GetTempPath()) ("tp-sync-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $sync | Out-Null
$out = Join-Path $bin 'itest.out.txt'
Remove-Item $out -ErrorAction SilentlyContinue

Start-Process -FilePath cmd.exe -Verb RunAs -WindowStyle Hidden `
  -ArgumentList "/c cd /d `"$bin`" && tp-itest.exe --sync-dir `"$sync`" > itest.out.txt 2>&1 & netsh advfirewall firewall delete rule name=tp-itest > nul 2>&1"

$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$deadline = (Get-Date).AddMinutes(8)
$chromeHandled = $false
while (-not (Test-Path (Join-Path $sync 'itest.finished'))) {
  if ((Get-Date) -gt $deadline) { Write-Error 'integration test did not finish in time'; break }
  $ready = Join-Path $sync 'chrome.ready'
  if (-not $chromeHandled -and (Test-Path $ready)) {
    $chromeHandled = $true
    $entries = (Get-Content $ready) | Where-Object { $_ } | ForEach-Object {
      $tag, $profile, $url = $_.Split('|')
      [pscustomobject]@{ Tag = $tag; Profile = $profile; Url = $url }
    }
    $procs = foreach ($e in $entries) {
      Start-Process -FilePath $chrome -PassThru -ArgumentList @(
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        "--user-data-dir=$($e.Profile)", '--virtual-time-budget=10000', '--dump-dom', $e.Url)
    }
    $procs | ForEach-Object { $_.WaitForExit(45000) | Out-Null }
    # Stop only the browsers this run started: they are identified by their profile directories.
    Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | Where-Object {
      $cmd = $_.CommandLine
      $entries | Where-Object { $cmd -like "*$($_.Profile)*" }
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Set-Content (Join-Path $sync 'chrome.done') 'done'
  }
  Start-Sleep -Milliseconds 300
}

Get-Content $out
$code = [int](Get-Content (Join-Path $sync 'itest.finished') -ErrorAction SilentlyContinue)
Remove-Item $sync -Recurse -Force -ErrorAction SilentlyContinue
exit $code
