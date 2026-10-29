<#
.SYNOPSIS
  End-to-end test of the portable package: run it from a copy of dist in a temp folder, use the engine as a
  normal user over the pipe, shut it down, and check nothing is left behind. One UAC approval.

.DESCRIPTION
  A loopback WireGuard gateway (tp-itest --gateway-only) plays the VPN server, so no real server is needed.
  One elevated helper starts the engine the way TunnelPick.exe does (elevated, --parent-pid); everything else
  runs as the normal user, like the UI does. The run ends with the helper deleting the "tp-itest" firewall
  rules Windows creates by itself for the test gateway.
#>
param([switch]$SkipPublish)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'engine\bin'
$failures = 0
function Check($name, [bool]$ok, $detail = '') {
  $script:failures += [int](-not $ok)
  Write-Host ("[{0}] {1} - {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail)
}

if (-not $SkipPublish) { & (Join-Path $PSScriptRoot 'publish.ps1') -SkipSign | Out-Null }

$work = Join-Path ([IO.Path]::GetTempPath()) ('tp-e2e-' + [guid]::NewGuid().ToString('N'))
$app = Join-Path $work 'app'
New-Item -ItemType Directory $work | Out-Null
Copy-Item (Join-Path $root 'dist') $app -Recurse
# The copy must start without the data of whoever uses dist: the test checks that only it creates data\.
Remove-Item (Join-Path $app 'data') -Recurse -Force -ErrorAction SilentlyContinue
$engineExe = Join-Path $app 'engine\tunnelpick-engine.exe'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ruleName = 'TunnelPick engine relay'

function Get-Tree { (Get-ChildItem $app -Recurse -Force | ForEach-Object { $_.FullName.Substring($app.Length + 1) } | Sort-Object) }

# Snapshot of what must be identical before the first start and after the last stop.
function Get-SystemState {
  [pscustomobject]@{
    Routes   = (Get-NetRoute | ForEach-Object { "$($_.DestinationPrefix)>$($_.NextHop)@$($_.InterfaceIndex)" } | Sort-Object) -join ';'
    Dns      = (Get-DnsClientServerAddress | ForEach-Object { "$($_.InterfaceIndex):" + ($_.ServerAddresses -join ',') } | Sort-Object) -join ';'
    # Windows creates Allow rules named tp-itest by itself when the test gateway starts listening.
    Fw       = (Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -ne 'tp-itest' } | Measure-Object).Count
    Services = (Get-Service TunnelPick, WinDivert -ErrorAction SilentlyContinue | Measure-Object).Count
    Folders  = @("$env:ProgramFiles\TunnelPick", "$env:ProgramData\TunnelPick", "$env:LOCALAPPDATA\TunnelPick" | Where-Object { Test-Path $_ }).Count
  }
}
$before = Get-SystemState
$treeBefore = @(Get-Tree)

# ---- elevated helper -------------------------------------------------------------------------
@'
param($Work, $App, $Sid)
$ErrorActionPreference = 'Continue'
Start-Transcript (Join-Path $Work 'helper.log') | Out-Null
$engineExe = Join-Path $App 'engine\tunnelpick-engine.exe'
Set-Content (Join-Path $Work 'helper.ready') 'ready'
$done = $false
while (-not $done) {
  $cmdFile = Join-Path $Work 'cmd.txt'
  if (Test-Path $cmdFile) {
    $cmd = (Get-Content $cmdFile -Raw).Trim(); Remove-Item $cmdFile
    try {
      switch ($cmd) {
        'start' {
          $parentPid = (Get-Content (Join-Path $Work 'parent.pid')).Trim()
          $p = Start-Process $engineExe -PassThru -WindowStyle Hidden -ArgumentList @(
            'run', '--allow-sid', $Sid, '--data-dir', "`"$App\data\engine`"", '--parent-pid', $parentPid)
          Set-Content (Join-Path $Work 'engine.pid') $p.Id
        }
        'cleanup' { Remove-NetFirewallRule -DisplayName tp-itest -ErrorAction SilentlyContinue; $done = $true }
      }
    } catch { Write-Host "helper command '$cmd' failed: $_" }
    Set-Content (Join-Path $Work 'cmd.done') $cmd
  }
  Start-Sleep -Milliseconds 200
}
Stop-Transcript | Out-Null
'@ | Set-Content (Join-Path $work 'helper.ps1') -Encoding utf8

function Send-Admin($cmd) {
  Remove-Item (Join-Path $work 'cmd.done') -ErrorAction SilentlyContinue
  Set-Content (Join-Path $work 'cmd.txt') $cmd
  for ($i = 0; $i -lt 300 -and -not (Test-Path (Join-Path $work 'cmd.done')); $i++) { Start-Sleep -Milliseconds 200 }
}

function Invoke-Engine($cmd, $params = $null) {
  $c = New-Object IO.Pipes.NamedPipeClientStream '.', 'TunnelPick', 'InOut'
  try {
    $c.Connect(3000)
    $w = New-Object IO.StreamWriter($c); $w.AutoFlush = $true
    $r = New-Object IO.StreamReader($c)
    $req = @{ id = 1; cmd = $cmd }
    if ($null -ne $params) { $req.params = $params }
    $w.WriteLine(($req | ConvertTo-Json -Depth 10 -Compress))
    return ($r.ReadLine() | ConvertFrom-Json)
  } finally { $c.Dispose() }
}

function Wait-Engine($seconds = 20) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $seconds) {
    try { if ((Invoke-Engine 'ping').ok) { return $sw.Elapsed.TotalSeconds } } catch { }
    Start-Sleep -Milliseconds 100
  }
  return $null
}

function Wait-State($state, $seconds = 20) {
  for ($i = 0; $i -lt $seconds * 5; $i++) {
    if ((Invoke-Engine 'status').data.state -eq $state) { return $true }
    Start-Sleep -Milliseconds 200
  }
  return $false
}

# True once the engine process is gone (its pid was written by the helper).
function Wait-EngineGone($seconds = 15) {
  $enginePid = [int](Get-Content (Join-Path $work 'engine.pid'))
  for ($i = 0; $i -lt $seconds * 5; $i++) {
    if (-not (Get-Process -Id $enginePid -ErrorAction SilentlyContinue)) { return $true }
    Start-Sleep -Milliseconds 200
  }
  return $false
}

function Get-RelayRule { Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue }

function New-Parent {
  $p = Start-Process powershell -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 900' -WindowStyle Hidden -PassThru
  Set-Content (Join-Path $work 'parent.pid') $p.Id
  return $p
}

function Invoke-Probe($exe, [string[]]$action, $ruleFor = $null) {
  $goFile = Join-Path $work ([guid]::NewGuid().ToString('N'))
  $p = Start-Process (Join-Path $bin $exe) -ArgumentList (@('--go', $goFile) + $action) -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$goFile.out"
  if ($ruleFor -eq 'instance') {
    $created = $p.StartTime.ToUniversalTime().ToFileTimeUtc()
    $set = @{ bypassLan = $false; rules = @(@{ id = 'e2e'; kind = 'instance'; pid = $p.Id; created = $created; children = $false; enabled = $true }) }
    $r = Invoke-Engine 'setPolicy' $set
    if (-not $r.ok) { return "policy rejected: $($r.error)" }
  }
  Set-Content $goFile 'go'
  if (-not $p.WaitForExit(30000)) { $p.Kill(); return 'FAIL timeout' }
  return (Get-Content "$goFile.out" -Raw).Trim()
}

# ---- gateway + helper ---------------------------------------------------------------------------
$gwFile = Join-Path $work 'gw.json'
$gw = Start-Process (Join-Path $bin 'tp-itest.exe') -ArgumentList @('--gateway-only', $gwFile) -PassThru -WindowStyle Hidden
for ($i = 0; $i -lt 50 -and -not (Test-Path $gwFile); $i++) { Start-Sleep -Milliseconds 100 }
$gwConfig = Get-Content $gwFile -Raw | ConvertFrom-Json

$parent1 = New-Parent
Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList `
  "-NoProfile -ExecutionPolicy Bypass -File `"$work\helper.ps1`" -Work `"$work`" -App `"$app`" -Sid $sid"
for ($i = 0; $i -lt 600 -and -not (Test-Path (Join-Path $work 'helper.ready')); $i++) { Start-Sleep -Milliseconds 200 }
Check 'helper elevated' (Test-Path (Join-Path $work 'helper.ready')) ''

# ---- first run ------------------------------------------------------------------------------------
Send-Admin 'start'
$t = Wait-Engine
Check 'start: engine answers a normal (non-elevated) user' ($null -ne $t) $(if ($t) { "{0:N1} s" -f $t } else { 'never answered' })

$relay = Get-RelayRule
$relayApp = $relay | Get-NetFirewallApplicationFilter
$relayPort = $relay | Get-NetFirewallPortFilter
$relayAddr = $relay | Get-NetFirewallAddressFilter
Check 'start: exactly one narrow inbound firewall rule (this engine exe, TCP, LocalSubnet)' (@($relay).Count -eq 1 -and $relay.Direction -eq 'Inbound' -and $relay.Action -eq 'Allow' `
  -and $relayApp.Program -eq $engineExe -and $relayPort.Protocol -eq 'TCP' -and $relayAddr.RemoteAddress -eq 'LocalSubnet') ''

$aclPipe = New-Object IO.Pipes.NamedPipeClientStream '.', 'TunnelPick', 'InOut'
$aclPipe.Connect(3000)
$acl = $aclPipe.GetAccessControl().GetAccessRules($true, $true, [Security.Principal.NTAccount]) | ForEach-Object { $_.IdentityReference.Value }
$aclPipe.Dispose()
Write-Host "[info] pipe ACL: $($acl -join ', ')"
Check 'pipe ACL grants only SYSTEM, Administrators and the starting user' (@($acl | Where-Object { $_ -notmatch 'SYSTEM|Administrators|\\' + [regex]::Escape($env:USERNAME) + '$' }).Count -eq 0) ''

$cfg = @{ privateKey = $gwConfig.privateKey; addresses = @($gwConfig.addresses); dns = @($gwConfig.dns); mtu = 0
          peers = @($gwConfig.peers | ForEach-Object { @{ publicKey = $_.publicKey; endpoint = $_.endpoint; allowedIps = @($_.allowedIps); persistentKeepalive = $_.persistentKeepalive } }) }
$r = Invoke-Engine 'connect' $cfg
Check 'connect over the pipe' $r.ok "$($r.error)"
Check 'tunnel handshake' (Wait-State 'connected') ''

$url = 'http://10.99.0.1/'
$a = Invoke-Probe 'tp-probe.exe' @('http', $url) 'instance'
$b = Invoke-Probe 'tp-probe-control.exe' @('http', $url)
Check 'selected instance reaches the VPN-only server' ($a -like 'OK VPN-SIDE*') $a
Check 'unselected process does not' ($b -like 'FAIL*') $b

if ($a -notlike 'OK VPN-SIDE*') {
  Write-Host '[diag] engine status and log after the failed selected request:'
  Write-Host ((Invoke-Engine 'status').data | ConvertTo-Json -Depth 6 -Compress)
  (Invoke-Engine 'logs' @{ n = 40 }).data | ForEach-Object { Write-Host "[diag] $_" }
}

$dataDir = Join-Path $app 'data\engine'
Check 'policy and log are written under the app folder' ((Test-Path (Join-Path $dataDir 'policy.json')) -and (Test-Path (Join-Path $dataDir 'engine.log'))) ''
Check 'no key material in the policy or engine log' (-not ((Get-Content (Join-Path $dataDir 'policy.json'), (Join-Path $dataDir 'engine.log') -Raw) -match [regex]::Escape($gwConfig.privateKey))) ''

# ---- tunnel down: the kill switch must hold ------------------------------------------------------
$exeSet = @{ bypassLan = $false; rules = @(@{ id = 'e2e-exe'; kind = 'executable'; path = (Join-Path $bin 'tp-probe.exe'); children = $false; enabled = $true }) }
[void](Invoke-Engine 'setPolicy' $exeSet)
[void](Invoke-Engine 'disconnect')
$a = Invoke-Probe 'tp-probe.exe' @('http', $url)
Check 'tunnel down: selected exe is blocked, not sent direct' ($a -like 'FAIL*') $a
[void](Invoke-Engine 'connect' $cfg)
Wait-State 'connected' | Out-Null
$a = Invoke-Probe 'tp-probe.exe' @('http', $url)
Check 'reconnect restores access' ($a -like 'OK VPN-SIDE*') $a

# ---- shutdown command: nothing left -----------------------------------------------------------------
[void](Invoke-Engine 'shutdown')
Check 'shutdown: engine process exits' (Wait-EngineGone) ''
Check 'shutdown: firewall rule removed' ($null -eq (Get-RelayRule)) ''
Check 'shutdown: engine pipe is gone' (-not (Test-Path '\\.\pipe\TunnelPick')) ''
$driverGone = $false
for ($i = 0; $i -lt 25 -and -not $driverGone; $i++) { $driverGone = $null -eq (Get-Service WinDivert -ErrorAction SilentlyContinue); if (-not $driverGone) { Start-Sleep -Milliseconds 200 } }
Check 'shutdown: WinDivert driver service is gone' $driverGone ''
$a = Invoke-Probe 'tp-probe.exe' @('http', $url)
Check 'shutdown: no redirection remains (the selected exe is no longer special)' ($a -like 'FAIL*') $a

# ---- parent exit: the engine follows the app -------------------------------------------------------------
Stop-Process -Id $parent1.Id -Force -ErrorAction SilentlyContinue
$parent2 = New-Parent
Send-Admin 'start'
Check 'second start works after a clean shutdown' ($null -ne (Wait-Engine)) ''
Check 'second start: firewall rule is back, once' (@(Get-RelayRule).Count -eq 1) ''
Stop-Process -Id $parent2.Id -Force
Check 'parent exit: engine ends by itself' (Wait-EngineGone 20) ''
Check 'parent exit: firewall rule removed' ($null -eq (Get-RelayRule)) ''
$driverGone = $false
for ($i = 0; $i -lt 25 -and -not $driverGone; $i++) { $driverGone = $null -eq (Get-Service WinDivert -ErrorAction SilentlyContinue); if (-not $driverGone) { Start-Sleep -Milliseconds 200 } }
Check 'parent exit: WinDivert driver service is gone' $driverGone ''

# ---- final accounting -----------------------------------------------------------------------------------------
Send-Admin 'cleanup'
Start-Sleep -Seconds 1
$after = Get-SystemState
$treeNew = @(Get-Tree | Where-Object { $treeBefore -notcontains $_ -and $_ -ne 'data' -and $_ -notlike 'data\*' })
Check 'only the data folder was created inside the app folder' ($treeNew.Count -eq 0) ($treeNew -join ', ')
Check 'no service, Program Files, ProgramData or LocalAppData entry exists' ($after.Services -eq 0 -and $after.Folders -eq 0) "services=$($after.Services) folders=$($after.Folders)"
Check 'system routes were never changed' ($before.Routes -eq $after.Routes) ''
Check 'system DNS settings were never changed' ($before.Dns -eq $after.Dns) ''
Check 'no firewall rule is left' ($before.Fw -eq $after.Fw -and $null -eq (Get-RelayRule) -and $null -eq (Get-NetFirewallRule -DisplayName tp-itest -ErrorAction SilentlyContinue)) "$($before.Fw) -> $($after.Fw)"

Set-Content "$gwFile.stop" 'stop'
Start-Sleep -Milliseconds 500
if (-not $gw.HasExited) { $gw.Kill() }
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue

if ($failures) { Write-Host "`n$failures CHECK(S) FAILED"; exit 1 }
Write-Host "`nALL CHECKS PASSED"
