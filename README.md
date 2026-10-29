# TunnelPick

A Windows desktop app that sends the traffic of **selected processes** through a WireGuard server and leaves
every other process on the normal network.

* Import a WireGuard `.conf` directly. No WireGuard for Windows needed; existing tunnels are never touched.
* Pick running processes (one instance, or every instance of an executable, optionally with child processes).
* "Open Chrome via VPN" starts a separate Chrome with its own data folder, routed through the VPN, while your
  everyday Chrome keeps the normal network.
* Per-process kill switch: if the tunnel drops, selected processes are blocked, never sent directly.
* TCP, UDP (QUIC, STUN/WebRTC) and DNS go through the tunnel. IPv6 from selected processes is blocked.

How it works and why: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

* Windows 10/11 x64. TunnelPick is portable: nothing is installed. It asks for administrator rights (UAC) each
  time you open it, because the packet driver cannot be loaded without them.
* .NET 10 SDK to build, .NET 10 Desktop Runtime to run the UI.
* Go 1.27+ to build the engine (the scripts also find a portable Go in `%USERPROFILE%\tools\go-*`).
* Windows Defender may flag the WinDivert download. Add an exclusion for `third_party\windivert` (only that
  folder) before the first build. TunnelPick never disables or works around Defender.
* A normal build and run does **not** need test signing or any protection turned off: the WinDivert driver is
  pre-signed. It loads with Memory Integrity (HVCI) on (checked on Windows 11 build 26300).

## Build

```powershell
.\publish.bat                # builds engine + UI into .\dist, 0 warnings expected, then signs it
.\publish.bat -SkipSign      # same, without signing (or run .\scripts\publish.ps1 directly)
dotnet test --project src\TunnelPick.Tests -c Release   # unit tests (run from src\)
cd engine; go test ./...      # engine unit tests
```

## Run

Copy the `dist` folder anywhere and start `TunnelPick.exe`. There is no installer and no uninstaller.

Opening the app shows the UAC prompt once (a signed build names the publisher). The app then starts
`engine\tunnelpick-engine.exe` as its own child, which inherits the elevation, so nothing more is asked. If the
engine does not start, the banner offers **Start engine**. The engine ends when you close the app.

1. **Import .conf** (one or several files at once) or **Paste config…** (paste the text of a config; a config you just
   copied is filled in for you, and you give it a name). Unsupported fields are listed and you decide whether to
   import. Every config appears in the list; press **Activate** on the one to use (the first import is active
   already). Activating another config while connected reconnects with it.
2. **Connect** uses the active config. The banner shows the handshake age, bytes sent and received and what is
   being enforced.
3. Tick applications in the list: one row per executable, with the number of its running processes (a browser with a
   dozen processes is one row). Choose first whether a tick means *its running processes only* (one rule per process
   running now) or *every process of the executable, including later launches* (one rule), and whether children are
   included. Rules are listed on the right and survive restarts.
4. **Open Chrome via VPN** for a browser that is always on the VPN. **Check IP** shows the address the VPN server
   presents next to your normal address.

Closing the window stops the VPN and the redirection (the app asks first when selected processes are on the
VPN): selected processes use the normal network again.

## Leaving nothing behind

Everything the app stores is in the `data` folder next to `TunnelPick.exe`. To remove TunnelPick, close it and
delete the folder.

While the engine runs it has two things outside the folder, and it removes both when it ends:

* the `WinDivert` driver service that WinDivert registers on first use (the engine stops and deletes it);
* the firewall rule `TunnelPick engine relay`: inbound Allow, this engine executable only, TCP only, local subnet
  only. Without it Windows Firewall drops the packets the redirector hands to the engine's relay.

If the engine is killed instead of ending normally (Task Manager, power loss), the next start removes the rule it
left; the driver service is gone after a reboot or the next normal exit. No route, DNS setting, scheduled task or
registry key is ever created.

One thing stays on purpose: a build signed with the Hoshizora certificate adds the Hoshizora Root CA (embedded in
the exe) to the machine's Trusted Root Certification Authorities the first time it runs, so Windows can verify the
signature and the UAC prompt names the publisher. It is added once and skipped when already present; an unsigned
build never touches the certificate store. Other Hoshizora-signed software (SysLens) uses the same certificate, so
it is not removed with the folder; delete it in `certmgr.msc` if you want it gone.

## What is stored where

| Data | Location | Protection |
|---|---|---|
| Imported configs, private and preshared keys; `active.txt` names the active config | `data\profiles` | Keys encrypted with Windows DPAPI (current user), so the configs only open for the same Windows user on the same PC |
| Rules | `data\policy.json` and `data\engine\policy.json` | No secrets |
| Engine log | `data\engine\engine.log` | Key-shaped strings are redacted; capped at 1 MiB |
| Chrome VPN profile | `data\chrome-profile` | Normal Chrome profile |

`PostUp` / `PostDown` and the other command fields of a `.conf` are never executed; the import reports them.

## Limits you should know

* **IPv6** from a selected process is blocked (applications fall back to IPv4). **ICMP** (`ping`) is not
  attributable to a process and is not covered.
* **Existing connections** of a process are cut once when it is selected, so the application reconnects through
  the VPN. A socket cannot be moved into the tunnel.
* **Shared services:** DNS lookups made through the Windows DNS Client are sent by `svchost.exe`, not by the
  application. The UI flags `svchost.exe` and processes whose path cannot be read.
* **Engine crash or kill:** nothing restarts it. Until you start it again (the app's banner has a button) packets
  of selected processes are not intercepted and use the normal network. See *Kill switch* in the architecture notes.
* **Closing the app** ends interception on purpose.
* **Where you put the folder:** `TunnelPick.exe` and `engine\` run elevated from it, so keep the folder where only
  you can write (not a shared or world-writable location).
* AmneziaWG (obfuscated) configs are rejected, not half-imported.
* The UI strings are English.

## Verification

Run these yourself; each needs one UAC approval. Windows creates firewall rules named `tp-itest` by itself for the
test gateway and tools; both scripts delete them again.

```powershell
.\scripts\run-itest.ps1       # redirector against a loopback WireGuard gateway, incl. two Chrome profiles
.\scripts\e2e-portable.ps1    # runs a copy of dist, starts the engine like the app does, then checks nothing is left behind
```

What `run-itest.ps1` asserts (probes are small programs started by the test, a loopback gateway plays the VPN
server, and a plain server on the LAN address detects any traffic that went out directly):

| # | Check |
|---|---|
| T1 | A selected executable reaches a server that exists only inside the tunnel; the server sees the tunnel address. An unselected copy of the program cannot. |
| T2/T3 | UDP and DNS go through the tunnel; DNS asked of 8.8.8.8 is answered by the tunnel's resolver for a selected process only. |
| T4 | A selected process cannot reach a LAN server directly; an unselected one can. |
| T5 | Tunnel down: selected TCP is refused fast, UDP dropped, nothing reaches the LAN server; unselected process is unaffected; policy text says so. |
| T6 | Two instances of the same executable get different policy (instance rule). |
| T7 | Child processes follow the parent only when "include children" is on. |
| T8 | A connection opened before selection is cut after selection and none of its later bytes arrive directly. |
| T9/T10 | IPv6 does not connect; the local-network option works only when enabled. |
| T11/T12 | Chrome with the VPN profile reaches the tunnel-only server and resolves a tunnel-only name; ordinary Chrome running at the same time does not. |

**Not verified:** a connection to a real WireGuard server. The development machine had no config, so the
public-IP check (`Check IP`) and real handshake against your server are untested; everything above used a
loopback gateway. Import your config and use **Check IP**.

## Dependencies and licenses

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). WinDivert (LGPL-3.0 / GPL-2.0) is loaded as an unmodified
DLL plus its signed driver and is downloaded at build time, not stored in this repository.

## Layout

```
engine/   Go: tunnelpick-engine (elevated helper process), tunnel, redirector, rules, IPC, test tools (tp-itest, tp-probe)
src/      C#: TunnelPick.Core, TunnelPick.App (WPF; Assets\ holds the icon, Properties\PublishProfiles\win-x64.pubxml the publish profile), TunnelPick.Tests
publish.bat  one-step publish (calls scripts\publish.ps1)
scripts/  build-engine, publish, run-itest, e2e-portable, get-windivert
docs/     ARCHITECTURE.md
```
