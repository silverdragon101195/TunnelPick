# TunnelPick architecture

TunnelPick routes the traffic of selected Windows processes through a WireGuard server and leaves every
other process on the normal network.

```
selected process ──► WinDivert (kernel driver) ──► redirector (engine) ──► userspace netstack ─► wireguard-go ─► VPN server
other process    ──► Windows default route ───────────────────────────────────────────────────────────────────► Internet
```

## Components

| Part | Language | Role |
|---|---|---|
| `engine/` `tunnelpick-engine.exe` | Go | Child process of the UI (`run`), elevated like the UI. Runs the WireGuard device, the redirector, the rule engine and the IPC server; exits with the UI. |
| `src/TunnelPick.Core` | C# | Config parser, DPAPI profile store, rule store, IPC client, process listing, Chrome launcher. |
| `src/TunnelPick.App` | C# / WPF | The window. Relaunches itself elevated at start (one UAC prompt, same pattern as SysLens) and starts the engine as its child. |
| WinDivert 2.2.2 | C | Pre-signed kernel driver plus `WinDivert.dll`, loaded dynamically by the engine. |

## Decisions

### WireGuard engine: wireguard-go + gVisor netstack

`golang.zx2c4.com/wireguard` with its `tun/netstack` package terminates the tunnel in a userspace TCP/IP stack.
There is no virtual adapter, no Wintun driver and no change to the Windows routing table or DNS settings, so
processes that are not selected are not affected by the tunnel at all. It does not need the official WireGuard
for Windows application, and does not read or modify existing WireGuard tunnels.

The engine dials through the tunnel with `netstack.Net` (`DialContextTCPAddrPort`, `DialUDPAddrPort`). The WireGuard
UDP socket itself is created by the engine process, which the redirector never touches.

### Per-process redirection: WinDivert at the network layer

Researched options:

| Option | Verdict |
|---|---|
| WFP user-mode filters | Can permit or block per application, but cannot redirect a connection. The redirect actions need a callout driver. |
| Own WFP callout driver | Needs an EV certificate and Microsoft attestation signing. Not available for a personal project. |
| Winsock hooking / DLL injection | Fragile; Chrome's sandboxed network service rejects it; anti-cheat and antivirus dislike it. |
| Local proxy (`--proxy-server`) | Works only for applications that honour a proxy. Kept in mind as a fallback, not implemented. |
| Commercial SDKs (Netfilter SDK, Proxifier) | Paid. |
| **WinDivert 2.2.2** | Free (LGPL-3.0 or GPL-2.0), driver is pre-signed so no test signing is needed, loads on Windows 11 with HVCI (verified on the development machine). Needs administrator rights, which the service has. |

Caveat: some antivirus products flag the WinDivert archive. Windows Defender did on the development machine
(`Misleading:Win32/Malgent!AMTB`). TunnelPick neither disables nor works around it; the build script stops and
tells the user to add an exclusion for the download folder.

### How a flow is classified

One WinDivert handle on the network layer, filter `outbound and (tcp or udp)`.

1. For the first packet of a flow the owner is read from the IP Helper socket tables
   (`GetExtendedTcpTable` / `GetExtendedUdpTable`). The socket exists in the table before its first packet
   leaves, so no race with a separate socket-layer handle exists.
2. The PID is resolved to an identity (start time, parent, image path, command line). `(PID, start time)` is the
   identity, because Windows reuses PIDs.
3. The rule set decides. Instance rules match `(PID, start time)`. Executable rules match the image path
   (case-insensitive) and optionally a command-line substring. With "include children", ancestry is walked up and
   a parent whose start time is later than its child's is rejected as a recycled PID.
4. Decisions are cached per flow until the policy changes or the flow idles.

### TCP

A SYN of a selected flow is rewritten into an inbound packet addressed to the machine itself on the relay port
(the same technique as WinDivert's `streamdump` sample). The relay accepts it, learns the original destination
from the flow table, dials it through the tunnel and pipes bytes. Replies from the relay are rewritten so they
appear to come from the original server. The client's TCP stack is unaware.

### UDP

Datagrams of selected flows are carried one flow at a time through a netstack UDP socket. Replies are injected
as hand-built IPv4/UDP packets whose source is the original destination. This carries QUIC, STUN/WebRTC and
DNS without a proxy protocol.

### DNS

For a selected process every packet to port 53 (UDP and TCP) is sent to the tunnel's first `DNS=` server,
whatever server the application asked. The system DNS settings are never changed. If the config has no `DNS`
line, the original destination is used and must be inside `AllowedIPs`.

### IPv4 / IPv6 / ICMP

* IPv4 TCP and UDP are carried.
* IPv6 from a selected process is **blocked**, not sent directly; applications fall back to IPv4.
* ICMP cannot be attributed to a process, so `ping` is not covered (it stays on the normal network).

### AllowedIPs and the local network

Destinations of a selected process that the tunnel does not route (outside `AllowedIPs`) are blocked. With the
"local network" option on, private, link-local and multicast destinations bypass the tunnel on purpose; this is
the only way a selected process is allowed to use the normal network, and it is off by default.

## Kill switch

* **Tunnel down or disconnected:** selected flows are still captured. TCP gets a reset (the SYN is answered
  with RST), UDP is dropped. Nothing is sent directly. Other processes are untouched.
* **Rules survive restarts:** the rule set is stored in `data\engine\policy.json` (no secrets). At engine
  start it is applied before any connect, so selected processes stay blocked until the tunnel is up.
* **Engine crash or kill:** nothing restarts the engine. WinDivert interception exists only while a handle is
  open, so from then until the UI starts the engine again **packets of selected processes are not intercepted**.
  The UI shows "Engine is not running" with a start button. Closing that gap would need a persistent kernel-side
  filter, which a user-mode WFP filter cannot provide without breaking the redirect.
* **Engine stopped on purpose** (the UI closed, `shutdown`): interception ends; selected processes use the normal
  network.

## Existing connections

A connection that was opened before its process was selected cannot be moved into the tunnel. When a packet of
such a connection is seen after selection it is reset, so the application reconnects and the new connection goes
through the VPN. The UI says so when a process is selected.

## Limits that cannot be fixed from user mode

* Applications that make the Windows DNS Client (svchost.exe) resolve names send those lookups from svchost, not
  from themselves. Selecting svchost.exe is possible but affects many services; the UI flags it.
* A service that performs network access on behalf of an application (BITS, Windows Update, background
  brokers) is attributed to the service, not the application.
* Traffic that does not use TCP or UDP over IPv4 (ICMP, IPv6) is blocked or not covered as listed above.

## IPC and permissions

* Named pipe `\\.\pipe\TunnelPick`, created by the engine with an explicit security descriptor:
  `SYSTEM` and `Administrators` full control, plus the SID of the user who started the app (`--allow-sid`). Remote clients are
  rejected by the pipe implementation.
* Requests are one JSON object per line. The private key crosses the pipe only in the `connect` request, is held
  in engine memory and never written to disk or logged (the log redacts key-shaped strings).
* The UI stores private and preshared keys with DPAPI (`CurrentUser` scope, application entropy).
* The engine is started with `--parent-pid` and exits when the UI process does. A machine-wide mutex allows one
  engine at a time. The engine runs elevated from the app folder, so that folder should only be writable by you.

## What the app puts on the system

TunnelPick is portable and has no installer. All of its data is in the `data` folder next to the executable.

| Change | While | Removed |
|---|---|---|
| Driver service `WinDivert` (WinDivert registers it on first use) | the engine runs | by the engine when it ends (stop + delete) |
| Firewall rule `TunnelPick engine relay`: inbound Allow, program = the engine executable, TCP, remote address `LocalSubnet` | the engine runs | by the engine when it ends; a killed engine's rule is removed at the next start |
| Hoshizora Root CA in the machine's Trusted Root Certification Authorities (`Native/SigningRoot.cs`; only when the exe is signed by a certificate that chains to it and the store lacks it) | permanent, added once at the first run | not removed: SysLens relies on the same certificate (`certmgr.msc` to delete) |

No route, DNS setting, service, scheduled task or registry key is created or changed, and no
WireGuard tunnel of another program is touched. The firewall rule is needed because Windows Firewall drops the
inbound packets the redirector bounces to the relay unless the engine may receive them. The rule covers nothing
else (one program, TCP, local subnet), and it exists before the relay listens so Windows never creates a
permanent rule of its own.
