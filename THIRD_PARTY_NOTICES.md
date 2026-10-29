# Third-party components

| Component | Use | License |
|---|---|---|
| [WinDivert 2.2.2](https://github.com/basil00/WinDivert) | Packet capture driver and `WinDivert.dll`, unmodified, downloaded by `scripts/get-windivert.ps1` and shipped next to the engine | LGPL-3.0 or GPL-2.0 (dual). The license text is copied to `engine\WinDivert-LICENSE.txt` in the package. |
| [wireguard-go](https://git.zx2c4.com/wireguard-go) (`golang.zx2c4.com/wireguard`) | WireGuard device and userspace network stack glue | MIT |
| [gVisor](https://gvisor.dev) (`gvisor.dev/gvisor`) | Userspace TCP/IP stack used by netstack | Apache-2.0 |
| [go-winio](https://github.com/microsoft/go-winio) | Named pipe server with security descriptor | MIT |
| `golang.org/x/sys`, `x/crypto`, `x/net`, `x/time` | Windows API, X25519, networking | BSD-3-Clause |
| [System.Security.Cryptography.ProtectedData](https://www.nuget.org/packages/System.Security.Cryptography.ProtectedData) | DPAPI for stored keys | MIT |
| [xunit.v3](https://xunit.net) | Unit tests only, not shipped | Apache-2.0 |

WireGuard is a registered trademark of Jason A. Donenfeld. TunnelPick is not affiliated with the WireGuard project.

No component requires a paid license or SDK.

Administrator rights are needed (the app asks once when it opens): to let WinDivert register and load its driver
service and to add the temporary firewall rule. Both are removed when the engine ends.
