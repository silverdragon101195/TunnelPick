namespace TunnelPick.Core.Engine;

public sealed class RedirectorStats
{
    public bool Active { get; set; }
    public int TcpFlows { get; set; }
    public int UdpFlows { get; set; }
    public ulong BlockedTcp { get; set; }
    public ulong BlockedUdp { get; set; }
    public ulong BlockedIpv6 { get; set; }
    public ulong PreexistingDropped { get; set; }
    public ulong OutsideAllowedIps { get; set; }
    public ulong RefusedTunnelDown { get; set; }
}

public sealed class EngineStatus
{
    public string Version { get; set; } = "";

    /// <summary>disconnected | connecting | connected</summary>
    public string State { get; set; } = "disconnected";

    public long LastHandshakeUnix { get; set; }
    public ulong RxBytes { get; set; }
    public ulong TxBytes { get; set; }
    public string? Error { get; set; }
    public string? RedirectError { get; set; }
    public RedirectorStats Redirector { get; set; } = new();
    public int EnabledRules { get; set; }
    public bool BypassLan { get; set; }
    public string Enforcement { get; set; } = "";
    public bool TunnelHasIpv6 { get; set; }
}

public sealed class FlowInfo
{
    public string Proto { get; set; } = "";
    public uint Pid { get; set; }
    public string Exe { get; set; } = "";
    public string Dst { get; set; } = "";
    public string Rule { get; set; } = "";
}

public sealed class EngineException(string message) : Exception(message);
