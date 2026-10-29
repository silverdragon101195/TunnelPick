namespace TunnelPick.Core.Config;

public sealed record WgInterface(
    string PrivateKey,
    IReadOnlyList<string> Addresses,
    IReadOnlyList<string> Dns,
    int? Mtu,
    int? ListenPort);

public sealed record WgPeer(
    string PublicKey,
    string? PresharedKey,
    string? Endpoint,
    IReadOnlyList<string> AllowedIps,
    int? PersistentKeepalive);

public sealed record WgConfig(WgInterface Interface, IReadOnlyList<WgPeer> Peers);

/// <summary>A problem found in a config file. Line is 1-based; 0 means the file as a whole.</summary>
public sealed record ConfigIssue(int Line, string Message)
{
    public override string ToString() => Line > 0 ? $"line {Line}: {Message}" : Message;
}

public sealed record ParseResult(
    WgConfig? Config,
    IReadOnlyList<ConfigIssue> Errors,
    IReadOnlyList<ConfigIssue> Warnings)
{
    public bool Ok => Config is not null && Errors.Count == 0;
}
