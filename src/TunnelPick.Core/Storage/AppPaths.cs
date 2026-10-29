namespace TunnelPick.Core.Storage;

public static class AppPaths
{
    /// <summary>
    /// Everything TunnelPick stores (profiles with DPAPI-protected keys, rules, the engine's log, the Chrome VPN
    /// profile) lives in this folder next to the executable. Nothing is written anywhere else.
    /// </summary>
    public static string Data { get; } = Path.Combine(AppContext.BaseDirectory, "data");

    public static string Profiles => Path.Combine(Data, "profiles");

    public static string Policy => Path.Combine(Data, "policy.json");

    public static string EngineData => Path.Combine(Data, "engine");

    public static string ChromeProfile => Path.Combine(Data, "chrome-profile");
}
