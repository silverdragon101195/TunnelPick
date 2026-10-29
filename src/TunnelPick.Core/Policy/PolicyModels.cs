namespace TunnelPick.Core.Policy;

public static class RuleKinds
{
    public const string Instance = "instance";
    public const string Executable = "executable";
}

/// <summary>One rule. The shape mirrors the engine's JSON (camelCase on the wire).</summary>
public sealed class Rule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? Name { get; set; }
    public string Kind { get; set; } = RuleKinds.Executable;
    public uint Pid { get; set; }

    /// <summary>FILETIME of the process start; together with Pid it identifies one instance.</summary>
    public ulong Created { get; set; }

    public string? Path { get; set; }
    public string? CmdContains { get; set; }
    public bool Children { get; set; }
    public bool Enabled { get; set; } = true;

    public string Target => Kind == RuleKinds.Instance
        ? $"PID {Pid} (this running instance)"
        : string.IsNullOrEmpty(CmdContains) ? Path ?? "" : $"{Path} [{CmdContains}]";

    public bool Matches(uint pid, ulong created, string? path) =>
        Kind switch
        {
            RuleKinds.Instance => Pid == pid && Created == created,
            RuleKinds.Executable => string.IsNullOrEmpty(CmdContains)
                && path is not null
                && string.Equals(Path, path, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
}

public sealed class PolicySet
{
    public List<Rule> Rules { get; set; } = [];

    /// <summary>Private, link-local and multicast destinations bypass the tunnel for selected processes.</summary>
    public bool BypassLan { get; set; }
}
