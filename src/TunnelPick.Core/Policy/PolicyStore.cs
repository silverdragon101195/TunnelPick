using System.Text.Json;
using System.Text.Json.Serialization;

namespace TunnelPick.Core.Policy;

public sealed class PolicyStore(string path)
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public PolicySet Load()
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<PolicySet>(File.ReadAllText(path), Json) ?? new PolicySet()
                : new PolicySet();
        }
        catch (JsonException)
        {
            return new PolicySet();
        }
    }

    public void Save(PolicySet set)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(set, Json));
    }

    /// <summary>
    /// Removes instance rules whose process is gone or whose PID now belongs to a different process.
    /// Returns true when something was removed.
    /// </summary>
    public static bool PruneStaleInstances(PolicySet set, Func<uint, ulong?> startTimeOf) =>
        set.Rules.RemoveAll(r => r.Kind == RuleKinds.Instance && startTimeOf(r.Pid) != r.Created) > 0;
}
