using TunnelPick.Core.Processes;

namespace TunnelPick.Core.Policy;

/// <summary>
/// Selecting an application in the list means selecting every running process of one executable (a group),
/// so a browser with a dozen processes is one row and one tick.
/// </summary>
public static class GroupSelection
{
    /// <summary>The group a process belongs to: its executable path, or its name when the path cannot be read.</summary>
    public static string KeyOf(ProcInfo p) =>
        p.Path is { Length: > 0 } path ? path.ToUpperInvariant() : "name:" + p.Name.ToUpperInvariant();

    /// <summary>True when a rule covers every process of the group.</summary>
    public static bool IsRouted(PolicySet set, IReadOnlyList<ProcInfo> members) =>
        members.Count > 0 && members.All(m => set.Rules.Exists(r => r.Enabled && r.Matches(m.Pid, m.Created, m.Path)));

    /// <summary>
    /// Selects the group. A whole-executable rule covers every instance, including later launches; without one
    /// (or when the path is unknown) each running process not yet covered gets its own instance rule.
    /// </summary>
    public static void Select(PolicySet set, IReadOnlyList<ProcInfo> members, bool wholeExecutable, bool children)
    {
        var first = members[0];
        if (wholeExecutable && first.Path is not null)
        {
            set.Rules.RemoveAll(r => r.Kind == RuleKinds.Executable
                && string.IsNullOrEmpty(r.CmdContains)
                && string.Equals(r.Path, first.Path, StringComparison.OrdinalIgnoreCase));
            set.Rules.Add(new Rule { Name = first.Name, Kind = RuleKinds.Executable, Path = first.Path, Children = children });
            return;
        }

        foreach (var m in members)
        {
            if (!set.Rules.Exists(r => r.Enabled && r.Matches(m.Pid, m.Created, m.Path)))
            {
                set.Rules.Add(new Rule { Name = m.Name, Kind = RuleKinds.Instance, Pid = m.Pid, Created = m.Created, Path = m.Path, Children = children });
            }
        }
    }

    /// <summary>Removes every rule that covers a process of the group.</summary>
    public static void Deselect(PolicySet set, IReadOnlyList<ProcInfo> members) =>
        set.Rules.RemoveAll(r => members.Any(m => r.Matches(m.Pid, m.Created, m.Path)));
}
