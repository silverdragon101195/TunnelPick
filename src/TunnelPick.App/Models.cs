using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using TunnelPick.Core.Policy;
using TunnelPick.Core.Processes;
using TunnelPick.Core.Storage;

namespace TunnelPick.App;

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>A row of the config list; the Activate button of a row calls the owner.</summary>
public sealed class ProfileRow(StoredProfile profile, bool isActive) : Observable
{
    private bool _isActive = isActive;

    public StoredProfile Profile { get; } = profile;
    public string Name => Profile.Name;
    public string Endpoint => Profile.Peers.FirstOrDefault()?.Endpoint ?? "";
    public string Imported => Profile.ImportedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    public bool IsActive
    {
        get => _isActive;
        set
        {
            if (_isActive == value)
            {
                return;
            }

            _isActive = value;
            Raise();
            Raise(nameof(CanActivate));
            Raise(nameof(ActivateText));
        }
    }

    public bool CanActivate => !_isActive;
    public string ActivateText => _isActive ? "Active" : "Activate";
}

/// <summary>
/// A row of the application list: every running process of one executable. Ticking the box adds or removes
/// rules through the owner.
/// </summary>
public sealed class GroupRow(string key, IReadOnlyList<ProcInfo> members, Action<GroupRow, bool> onToggle) : Observable
{
    private bool _routed;

    public string Key { get; } = key;
    public IReadOnlyList<ProcInfo> Members { get; private set; } = members;
    public string Name => Members[0].Name;
    public string PathText => Members[0].Path ?? "(not readable)";
    public int Count => Members.Count;
    public string? Limitation => Members.Select(m => m.Limitation).FirstOrDefault(l => l is not null);

    /// <summary>The process ids, for the search box.</summary>
    public string PidsText => string.Join(' ', Members.Select(m => m.Pid.ToString(CultureInfo.InvariantCulture)));

    public bool Routed
    {
        get => _routed;
        set
        {
            if (_routed == value)
            {
                return;
            }

            _routed = value;
            Raise();
            onToggle(this, value);
        }
    }

    public void SetMembers(IReadOnlyList<ProcInfo> members)
    {
        Members = members;
        Raise(nameof(Count));
        Raise(nameof(Limitation));
    }

    /// <summary>Reflects the rule set without triggering a rule change.</summary>
    public void SetRoutedFromPolicy(bool value)
    {
        if (_routed == value)
        {
            return;
        }

        _routed = value;
        Raise(nameof(Routed));
    }
}

/// <summary>A row of the rule list; edits write straight through to the rule.</summary>
public sealed class RuleRow(Rule rule, Action onChanged) : Observable
{
    public Rule Rule { get; } = rule;
    public string Name => Rule.Name ?? Rule.Id;
    public string Target => Rule.Target;

    public bool Enabled
    {
        get => Rule.Enabled;
        set
        {
            if (Rule.Enabled == value)
            {
                return;
            }

            Rule.Enabled = value;
            Raise();
            onChanged();
        }
    }

    public bool Children
    {
        get => Rule.Children;
        set
        {
            if (Rule.Children == value)
            {
                return;
            }

            Rule.Children = value;
            Raise();
            onChanged();
        }
    }
}
