using TunnelPick.Core.Policy;
using TunnelPick.Core.Processes;

namespace TunnelPick.Tests;

public sealed class GroupSelectionTests
{
    private const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

    private static ProcInfo P(uint pid, string? path = Chrome, string name = "chrome.exe") => new(pid, name, path, pid * 10UL, null);

    private static ProcInfo[] Browser() => [P(1), P(2), P(3)];

    [Fact]
    public void ProcessesOfOneExecutableShareAGroupRegardlessOfPathCase()
    {
        Assert.Equal(GroupSelection.KeyOf(P(1)), GroupSelection.KeyOf(P(2, Chrome.ToUpperInvariant())));
        Assert.NotEqual(GroupSelection.KeyOf(P(1)), GroupSelection.KeyOf(P(1, @"C:\Other\chrome.exe")));
    }

    [Fact]
    public void ProcessesWithoutAReadablePathAreGroupedByName()
    {
        Assert.Equal(GroupSelection.KeyOf(P(1, null, "Idle.exe")), GroupSelection.KeyOf(P(2, null, "idle.EXE")));
        Assert.NotEqual(GroupSelection.KeyOf(P(1, null, "a.exe")), GroupSelection.KeyOf(P(2, null, "b.exe")));
    }

    [Fact]
    public void WholeExecutableSelectionIsOneRuleThatCoversEveryProcessAndLaterOnes()
    {
        var set = new PolicySet();

        GroupSelection.Select(set, Browser(), wholeExecutable: true, children: true);

        var rule = Assert.Single(set.Rules);
        Assert.Equal(RuleKinds.Executable, rule.Kind);
        Assert.True(rule.Children);
        Assert.True(GroupSelection.IsRouted(set, Browser()));
        Assert.True(GroupSelection.IsRouted(set, [.. Browser(), P(99)]));
    }

    [Fact]
    public void SelectingTheSameExecutableTwiceDoesNotDuplicateTheRule()
    {
        var set = new PolicySet();

        GroupSelection.Select(set, Browser(), true, false);
        GroupSelection.Select(set, Browser(), true, true);

        Assert.True(Assert.Single(set.Rules).Children);
    }

    [Fact]
    public void InstanceSelectionAddsOneRulePerRunningProcessAndSkipsCoveredOnes()
    {
        var set = new PolicySet();
        GroupSelection.Select(set, [P(1)], wholeExecutable: false, children: false);

        GroupSelection.Select(set, Browser(), wholeExecutable: false, children: false);

        Assert.Equal([1u, 2u, 3u], set.Rules.Select(r => r.Pid).Order());
        Assert.All(set.Rules, r => Assert.Equal(RuleKinds.Instance, r.Kind));
        Assert.True(GroupSelection.IsRouted(set, Browser()));
    }

    [Fact]
    public void AProcessStartedAfterAnInstanceSelectionLeavesTheGroupNotFullyRouted()
    {
        var set = new PolicySet();
        GroupSelection.Select(set, Browser(), false, false);

        Assert.False(GroupSelection.IsRouted(set, [.. Browser(), P(4)]));
    }

    [Fact]
    public void WithoutAPathTheSelectionFallsBackToInstanceRules()
    {
        var set = new PolicySet();

        GroupSelection.Select(set, [P(1, null)], wholeExecutable: true, children: false);

        Assert.Equal(RuleKinds.Instance, Assert.Single(set.Rules).Kind);
    }

    [Fact]
    public void DeselectingRemovesTheRulesOfTheGroupOnly()
    {
        var set = new PolicySet();
        GroupSelection.Select(set, Browser(), true, false);
        GroupSelection.Select(set, [P(50, @"C:\Tools\a.exe", "a.exe")], true, false);

        GroupSelection.Deselect(set, Browser());

        Assert.Equal(@"C:\Tools\a.exe", Assert.Single(set.Rules).Path);
    }

    [Fact]
    public void ADisabledRuleDoesNotCountAsRouted()
    {
        var set = new PolicySet();
        GroupSelection.Select(set, Browser(), true, false);
        set.Rules[0].Enabled = false;

        Assert.False(GroupSelection.IsRouted(set, Browser()));
    }

    [Fact]
    public void TheChromeVpnProfileRuleIsNotMistakenForSelectingChrome()
    {
        var set = new PolicySet { Rules = [ChromeLauncher.BuildRule(Chrome, @"C:\data\chrome-profile")] };

        Assert.False(GroupSelection.IsRouted(set, Browser()));
    }
}
