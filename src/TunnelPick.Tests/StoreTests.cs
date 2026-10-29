using TunnelPick.Core.Config;
using TunnelPick.Core.Policy;
using TunnelPick.Core.Processes;
using TunnelPick.Core.Storage;

namespace TunnelPick.Tests;

public sealed class StoreTests : IDisposable
{
    private const string PrivateKey = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    private const string PublicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    private const string Preshared = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tp-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private static WgConfig Sample() => new(
        new WgInterface(PrivateKey, ["10.2.0.2/32"], ["10.2.0.1"], 1380, null),
        [new WgPeer(PublicKey, Preshared, "vpn.example.com:51820", ["0.0.0.0/0"], 25)]);

    [Fact]
    public void KeysAreNeverWrittenInTheClear()
    {
        var store = new ProfileStore(_dir);
        var saved = store.Save(Sample(), "work");

        var onDisk = File.ReadAllText(Path.Combine(_dir, saved.Id + ".json"));
        Assert.DoesNotContain(PrivateKey, onDisk);
        Assert.DoesNotContain(Preshared, onDisk);
        Assert.DoesNotContain("YAnz5TF", onDisk);
    }

    [Fact]
    public void ProtectedKeysRoundTripIntoTheEngineConfig()
    {
        var store = new ProfileStore(_dir);
        store.Save(Sample(), "work");

        var loaded = Assert.Single(store.List());
        var engine = ProfileStore.ToEngineConfig(loaded);

        Assert.Equal(PrivateKey, engine.PrivateKey);
        Assert.Equal(Preshared, engine.Peers[0].PresharedKey);
        Assert.Equal("vpn.example.com:51820", engine.Peers[0].Endpoint);
        Assert.Equal(25, engine.Peers[0].PersistentKeepalive);
        Assert.Equal(1380, engine.Mtu);
    }

    [Fact]
    public void DeleteRemovesTheProfileAndRejectsTraversal()
    {
        var store = new ProfileStore(_dir);
        var saved = store.Save(Sample(), "work");

        store.Delete(saved.Id);

        Assert.Empty(store.List());
        Assert.Throws<ArgumentException>(() => store.Delete(@"..\evil"));
    }

    [Fact]
    public void TheFirstProfileBecomesActiveAndLaterOnesDoNot()
    {
        var store = new ProfileStore(_dir);
        Assert.Null(store.GetActive());

        var first = store.Save(Sample(), "first");
        var second = store.Save(Sample(), "second");

        Assert.Equal(first.Id, store.GetActive()?.Id);
        Assert.Equal(2, store.List().Count);
        Assert.NotEqual(first.Id, second.Id);
    }

    [Fact]
    public void SetActiveSwitchesTheProfileAndSurvivesANewStoreInstance()
    {
        var store = new ProfileStore(_dir);
        store.Save(Sample(), "first");
        var second = store.Save(Sample(), "second");

        store.SetActive(second.Id);

        Assert.Equal(second.Id, new ProfileStore(_dir).GetActive()?.Id);
        Assert.Throws<ArgumentException>(() => store.SetActive(@"..\evil"));
    }

    [Fact]
    public void DeletingTheActiveProfileHandsOverToARemainingOne()
    {
        var store = new ProfileStore(_dir);
        var first = store.Save(Sample(), "first");
        var second = store.Save(Sample(), "second");
        store.SetActive(second.Id);

        store.Delete(second.Id);
        Assert.Equal(first.Id, store.GetActive()?.Id);

        store.Delete(first.Id);
        Assert.Null(store.GetActive());
        Assert.Empty(store.List());
    }

    [Fact]
    public void DeletingAnInactiveProfileKeepsTheActiveOne()
    {
        var store = new ProfileStore(_dir);
        var first = store.Save(Sample(), "first");
        var second = store.Save(Sample(), "second");

        store.Delete(second.Id);

        Assert.Equal(first.Id, store.GetActive()?.Id);
    }

    [Fact]
    public void ADamagedProfileFileDoesNotHideTheOthers()
    {
        var store = new ProfileStore(_dir);
        store.Save(Sample(), "good");
        File.WriteAllText(Path.Combine(_dir, "broken.json"), "{ not json");

        Assert.Single(store.List());
    }

    [Fact]
    public void PolicyRoundTripsAndUsesTheEngineFieldNames()
    {
        var store = new PolicyStore(Path.Combine(_dir, "policy.json"));
        store.Save(new PolicySet
        {
            BypassLan = true,
            Rules = [new Rule { Id = "a", Kind = RuleKinds.Instance, Pid = 42, Created = 123456789012345678, Children = true }],
        });

        var json = File.ReadAllText(Path.Combine(_dir, "policy.json"));
        Assert.Contains("\"bypassLan\": true", json);
        Assert.Contains("\"created\": 123456789012345678", json);
        var loaded = store.Load();
        Assert.Equal(123456789012345678UL, loaded.Rules[0].Created);
    }

    [Fact]
    public void StaleInstanceRulesAreDroppedButExecutableRulesStay()
    {
        var set = new PolicySet
        {
            Rules =
            [
                new Rule { Id = "alive", Kind = RuleKinds.Instance, Pid = 1, Created = 100 },
                new Rule { Id = "gone", Kind = RuleKinds.Instance, Pid = 2, Created = 200 },
                new Rule { Id = "recycled", Kind = RuleKinds.Instance, Pid = 3, Created = 300 },
                new Rule { Id = "exe", Kind = RuleKinds.Executable, Path = @"C:\a.exe" },
            ],
        };

        var changed = PolicyStore.PruneStaleInstances(set, pid => pid switch { 1 => 100UL, 3 => 999UL, _ => null });

        Assert.True(changed);
        Assert.Equal(["alive", "exe"], set.Rules.Select(r => r.Id));
    }

    [Fact]
    public void RuleMatchingDistinguishesInstancesOfTheSameExecutable()
    {
        var instance = new Rule { Kind = RuleKinds.Instance, Pid = 10, Created = 5 };
        var exe = new Rule { Kind = RuleKinds.Executable, Path = @"C:\Tools\a.exe" };

        Assert.True(instance.Matches(10, 5, @"C:\Tools\a.exe"));
        Assert.False(instance.Matches(11, 6, @"C:\Tools\a.exe"));
        Assert.False(instance.Matches(10, 6, @"C:\Tools\a.exe"));
        Assert.True(exe.Matches(11, 6, @"c:\tools\A.EXE"));
    }

    [Fact]
    public void ChromeVpnUsesItsOwnProfileAndSelectsItByCommandLine()
    {
        var rule = ChromeLauncher.BuildRule(@"C:\Chrome\chrome.exe", @"C:\data\chrome-profile");
        var args = ChromeLauncher.Arguments(@"C:\data\chrome-profile");

        Assert.Equal(@"C:\data\chrome-profile", rule.CmdContains);
        Assert.True(rule.Children);
        Assert.Contains(@"--user-data-dir=C:\data\chrome-profile", args);
        Assert.Contains(args, a => a.StartsWith("--force-webrtc-ip-handling-policy=", StringComparison.Ordinal));
    }

    [Fact]
    public void ProcessSnapshotSeesThisProcessWithAStartTime()
    {
        var me = (uint)Environment.ProcessId;

        var self = Assert.Single(ProcessLister.Snapshot(), p => p.Pid == me);

        Assert.NotNull(self.Path);
        Assert.True(self.Created > 0);
        Assert.Equal(self.Created, ProcessLister.StartTimeOf(me));
    }
}
