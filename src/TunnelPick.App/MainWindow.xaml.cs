using System.Collections.ObjectModel;
using System.Globalization;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using TunnelPick.App.Native;
using TunnelPick.Core.Config;
using TunnelPick.Core.Engine;
using TunnelPick.Core.Policy;
using TunnelPick.Core.Processes;
using TunnelPick.Core.Storage;

namespace TunnelPick.App;

public partial class MainWindow : Window, IDisposable
{
    private static readonly HttpClient Direct = new() { Timeout = TimeSpan.FromSeconds(10) };

    private readonly ProfileStore _profiles = new(AppPaths.Profiles);
    private readonly PolicyStore _policyStore = new(AppPaths.Policy);
    private readonly EngineClient _engine = new();
    private readonly PolicySet _policy;

    private readonly ObservableCollection<ProfileRow> _profileRows = [];
    private readonly ObservableCollection<GroupRow> _procRows = [];
    private readonly ObservableCollection<RuleRow> _ruleRows = [];
    private readonly ICollectionView _procView;
    private readonly Dictionary<string, GroupRow> _groupIndex = [];
    private readonly Dictionary<(uint, ulong), ProcInfo> _knownProcs = [];
    private readonly HashSet<(uint, ulong)> _routedProcs = [];

    private readonly DispatcherTimer _statusTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _procTimer = new() { Interval = TimeSpan.FromSeconds(2) };

    private EngineStatus? _status;
    private bool _engineUp;
    private bool _busy;
    private bool _loading = true;
    private bool _starting;
    private Process? _engineProcess;
    private string _lastEngineLog = "";

    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => DarkTitleBar.Apply(this);
        _policy = _policyStore.Load();

        ProfileGrid.ItemsSource = _profileRows;
        RebuildProfileRows();

        _procView = CollectionViewSource.GetDefaultView(_procRows);
        _procView.Filter = FilterProcess;
        _procView.SortDescriptions.Add(new SortDescription(nameof(GroupRow.Name), ListSortDirection.Ascending));
        ProcessGrid.ItemsSource = _procView;
        RuleGrid.ItemsSource = _ruleRows;

        BypassLanBox.IsChecked = _policy.BypassLan;
        RebuildRuleRows();
        _loading = false;

        _statusTimer.Tick += async (_, _) => await RefreshStatusAsync();
        _procTimer.Tick += (_, _) => RefreshProcesses();
        Loaded += async (_, _) =>
        {
            RefreshProcesses();
            await RefreshStatusAsync();
            _statusTimer.Start();
            _procTimer.Start();
            if (!_engineUp)
            {
                await StartEngineAsync();
            }
        };
        Closing += OnClosing;
        Closed += (_, _) => Dispose();
    }

    public void Dispose()
    {
        _engine.Dispose();
        GC.SuppressFinalize(this);
    }

    // ---- logging ----

    private void Log(string message)
    {
        AppLog.AppendText($"{DateTime.Now:HH:mm:ss} {message}{Environment.NewLine}");
        AppLog.ScrollToEnd();
    }

    // ---- engine process ----

    private async void OnStartEngine(object sender, RoutedEventArgs e) => await StartEngineAsync();

    /// <summary>Starts the engine elevated and waits until it answers on its pipe.</summary>
    private async Task StartEngineAsync()
    {
        if (_starting || _engineUp)
        {
            return;
        }

        _starting = true;
        RenderStatus();
        try
        {
            Log("starting the engine");
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
            var process = EngineHost.Start(sid, AppPaths.EngineData);
            _engineProcess = process;

            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline && !process.HasExited && !await _engine.IsAvailableAsync())
            {
                await Task.Delay(300);
            }

            if (!await _engine.IsAvailableAsync())
            {
                var reason = process.HasExited ? $"it exited with code {process.ExitCode}" : "it did not answer in time";
                _engineProcess = null;
                throw new EngineException($"The engine did not come up: {reason}. See {Path.Combine(AppPaths.EngineData, "engine.log")}.");
            }
        }
        catch (Exception ex) when (ex is EngineException or Win32Exception or InvalidOperationException)
        {
            Log($"engine not started: {ex.Message}");
            MessageBox.Show(this, ex.Message, "TunnelPick", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _starting = false;
        }

        await RefreshStatusAsync();
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_engineProcess is null)
        {
            return;
        }

        if (_status is { State: not "disconnected", EnabledRules: > 0 } &&
            MessageBox.Show(this, "Closing TunnelPick stops the VPN and the redirection: selected processes will use the normal network again. Close anyway?",
                "TunnelPick", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            e.Cancel = true;
            return;
        }

        // The engine also ends by itself when this process exits. Asking it first and waiting for it means
        // its firewall rule and driver service are gone before this window is.
        try
        {
            Task.Run(() => _engine.ShutdownAsync()).Wait(TimeSpan.FromSeconds(3));
            _engineProcess.WaitForExit(TimeSpan.FromSeconds(12));
        }
        catch (AggregateException)
        {
            // The engine is already gone or unreachable; it ends with this process anyway.
        }
    }

    // ---- engine status ----

    private async Task RefreshStatusAsync()
    {
        if (_busy)
        {
            return;
        }

        try
        {
            var status = await _engine.StatusAsync();
            if (!_engineUp)
            {
                _engineUp = true;
                Log("engine reachable; sending the rule set");
                await PushPolicyAsync();
                status = await _engine.StatusAsync();
            }

            _status = status;
            var logs = string.Join(Environment.NewLine, await _engine.LogsAsync(200));
            if (logs != _lastEngineLog)
            {
                _lastEngineLog = logs;
                EngineLog.Text = logs;
                EngineLog.ScrollToEnd();
            }

            FlowGrid.ItemsSource = (await _engine.FlowsAsync()).Select(f => new { f.Proto, f.Pid, Exe = Path.GetFileName(f.Exe), f.Dst, f.Rule }).ToList();
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException or EngineException or OperationCanceledException)
        {
            if (_engineUp)
            {
                Log($"lost the engine: {ex.Message}");
            }

            _engineUp = false;
            _status = null;
        }

        RenderStatus();
    }

    private void RenderStatus()
    {
        var s = _status;
        if (!_engineUp || s is null)
        {
            SetBanner("BannerErrorBrush", _starting
                ? "Starting the engine…"
                : "Engine is not running. Selected processes are not being redirected.");
            StatsText.Text = "";
            StartEngineButton.Visibility = _starting ? Visibility.Collapsed : Visibility.Visible;
            ConnectButton.IsEnabled = false;
            CheckIpButton.IsEnabled = false;
            return;
        }

        StartEngineButton.Visibility = Visibility.Collapsed;
        ConnectButton.IsEnabled = !_busy;
        CheckIpButton.IsEnabled = s.State == "connected" && !_busy;
        ConnectButton.Content = s.State == "disconnected" ? "Connect" : "Disconnect";

        var color = s.RedirectError is { Length: > 0 } ? "BannerErrorBrush"
            : s.EnabledRules == 0 ? "BannerNeutralBrush"
            : s.State == "connected" ? "BannerOkBrush"
            : "BannerWarnBrush";
        SetBanner(color, s.Enforcement);

        var parts = new List<string> { $"State: {s.State}" };
        if (s.LastHandshakeUnix > 0)
        {
            var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(s.LastHandshakeUnix);
            parts.Add($"last handshake {Math.Max(0, (int)age.TotalSeconds)} s ago");
        }

        parts.Add($"received {FormatBytes(s.RxBytes)}, sent {FormatBytes(s.TxBytes)}");
        parts.Add($"{s.Redirector.TcpFlows} TCP and {s.Redirector.UdpFlows} UDP flows in the tunnel");
        if (s.Redirector.BlockedTcp + s.Redirector.BlockedUdp + s.Redirector.BlockedIpv6 > 0)
        {
            parts.Add($"blocked: {s.Redirector.BlockedTcp} TCP, {s.Redirector.BlockedUdp} UDP, {s.Redirector.BlockedIpv6} IPv6");
        }

        if (!string.IsNullOrEmpty(s.Error))
        {
            parts.Add($"error: {s.Error}");
        }

        StatsText.Text = string.Join("  |  ", parts);
    }

    private void SetBanner(string brushKey, string text)
    {
        Banner.Background = (Brush)FindResource(brushKey);
        EnforcementText.Text = text;
    }

    private static string FormatBytes(ulong n) => n switch
    {
        < 1024 => $"{n} B",
        < 1024 * 1024 => $"{n / 1024.0:F1} KiB",
        < 1024UL * 1024 * 1024 => $"{n / 1048576.0:F1} MiB",
        _ => $"{n / 1073741824.0:F2} GiB",
    };

    // ---- profiles ----

    private void RebuildProfileRows()
    {
        var activeId = _profiles.GetActive()?.Id;
        _profileRows.Clear();
        foreach (var p in _profiles.List())
        {
            _profileRows.Add(new ProfileRow(p, p.Id == activeId));
        }
    }

    private void OnImport(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "WireGuard config (*.conf)|*.conf|All files|*.*",
            Title = "Import WireGuard configs",
            Multiselect = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        foreach (var file in dialog.FileNames)
        {
            ImportFile(file);
        }

        RebuildProfileRows();
    }

    private void ImportFile(string file)
    {
        var fileName = Path.GetFileName(file);
        string text;
        try
        {
            text = File.ReadAllText(file);
        }
        catch (IOException ex)
        {
            MessageBox.Show(this, $"{fileName}: {ex.Message}", "Import failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        ImportText(text, fileName, Path.GetFileNameWithoutExtension(file));
    }

    private void OnPasteImport(object sender, RoutedEventArgs e)
    {
        var dialog = new PasteConfigWindow(UniqueName("pasted-config")) { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        if (ImportText(dialog.ConfigText, "the pasted text", dialog.ConfigName))
        {
            RebuildProfileRows();
        }
    }

    /// <summary>Validates config text and stores it under a name that is not taken yet. Returns false when nothing was stored.</summary>
    private bool ImportText(string text, string source, string name)
    {
        var result = WgConfigParser.Parse(text);
        if (!result.Ok)
        {
            MessageBox.Show(this, $"{source} was not imported:\n\n" + string.Join("\n", result.Errors.Select(x => "• " + x)),
                "Invalid config", MessageBoxButton.OK, MessageBoxImage.Error);
            Log($"import of {source} rejected: {result.Errors.Count} error(s)");
            return false;
        }

        if (result.Warnings.Count > 0)
        {
            var proceed = MessageBox.Show(this,
                $"{source}: these fields are not supported and will have no effect:\n\n" + string.Join("\n", result.Warnings.Select(x => "• " + x)) + "\n\nImport anyway?",
                "Unsupported fields", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (proceed != MessageBoxResult.Yes)
            {
                return false;
            }
        }

        var stored = _profiles.Save(result.Config!, UniqueName(name));
        Log($"imported '{stored.Name}' ({result.Config!.Peers.Count} peer(s)); the private key is stored with Windows data protection");
        return true;
    }

    private string UniqueName(string name)
    {
        var taken = _profiles.List().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var candidate = name;
        for (var n = 2; taken.Contains(candidate); n++)
        {
            candidate = $"{name} ({n})";
        }

        return candidate;
    }

    private async void OnActivateProfile(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is not ProfileRow row || row.IsActive || _busy)
        {
            return;
        }

        _profiles.SetActive(row.Profile.Id);
        foreach (var r in _profileRows)
        {
            r.IsActive = r == row;
        }

        Log($"'{row.Name}' is now the active config");

        // A running tunnel keeps using the old config until it is replaced.
        if (_status is { State: not "disconnected" })
        {
            await RunEngineActionAsync(() => ConnectAsync(row.Profile));
        }
    }

    private async void OnRemoveProfile(object sender, RoutedEventArgs e)
    {
        if (ProfileGrid.SelectedItem is not ProfileRow row || _busy)
        {
            return;
        }

        var running = row.IsActive && _status is { State: not "disconnected" };
        var question = $"Remove '{row.Name}' from TunnelPick? The original .conf file is not touched.";
        if (running)
        {
            question += "\n\nIt is the active config and the VPN is on, so the VPN will be disconnected.";
        }

        if (MessageBox.Show(this, question, "Remove config", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        _profiles.Delete(row.Profile.Id);
        RebuildProfileRows();
        Log($"removed '{row.Name}'");
        if (running)
        {
            await RunEngineActionAsync(DisconnectAsync);
        }
    }

    // ---- connect / disconnect ----

    private async void OnConnectToggle(object sender, RoutedEventArgs e)
    {
        if (_status is null)
        {
            return;
        }

        if (_status.State != "disconnected")
        {
            await RunEngineActionAsync(DisconnectAsync);
            return;
        }

        if (_profiles.GetActive() is not { } profile)
        {
            MessageBox.Show(this, "Import a WireGuard config and mark it Active first.", "No active config", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        await RunEngineActionAsync(() => ConnectAsync(profile));
    }

    private async Task DisconnectAsync()
    {
        await _engine.DisconnectAsync();
        Log("disconnected; selected processes are now blocked from the network (kill switch)");
        IpText.Text = "";
    }

    private async Task ConnectAsync(StoredProfile profile)
    {
        await _engine.ConnectAsync(ProfileStore.ToEngineConfig(profile));
        Log($"connecting with '{profile.Name}'");
        IpText.Text = "";
    }

    /// <summary>Runs one engine call with the buttons held, reports a failure, then refreshes the status.</summary>
    private async Task RunEngineActionAsync(Func<Task> action)
    {
        _busy = true;
        ConnectButton.IsEnabled = false;
        try
        {
            await action();
        }
        catch (Exception ex) when (ex is EngineException or IOException or System.Security.Cryptography.CryptographicException)
        {
            Log($"failed: {ex.Message}");
            MessageBox.Show(this, ex.Message, "TunnelPick", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _busy = false;
        }

        await RefreshStatusAsync();
    }

    private async void OnCheckIp(object sender, RoutedEventArgs e)
    {
        IpText.Text = "Checking…";
        string via;
        string direct;
        try
        {
            via = await _engine.EgressIpAsync();
        }
        catch (Exception ex) when (ex is EngineException or IOException)
        {
            via = "failed (" + ex.Message + ")";
        }

        try
        {
            direct = (await Direct.GetStringAsync("https://api.ipify.org")).Trim();
        }
        catch (HttpRequestException ex)
        {
            direct = "failed (" + ex.Message + ")";
        }
        catch (TaskCanceledException)
        {
            direct = "timed out";
        }

        IpText.Text = $"Address seen through the tunnel: {via}   |   Address of the normal network: {direct}";
        Log(IpText.Text);
    }

    // ---- processes ----

    private bool FilterProcess(object item)
    {
        var text = SearchBox.Text.Trim();
        if (text.Length == 0 || item is not GroupRow row)
        {
            return true;
        }

        return row.Name.Contains(text, StringComparison.OrdinalIgnoreCase)
            || row.PathText.Contains(text, StringComparison.OrdinalIgnoreCase)
            || row.PidsText.Contains(text, StringComparison.Ordinal);
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e) => _procView?.Refresh();

    private void RefreshProcesses()
    {
        var snapshot = ProcessLister.Snapshot();
        var groups = snapshot.GroupBy(GroupSelection.KeyOf).ToDictionary(g => g.Key, g => (IReadOnlyList<ProcInfo>)g.ToList());

        foreach (var (key, members) in groups)
        {
            if (_groupIndex.TryGetValue(key, out var existing))
            {
                existing.SetMembers(members);
            }
            else
            {
                var row = new GroupRow(key, members, OnGroupToggle);
                _groupIndex[key] = row;
                _procRows.Add(row);
            }
        }

        foreach (var key in _groupIndex.Keys.Where(k => !groups.ContainsKey(k)).ToList())
        {
            _procRows.Remove(_groupIndex[key]);
            _groupIndex.Remove(key);
        }

        // Rules can match processes that started since the last look (an executable rule, a child process).
        foreach (var row in _procRows)
        {
            row.SetRoutedFromPolicy(GroupSelection.IsRouted(_policy, row.Members));
        }

        LogProcessChanges(snapshot);

        if (PolicyStore.PruneStaleInstances(_policy, ProcessLister.StartTimeOf))
        {
            RebuildRuleRows();
            SavePolicy();
            _ = PushPolicyAsync();
            Log("removed a rule for a process that exited");
        }
    }

    /// <summary>Logs the start and exit of processes that a rule covers.</summary>
    private void LogProcessChanges(IReadOnlyList<ProcInfo> snapshot)
    {
        var seen = new HashSet<(uint, ulong)>();
        foreach (var p in snapshot)
        {
            var key = (p.Pid, p.Created);
            seen.Add(key);
            if (_knownProcs.TryAdd(key, p) && IsMatched(p))
            {
                _routedProcs.Add(key);
                Log($"{p.Name} (PID {p.Pid}) started and matches a rule");
            }
        }

        foreach (var key in _knownProcs.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            var p = _knownProcs[key];
            _knownProcs.Remove(key);
            if (_routedProcs.Remove(key))
            {
                Log($"{p.Name} (PID {p.Pid}) exited");
            }
        }
    }

    private bool IsMatched(ProcInfo p) =>
        _policy.Rules.Exists(r => r.Enabled && r.Matches(p.Pid, p.Created, p.Path));

    private void OnGroupToggle(GroupRow row, bool routed)
    {
        if (_loading)
        {
            return;
        }

        var members = row.Members;
        if (routed)
        {
            var wholeExecutable = ModeExecutable.IsChecked == true && members[0].Path is not null;
            GroupSelection.Select(_policy, members, wholeExecutable, ChildrenBox.IsChecked == true);
            Log(wholeExecutable
                ? $"{row.Name}: every instance is now routed through the VPN"
                : $"{row.Name}: {members.Count} running process(es) are now routed through the VPN; their existing connections will be reset");
        }
        else
        {
            GroupSelection.Deselect(_policy, members);
            Log($"{row.Name} no longer selected; new connections use the normal network");
        }

        PolicyChanged();
    }

    // ---- rules ----

    private void RebuildRuleRows()
    {
        _ruleRows.Clear();
        foreach (var rule in _policy.Rules)
        {
            _ruleRows.Add(new RuleRow(rule, PolicyChanged));
        }
    }

    private void OnRemoveRule(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is RuleRow row)
        {
            _policy.Rules.Remove(row.Rule);
            Log($"rule '{row.Name}' removed");
            PolicyChanged();
        }
    }

    private void OnBypassLanChanged(object sender, RoutedEventArgs e)
    {
        if (_loading)
        {
            return;
        }

        _policy.BypassLan = BypassLanBox.IsChecked == true;
        PolicyChanged();
    }

    private void PolicyChanged()
    {
        if (_loading)
        {
            return;
        }

        RebuildRuleRows();
        foreach (var row in _procRows)
        {
            row.SetRoutedFromPolicy(GroupSelection.IsRouted(_policy, row.Members));
        }

        SavePolicy();
        _ = PushPolicyAsync();
    }

    private void SavePolicy() => _policyStore.Save(_policy);

    private async Task PushPolicyAsync()
    {
        try
        {
            await _engine.SetPolicyAsync(_policy);
        }
        catch (Exception ex) when (ex is EngineException or IOException or TimeoutException or UnauthorizedAccessException)
        {
            Log($"engine did not accept the rule set: {ex.Message}");
        }
    }

    // ---- Chrome ----

    private async void OnOpenChrome(object sender, RoutedEventArgs e)
    {
        var chrome = ChromeLauncher.FindChrome();
        if (chrome is null)
        {
            MessageBox.Show(this, "Google Chrome was not found.", "Chrome", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!_engineUp)
        {
            MessageBox.Show(this, "The engine is not running, so this Chrome could not be kept off the normal network. It was not started.",
                "Chrome", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_status?.State != "connected" &&
            MessageBox.Show(this, "The VPN is not connected. This Chrome will have no network until it is. Open it anyway?",
                "Chrome", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        var profileDir = AppPaths.ChromeProfile;
        _policy.Rules.RemoveAll(r => r.Id == ChromeLauncher.RuleId);
        _policy.Rules.Add(ChromeLauncher.BuildRule(chrome, profileDir));
        SavePolicy();
        RebuildRuleRows();

        // The rule must be enforced before the browser exists, or its first connections could go out directly.
        try
        {
            await _engine.SetPolicyAsync(_policy);
            ChromeLauncher.Launch(chrome, profileDir);
            Log("opened Chrome with its own profile; every process of that profile is routed through the VPN");
        }
        catch (Exception ex) when (ex is EngineException or IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Log($"Chrome VPN not started: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Chrome", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
