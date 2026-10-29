using System.Diagnostics;
using Microsoft.Win32;
using TunnelPick.Core.Policy;

namespace TunnelPick.Core.Processes;

/// <summary>
/// Starts a Chrome that is separate from the everyday one: its own user-data directory means its own
/// browser process tree, which the rule below selects by command line. Normal Chrome is untouched.
/// </summary>
public static class ChromeLauncher
{
    public const string RuleId = "chrome-vpn";

    public static string? FindChrome()
    {
        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            using var key = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe");
            if (key?.GetValue(null) is string path && File.Exists(path))
            {
                return path;
            }
        }

        foreach (var candidate in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Chrome\Application\chrome.exe"),
        })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    /// <summary>The rule selecting every process of the VPN Chrome: browser, network service, renderers.</summary>
    public static Rule BuildRule(string chromePath, string profileDir) => new()
    {
        Id = RuleId,
        Name = "Chrome VPN profile",
        Kind = RuleKinds.Executable,
        Path = chromePath,
        CmdContains = profileDir,
        Children = true,
        Enabled = true,
    };

    public static IReadOnlyList<string> Arguments(string profileDir) =>
    [
        $"--user-data-dir={profileDir}",
        "--no-first-run",
        "--no-default-browser-check",

        // Keep WebRTC from advertising local addresses next to the VPN one.
        "--force-webrtc-ip-handling-policy=default_public_interface_only",
    ];

    public static Process Launch(string chromePath, string profileDir)
    {
        Directory.CreateDirectory(profileDir);
        var info = new ProcessStartInfo(chromePath) { UseShellExecute = false };
        foreach (var arg in Arguments(profileDir))
        {
            info.ArgumentList.Add(arg);
        }

        return Process.Start(info) ?? throw new InvalidOperationException("Chrome did not start");
    }
}
