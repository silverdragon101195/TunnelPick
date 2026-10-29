using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using TunnelPick.App.Native;

namespace TunnelPick.App;

public partial class App : Application
{
    private const int ErrorCancelled = 1223;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (!IsAdministrator())
        {
            RelaunchElevated(e.Args);
            Shutdown();
            return;
        }

        try
        {
            SigningRoot.EnsureTrusted();
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            MessageBox.Show($"TunnelPick could not add its signing root CA to the Trusted Root Certification Authorities store: {ex.Message}",
                "TunnelPick", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        new MainWindow().Show();
    }

    private static bool IsAdministrator()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Starts a new elevated instance through ShellExecute, the only launch path that shows the UAC prompt;
    /// this unelevated instance exits afterwards. The manifest stays asInvoker so any launcher can start the app.
    /// </summary>
    private static void RelaunchElevated(string[] args)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = true,
            Verb = "runas",
        };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        try
        {
            Process.Start(start);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            MessageBox.Show("TunnelPick needs administrator rights to load the packet driver that redirects the selected processes.",
                "TunnelPick", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
