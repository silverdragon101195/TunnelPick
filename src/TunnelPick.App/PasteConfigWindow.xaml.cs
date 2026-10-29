using System.Windows;
using System.Windows.Controls;
using TunnelPick.App.Native;

namespace TunnelPick.App;

/// <summary>Asks for a name and the text of a WireGuard config, for configs that are copied rather than saved as a file.</summary>
public partial class PasteConfigWindow : Window
{
    public PasteConfigWindow(string suggestedName)
    {
        InitializeComponent();
        SourceInitialized += (_, _) => DarkTitleBar.Apply(this);
        NameBox.Text = suggestedName;

        // A config copied just before opening this window is the usual case.
        var clipboard = TryGetClipboardText();
        if (clipboard is not null && clipboard.Contains("[Interface]", StringComparison.OrdinalIgnoreCase))
        {
            ConfigBox.Text = clipboard;
        }

        Loaded += (_, _) => ConfigBox.Focus();
    }

    public string ConfigName => NameBox.Text.Trim();

    public string ConfigText => ConfigBox.Text;

    private static string? TryGetClipboardText()
    {
        try
        {
            return Clipboard.ContainsText() ? Clipboard.GetText() : null;
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            // Another program holds the clipboard; the user can paste by hand.
            return null;
        }
    }

    private void OnConfigChanged(object sender, TextChangedEventArgs e) =>
        ImportButton.IsEnabled = ConfigBox.Text.Trim().Length > 0;

    private void OnImport(object sender, RoutedEventArgs e)
    {
        if (ConfigName.Length == 0)
        {
            MessageBox.Show(this, "Give the config a name.", "Paste config", MessageBoxButton.OK, MessageBoxImage.Information);
            NameBox.Focus();
            return;
        }

        DialogResult = true;
    }
}
