using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace TunnelPick.App.Native;

internal static partial class DarkTitleBar
{
    private const int DwmwaUseImmersiveDarkMode = 20;

    /// <summary>Asks DWM to draw the window caption in dark colours. Call once the HWND exists.</summary>
    public static void Apply(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        var enabled = 1;
        DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref enabled, sizeof(int));
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(nint hwnd, int attribute, ref int value, int size);
}
