using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;

namespace TunnelPick.Core.Engine;

/// <summary>Starts the engine that sits in the engine folder next to the executable.</summary>
public static class EngineHost
{
    public static string ExePath { get; } = Path.Combine(AppContext.BaseDirectory, "engine", "tunnelpick-engine.exe");

    /// <summary>
    /// Starts the engine as a child of this process, which must be elevated: the child inherits the elevation,
    /// so Windows asks nothing more. The engine exits by itself when this process does, and only
    /// <paramref name="userSid"/> may talk to it.
    /// </summary>
    /// <exception cref="EngineException">The engine is missing or could not be started.</exception>
    public static Process Start(string userSid, string dataDir)
    {
        if (!File.Exists(ExePath))
        {
            throw new EngineException($"The engine was not found at {ExePath}.");
        }

        var info = new ProcessStartInfo(ExePath)
        {
            Arguments = string.Create(CultureInfo.InvariantCulture,
                $"run --allow-sid {userSid} --data-dir \"{dataDir}\" --parent-pid {Environment.ProcessId}"),
            WorkingDirectory = Path.GetDirectoryName(ExePath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        try
        {
            return Process.Start(info) ?? throw new EngineException("The engine did not start.");
        }
        catch (Win32Exception ex)
        {
            throw new EngineException($"The engine could not be started: {ex.Message}");
        }
    }
}
