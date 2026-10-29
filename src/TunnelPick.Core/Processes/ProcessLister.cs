using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TunnelPick.Core.Processes;

/// <summary>One running process. Created is the FILETIME start time, which makes (Pid, Created) unique.</summary>
public sealed record ProcInfo(uint Pid, string Name, string? Path, ulong Created, string? Limitation);

public static partial class ProcessLister
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    // Processes that send network traffic on behalf of others, so selecting them does not mean
    // "the app I am thinking of".
    private static readonly Dictionary<string, string> SharedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = "Shared Windows service host: it carries traffic for many services, including DNS lookups made on behalf of other apps.",
        ["services.exe"] = "Windows service control manager; it does not carry application traffic.",
        ["system"] = "Kernel traffic cannot be selected.",
    };

    public static IReadOnlyList<ProcInfo> Snapshot()
    {
        var result = new List<ProcInfo>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id is 0 or 4)
                {
                    continue;
                }

                var pid = (uint)p.Id;
                var created = StartTimeOf(pid);
                if (created is null)
                {
                    continue; // exited meanwhile, or not openable at all
                }

                var path = PathOf(pid);
                var name = path is null ? p.ProcessName + ".exe" : System.IO.Path.GetFileName(path);
                string? limitation = null;
                if (path is null)
                {
                    limitation = "Executable path is not readable (protected or elevated process); only this running instance can be selected.";
                }
                else if (SharedHosts.TryGetValue(name, out var note))
                {
                    limitation = note;
                }

                result.Add(new ProcInfo(pid, name, path, created.Value, limitation));
            }
        }

        return result;
    }

    /// <summary>The FILETIME start time of a process, or null when it is gone.</summary>
    public static ulong? StartTimeOf(uint pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return GetProcessTimes(handle, out var creation, out _, out _, out _) ? (ulong)creation : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    public static string? PathOf(uint pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var capacity = 1024;
            var buffer = new char[capacity];
            return QueryFullProcessImageNameW(handle, 0, buffer, ref capacity)
                ? new string(buffer, 0, capacity)
                : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(IntPtr handle, uint flags, [Out] char[] buffer, ref int size);
}
