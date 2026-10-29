using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TunnelPick.Core.Policy;
using TunnelPick.Core.Storage;

namespace TunnelPick.Core.Engine;

/// <summary>Talks to the engine over its named pipe (newline delimited JSON, one request at a time).</summary>
public sealed class EngineClient : IDisposable
{
    public const string PipeName = "TunnelPick";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private long _nextId;

    private async Task EnsureConnectedAsync(CancellationToken ct)
    {
        if (_pipe is { IsConnected: true })
        {
            return;
        }

        CloseConnection();
        var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(1500, ct).ConfigureAwait(false);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _pipe = pipe;
        _reader = new StreamReader(pipe, new UTF8Encoding(false), false, 64 * 1024, leaveOpen: true);
    }

    private void CloseConnection()
    {
        _reader?.Dispose();
        _pipe?.Dispose();
        _reader = null;
        _pipe = null;
    }

    private async Task<JsonElement> CallAsync(string cmd, object? parameters, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EnsureConnectedAsync(ct).ConfigureAwait(false);
            var id = ++_nextId;
            var request = JsonSerializer.Serialize(new { id, cmd, @params = parameters }, Json) + "\n";
            try
            {
                await _pipe!.WriteAsync(Encoding.UTF8.GetBytes(request), ct).ConfigureAwait(false);
                await _pipe.FlushAsync(ct).ConfigureAwait(false);
                var line = await _reader!.ReadLineAsync(ct).ConfigureAwait(false)
                    ?? throw new IOException("engine closed the connection");
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                if (!root.GetProperty("ok").GetBoolean())
                {
                    var error = root.TryGetProperty("error", out var e) ? e.GetString() : null;
                    throw new EngineException(error ?? "engine reported an error");
                }

                return root.TryGetProperty("data", out var data) ? data.Clone() : default;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                CloseConnection();
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>True when the engine answers on its pipe.</summary>
    public async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        try
        {
            await CallAsync("ping", null, ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException or EngineException)
        {
            return false;
        }
    }

    public async Task<EngineStatus> StatusAsync(CancellationToken ct = default) =>
        (await CallAsync("status", null, ct).ConfigureAwait(false)).Deserialize<EngineStatus>(Json) ?? new EngineStatus();

    public Task ConnectAsync(EngineConfig config, CancellationToken ct = default) => CallAsync("connect", config, ct);

    public Task DisconnectAsync(CancellationToken ct = default) => CallAsync("disconnect", null, ct);

    /// <summary>Asks the engine to exit. It answers first, so the call returns normally.</summary>
    public Task ShutdownAsync(CancellationToken ct = default) => CallAsync("shutdown", null, ct);

    public Task SetPolicyAsync(PolicySet set, CancellationToken ct = default) => CallAsync("setPolicy", set, ct);

    public async Task<IReadOnlyList<string>> LogsAsync(int count, CancellationToken ct = default) =>
        (await CallAsync("logs", new { n = count }, ct).ConfigureAwait(false)).Deserialize<List<string>>(Json) ?? [];

    public async Task<IReadOnlyList<FlowInfo>> FlowsAsync(CancellationToken ct = default) =>
        (await CallAsync("flows", null, ct).ConfigureAwait(false)).Deserialize<List<FlowInfo>>(Json) ?? [];

    /// <summary>The public address the VPN server presents, fetched through the tunnel.</summary>
    public async Task<string> EgressIpAsync(CancellationToken ct = default)
    {
        var data = await CallAsync("egress", null, ct).ConfigureAwait(false);
        return data.GetProperty("ip").GetString() ?? "";
    }

    public void Dispose()
    {
        CloseConnection();
        _gate.Dispose();
    }
}
