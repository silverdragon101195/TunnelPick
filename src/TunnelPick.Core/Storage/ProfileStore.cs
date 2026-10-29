using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TunnelPick.Core.Config;

namespace TunnelPick.Core.Storage;

public sealed class StoredPeer
{
    public string PublicKey { get; set; } = "";
    public string? PresharedKeyProtected { get; set; }
    public string? Endpoint { get; set; }
    public List<string> AllowedIps { get; set; } = [];
    public int? PersistentKeepalive { get; set; }
}

/// <summary>A profile as written to disk. Secrets are only ever stored DPAPI-protected.</summary>
public sealed class StoredProfile
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTimeOffset ImportedAt { get; set; }
    public string PrivateKeyProtected { get; set; } = "";
    public List<string> Addresses { get; set; } = [];
    public List<string> Dns { get; set; } = [];
    public int? Mtu { get; set; }
    public int? ListenPort { get; set; }
    public List<StoredPeer> Peers { get; set; } = [];

    public override string ToString() => Name;
}

/// <summary>The configuration object the engine expects over IPC (secrets in clear, never persisted).</summary>
public sealed class EngineConfig
{
    public string PrivateKey { get; set; } = "";
    public List<string> Addresses { get; set; } = [];
    public List<string> Dns { get; set; } = [];
    public int Mtu { get; set; }
    public int ListenPort { get; set; }
    public List<EnginePeer> Peers { get; set; } = [];
}

public sealed class EnginePeer
{
    public string PublicKey { get; set; } = "";
    public string? PresharedKey { get; set; }
    public string Endpoint { get; set; } = "";
    public List<string> AllowedIps { get; set; } = [];
    public int PersistentKeepalive { get; set; }
}

public sealed class ProfileStore(string directory)
{
    // Extra entropy ties the protected blobs to this application, not just to the Windows user.
    private static readonly byte[] Entropy = "TunnelPick.profile.v1"u8.ToArray();

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public IReadOnlyList<StoredProfile> List()
    {
        if (!Directory.Exists(directory))
        {
            return [];
        }

        var result = new List<StoredProfile>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var profile = JsonSerializer.Deserialize<StoredProfile>(File.ReadAllText(file), Json);
                if (profile is not null && profile.Id.Length > 0)
                {
                    result.Add(profile);
                }
            }
            catch (JsonException)
            {
                // A damaged file must not hide the other profiles.
            }
        }

        return result;
    }

    /// <summary>The profile Connect uses: the one marked active, or null when none is (or the marked one is gone).</summary>
    public StoredProfile? GetActive()
    {
        var id = ReadActiveId();
        return id is null ? null : List().FirstOrDefault(p => p.Id == id);
    }

    /// <summary>Marks a stored profile as the one Connect uses.</summary>
    public void SetActive(string id)
    {
        PathFor(id);
        Directory.CreateDirectory(directory);
        File.WriteAllText(ActivePath, id);
    }

    /// <summary>Saves a new profile. The first profile ever stored becomes the active one.</summary>
    public StoredProfile Save(WgConfig config, string name)
    {
        Directory.CreateDirectory(directory);
        var profile = new StoredProfile
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
            ImportedAt = DateTimeOffset.UtcNow,
            PrivateKeyProtected = Protect(config.Interface.PrivateKey),
            Addresses = [.. config.Interface.Addresses],
            Dns = [.. config.Interface.Dns],
            Mtu = config.Interface.Mtu,
            ListenPort = config.Interface.ListenPort,
            Peers = config.Peers.Select(p => new StoredPeer
            {
                PublicKey = p.PublicKey,
                PresharedKeyProtected = p.PresharedKey is null ? null : Protect(p.PresharedKey),
                Endpoint = p.Endpoint,
                AllowedIps = [.. p.AllowedIps],
                PersistentKeepalive = p.PersistentKeepalive,
            }).ToList(),
        };
        File.WriteAllText(PathFor(profile.Id), JsonSerializer.Serialize(profile, Json));
        if (GetActive() is null)
        {
            SetActive(profile.Id);
        }

        return profile;
    }

    /// <summary>Deletes a profile. When it was the active one, the first remaining profile becomes active.</summary>
    public void Delete(string id)
    {
        var path = PathFor(id);
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        if (ReadActiveId() == id)
        {
            File.Delete(ActivePath);
            var remaining = List();
            if (remaining.Count > 0)
            {
                SetActive(remaining[0].Id);
            }
        }
    }

    public static EngineConfig ToEngineConfig(StoredProfile profile) => new()
    {
        PrivateKey = Unprotect(profile.PrivateKeyProtected),
        Addresses = [.. profile.Addresses],
        Dns = [.. profile.Dns],
        Mtu = profile.Mtu ?? 0,
        ListenPort = profile.ListenPort ?? 0,
        Peers = profile.Peers.Select(p => new EnginePeer
        {
            PublicKey = p.PublicKey,
            PresharedKey = p.PresharedKeyProtected is null ? null : Unprotect(p.PresharedKeyProtected),
            Endpoint = p.Endpoint ?? "",
            AllowedIps = [.. p.AllowedIps],
            PersistentKeepalive = p.PersistentKeepalive ?? 0,
        }).ToList(),
    };

    // Not a *.json file, so List() never mistakes it for a profile.
    private string ActivePath => Path.Combine(directory, "active.txt");

    private string? ReadActiveId()
    {
        try
        {
            return File.Exists(ActivePath) ? File.ReadAllText(ActivePath).Trim() : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private string PathFor(string id)
    {
        // Ids are generated here; reject anything that could escape the directory.
        if (id.Any(c => !char.IsAsciiLetterOrDigit(c)))
        {
            throw new ArgumentException("invalid profile id", nameof(id));
        }

        return Path.Combine(directory, id + ".json");
    }

    internal static string Protect(string secret) =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), Entropy, DataProtectionScope.CurrentUser));

    internal static string Unprotect(string blob) =>
        Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob), Entropy, DataProtectionScope.CurrentUser));
}
