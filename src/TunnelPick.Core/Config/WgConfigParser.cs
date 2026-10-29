using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace TunnelPick.Core.Config;

/// <summary>
/// Parses WireGuard <c>.conf</c> text. Nothing in the file is ever executed. Fields that cannot be
/// honoured are reported, never dropped silently: harmless wg-quick extras become warnings, and
/// fields whose absence would change behaviour (such as AmneziaWG obfuscation) become errors.
/// </summary>
public static class WgConfigParser
{
    private static readonly HashSet<string> CommandKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "PreUp", "PostUp", "PreDown", "PostDown",
    };

    private static readonly HashSet<string> WgQuickOnlyKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Table", "FwMark", "SaveConfig",
    };

    // AmneziaWG extensions change the wire format; a plain WireGuard engine cannot talk to such a server.
    private static readonly HashSet<string> ObfuscationKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "I1", "I2", "I3", "I4", "I5", "J1", "J2", "J3", "Itime",
    };

    public static ParseResult Parse(string text)
    {
        var errors = new List<ConfigIssue>();
        var warnings = new List<ConfigIssue>();

        var iface = new InterfaceBuilder();
        var peers = new List<PeerBuilder>();
        object? current = null;
        var interfaceSections = 0;

        var lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var lineNo = i + 1;
            var line = StripComment(lines[i]).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('['))
            {
                if (!line.EndsWith(']'))
                {
                    errors.Add(new(lineNo, "malformed section header"));
                    current = null;
                    continue;
                }

                var name = line[1..^1].Trim();
                if (name.Equals("Interface", StringComparison.OrdinalIgnoreCase))
                {
                    interfaceSections++;
                    if (interfaceSections > 1)
                    {
                        errors.Add(new(lineNo, "more than one [Interface] section"));
                    }

                    current = iface;
                }
                else if (name.Equals("Peer", StringComparison.OrdinalIgnoreCase))
                {
                    var peer = new PeerBuilder { Line = lineNo };
                    peers.Add(peer);
                    current = peer;
                }
                else
                {
                    errors.Add(new(lineNo, $"unknown section [{name}]"));
                    current = null;
                }

                continue;
            }

            var eq = line.IndexOf('=');
            if (eq <= 0)
            {
                errors.Add(new(lineNo, "expected 'Key = Value'"));
                continue;
            }

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();

            switch (current)
            {
                case null:
                    errors.Add(new(lineNo, $"'{key}' appears outside a section"));
                    break;
                case InterfaceBuilder ib:
                    ib.Set(key, value, lineNo, errors, warnings);
                    break;
                case PeerBuilder pb:
                    pb.Set(key, value, lineNo, errors, warnings);
                    break;
            }
        }

        if (interfaceSections == 0)
        {
            errors.Add(new(0, "missing [Interface] section"));
        }

        if (peers.Count == 0)
        {
            errors.Add(new(0, "no [Peer] section"));
        }

        iface.Validate(errors);
        foreach (var p in peers)
        {
            p.Validate(errors);
        }

        if (errors.Count > 0)
        {
            return new ParseResult(null, errors, warnings);
        }

        var config = new WgConfig(iface.Build(), peers.Select(p => p.Build()).ToList());
        return new ParseResult(config, errors, warnings);
    }

    private static string StripComment(string line)
    {
        var hash = line.IndexOf('#');
        return hash >= 0 ? line[..hash] : line;
    }

    private abstract class Builder
    {
        protected static void UnknownKey(string key, int line, List<ConfigIssue> warnings) =>
            warnings.Add(new(line, $"unknown field '{key}' is ignored"));
    }

    private sealed class InterfaceBuilder : Builder
    {
        private string? _privateKey;
        private readonly List<string> _addresses = [];
        private readonly List<string> _dns = [];
        private int? _mtu;
        private int? _listenPort;

        public void Set(string key, string value, int line, List<ConfigIssue> errors, List<ConfigIssue> warnings)
        {
            switch (key.ToLowerInvariant())
            {
                case "privatekey":
                    if (_privateKey is not null)
                    {
                        errors.Add(new(line, "PrivateKey is set twice"));
                        break;
                    }

                    _privateKey = value;
                    if (!IsKey(value))
                    {
                        // The value is deliberately not echoed: it may be a real secret with a typo.
                        errors.Add(new(line, "PrivateKey must be a base64 encoded 32 byte key"));
                    }

                    break;
                case "address":
                    foreach (var part in Split(value))
                    {
                        if (TryNormalizeCidr(part, out var cidr))
                        {
                            _addresses.Add(cidr);
                        }
                        else
                        {
                            errors.Add(new(line, $"invalid Address '{part}'"));
                        }
                    }

                    break;
                case "dns":
                    foreach (var part in Split(value))
                    {
                        if (IPAddress.TryParse(part, out var ip))
                        {
                            _dns.Add(ip.ToString());
                        }
                        else
                        {
                            warnings.Add(new(line, $"DNS search domain '{part}' is ignored; only resolver addresses are used"));
                        }
                    }

                    break;
                case "mtu":
                    if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var mtu) && mtu is >= 576 and <= 1500)
                    {
                        _mtu = mtu;
                    }
                    else
                    {
                        errors.Add(new(line, "MTU must be a number between 576 and 1500"));
                    }

                    break;
                case "listenport":
                    if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is >= 1 and <= 65535)
                    {
                        _listenPort = port;
                    }
                    else
                    {
                        errors.Add(new(line, "ListenPort must be a number between 1 and 65535"));
                    }

                    break;
                default:
                    if (CommandKeys.Contains(key))
                    {
                        warnings.Add(new(line, $"{key} is ignored: TunnelPick never runs commands from an imported file"));
                    }
                    else if (WgQuickOnlyKeys.Contains(key))
                    {
                        warnings.Add(new(line, $"{key} is a wg-quick routing option and has no effect in TunnelPick"));
                    }
                    else if (ObfuscationKeys.Contains(key))
                    {
                        errors.Add(new(line, $"{key} is an AmneziaWG obfuscation setting; this engine speaks plain WireGuard only"));
                    }
                    else
                    {
                        UnknownKey(key, line, warnings);
                    }

                    break;
            }
        }

        public void Validate(List<ConfigIssue> errors)
        {
            if (_privateKey is null)
            {
                errors.Add(new(0, "[Interface] has no PrivateKey"));
            }

            if (_addresses.Count == 0)
            {
                errors.Add(new(0, "[Interface] has no Address"));
            }
        }

        public WgInterface Build() => new(_privateKey!, _addresses, _dns, _mtu, _listenPort);
    }

    private sealed class PeerBuilder : Builder
    {
        public int Line { get; init; }
        private string? _publicKey;
        private string? _presharedKey;
        private string? _endpoint;
        private readonly List<string> _allowed = [];
        private int? _keepalive;

        public void Set(string key, string value, int line, List<ConfigIssue> errors, List<ConfigIssue> warnings)
        {
            switch (key.ToLowerInvariant())
            {
                case "publickey":
                    if (_publicKey is not null)
                    {
                        errors.Add(new(line, "PublicKey is set twice"));
                        break;
                    }

                    _publicKey = value;
                    if (!IsKey(value))
                    {
                        errors.Add(new(line, "PublicKey must be a base64 encoded 32 byte key"));
                    }

                    break;
                case "presharedkey":
                    _presharedKey = value;
                    if (!IsKey(value))
                    {
                        errors.Add(new(line, "PresharedKey must be a base64 encoded 32 byte key"));
                    }

                    break;
                case "endpoint":
                    if (TryParseEndpoint(value, out var endpoint))
                    {
                        _endpoint = endpoint;
                    }
                    else
                    {
                        errors.Add(new(line, $"invalid Endpoint '{value}'; expected host:port"));
                    }

                    break;
                case "allowedips":
                    foreach (var part in Split(value))
                    {
                        if (TryNormalizeCidr(part, out var cidr))
                        {
                            _allowed.Add(cidr);
                        }
                        else
                        {
                            errors.Add(new(line, $"invalid AllowedIPs entry '{part}'"));
                        }
                    }

                    break;
                case "persistentkeepalive":
                    if (value.Equals("off", StringComparison.OrdinalIgnoreCase))
                    {
                        _keepalive = 0;
                    }
                    else if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var ka) && ka is >= 0 and <= 65535)
                    {
                        _keepalive = ka;
                    }
                    else
                    {
                        errors.Add(new(line, "PersistentKeepalive must be 'off' or a number between 0 and 65535"));
                    }

                    break;
                default:
                    UnknownKey(key, line, warnings);
                    break;
            }
        }

        public void Validate(List<ConfigIssue> errors)
        {
            if (_publicKey is null)
            {
                errors.Add(new(Line, "[Peer] has no PublicKey"));
            }

            if (_allowed.Count == 0)
            {
                errors.Add(new(Line, "[Peer] has no AllowedIPs, so no traffic would be routed to it"));
            }
        }

        public WgPeer Build() => new(_publicKey!, _presharedKey, _endpoint, _allowed, _keepalive);
    }

    private static string[] Split(string value) =>
        value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool IsKey(string value)
    {
        Span<byte> buffer = stackalloc byte[48];
        return value.Length == 44
            && Convert.TryFromBase64String(value, buffer, out var written)
            && written == 32;
    }

    /// <summary>Accepts "addr/len" or a bare address (host route) and returns the canonical form.</summary>
    internal static bool TryNormalizeCidr(string text, out string cidr)
    {
        cidr = string.Empty;
        var slash = text.IndexOf('/');
        var addrPart = slash >= 0 ? text[..slash] : text;
        if (!IPAddress.TryParse(addrPart, out var ip))
        {
            return false;
        }

        var max = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        var len = max;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out len) || len > max))
        {
            return false;
        }

        cidr = $"{ip}/{len}";
        return true;
    }

    internal static bool TryParseEndpoint(string text, out string endpoint)
    {
        endpoint = string.Empty;
        string host;
        string portText;
        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']');
            if (close < 0 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return false;
            }

            host = text[1..close];
            portText = text[(close + 2)..];
            if (!IPAddress.TryParse(host, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }
        }
        else
        {
            var colon = text.LastIndexOf(':');
            if (colon <= 0)
            {
                return false;
            }

            host = text[..colon];
            portText = text[(colon + 1)..];
            if (host.Contains(':'))
            {
                return false; // an IPv6 literal must be bracketed
            }

            if (!IPAddress.TryParse(host, out _) && Uri.CheckHostName(host) != UriHostNameType.Dns)
            {
                return false;
            }
        }

        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            return false;
        }

        endpoint = text.StartsWith('[') ? $"[{host}]:{port}" : $"{host}:{port}";
        return true;
    }
}
