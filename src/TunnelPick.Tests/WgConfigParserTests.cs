using TunnelPick.Core.Config;

namespace TunnelPick.Tests;

public class WgConfigParserTests
{
    // Throw-away keys generated for these tests only.
    private const string PrivateKey = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    private const string PublicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    private const string Preshared = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    private static string Config(string extraInterface = "", string extraPeer = "") => $"""
        [Interface]
        PrivateKey = {PrivateKey}
        Address = 10.2.0.2/32, fd00::2/128
        DNS = 10.2.0.1, example.lan
        MTU = 1380
        {extraInterface}

        [Peer]
        PublicKey = {PublicKey}
        PresharedKey = {Preshared}
        Endpoint = vpn.example.com:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        {extraPeer}
        """;

    [Fact]
    public void ParsesTheCommonFields()
    {
        var r = WgConfigParser.Parse(Config());

        Assert.True(r.Ok, string.Join("; ", r.Errors));
        var c = r.Config!;
        Assert.Equal(["10.2.0.2/32", "fd00::2/128"], c.Interface.Addresses);
        Assert.Equal(["10.2.0.1"], c.Interface.Dns);
        Assert.Equal(1380, c.Interface.Mtu);
        var peer = Assert.Single(c.Peers);
        Assert.Equal(PublicKey, peer.PublicKey);
        Assert.Equal(Preshared, peer.PresharedKey);
        Assert.Equal("vpn.example.com:51820", peer.Endpoint);
        Assert.Equal(["0.0.0.0/0", "::/0"], peer.AllowedIps);
        Assert.Equal(25, peer.PersistentKeepalive);
    }

    [Fact]
    public void ReportsSearchDomainsInsteadOfDroppingThemSilently()
    {
        var r = WgConfigParser.Parse(Config());

        Assert.Contains(r.Warnings, w => w.Message.Contains("example.lan"));
    }

    [Theory]
    [InlineData("PostUp = iptables -A FORWARD -j ACCEPT")]
    [InlineData("PreDown = rm -rf /")]
    public void NeverExecutesCommandsAndSaysSo(string line)
    {
        var r = WgConfigParser.Parse(Config(extraInterface: line));

        Assert.True(r.Ok);
        Assert.Contains(r.Warnings, w => w.Message.Contains("never runs commands"));
    }

    [Fact]
    public void RejectsObfuscationFieldsRatherThanConnectingWithTheWrongProtocol()
    {
        var r = WgConfigParser.Parse(Config(extraInterface: "Jc = 5"));

        Assert.False(r.Ok);
        Assert.Contains(r.Errors, e => e.Message.Contains("AmneziaWG"));
    }

    [Fact]
    public void WarnsAboutUnknownFields()
    {
        var r = WgConfigParser.Parse(Config(extraPeer: "Frobnicate = yes"));

        Assert.True(r.Ok);
        Assert.Contains(r.Warnings, w => w.Message.Contains("Frobnicate"));
    }

    [Fact]
    public void ErrorsNameTheLineAndNeverContainTheKey()
    {
        var text = Config().Replace(PrivateKey, PrivateKey[..^2] + "A");
        var r = WgConfigParser.Parse(text);

        Assert.False(r.Ok);
        var error = Assert.Single(r.Errors, e => e.Message.Contains("PrivateKey"));
        Assert.Equal(2, error.Line);
        Assert.DoesNotContain(PrivateKey[..20], error.ToString());
    }

    [Theory]
    [InlineData("Address = 300.1.1.1/32")]
    [InlineData("Address = 10.0.0.2/40")]
    [InlineData("MTU = 99999")]
    [InlineData("MTU = abc")]
    public void RejectsInvalidInterfaceValues(string line)
    {
        var text = Config().Replace("MTU = 1380", line);
        if (line.StartsWith("Address", StringComparison.Ordinal))
        {
            text = Config().Replace("Address = 10.2.0.2/32, fd00::2/128", line);
        }

        Assert.False(WgConfigParser.Parse(text).Ok);
    }

    [Theory]
    [InlineData("Endpoint = nohostport")]
    [InlineData("Endpoint = host:99999")]
    [InlineData("Endpoint = 2001:db8::1:51820")]
    [InlineData("AllowedIPs = 10.0.0.0/33")]
    [InlineData("PersistentKeepalive = soon")]
    public void RejectsInvalidPeerValues(string line)
    {
        var key = line.Split('=')[0].Trim();
        var text = string.Join('\n', Config().Split('\n').Select(l => l.TrimStart().StartsWith(key, StringComparison.Ordinal) ? line : l));

        Assert.False(WgConfigParser.Parse(text).Ok);
    }

    [Fact]
    public void AcceptsBracketedIpv6EndpointAndBareAddresses()
    {
        var text = Config().Replace("vpn.example.com:51820", "[2001:db8::1]:51820").Replace("0.0.0.0/0, ::/0", "10.0.0.1, 192.168.0.0/16");
        var r = WgConfigParser.Parse(text);

        Assert.True(r.Ok, string.Join("; ", r.Errors));
        Assert.Equal("[2001:db8::1]:51820", r.Config!.Peers[0].Endpoint);
        Assert.Equal(["10.0.0.1/32", "192.168.0.0/16"], r.Config.Peers[0].AllowedIps);
    }

    [Fact]
    public void RequiresInterfaceAndPeer()
    {
        Assert.False(WgConfigParser.Parse("").Ok);
        Assert.False(WgConfigParser.Parse($"[Interface]\nPrivateKey = {PrivateKey}\nAddress = 10.0.0.2/32\n").Ok);
    }

    [Fact]
    public void PeerWithoutAllowedIpsIsAnError()
    {
        var text = string.Join('\n', Config().Split('\n').Where(l => !l.TrimStart().StartsWith("AllowedIPs", StringComparison.Ordinal)));

        Assert.Contains(WgConfigParser.Parse(text).Errors, e => e.Message.Contains("AllowedIPs"));
    }

    [Fact]
    public void SupportsMultiplePeersAndComments()
    {
        var text = Config() + $"\n# second peer\n[Peer]\nPublicKey = {PublicKey}\nAllowedIPs = 10.9.0.0/24 # lan\n";
        var r = WgConfigParser.Parse(text);

        Assert.True(r.Ok, string.Join("; ", r.Errors));
        Assert.Equal(2, r.Config!.Peers.Count);
    }
}
