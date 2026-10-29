package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func newKeyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startPair brings up a gateway-side tunnel (10.99.0.1) and a client-side
// tunnel (10.99.0.2) that talk to each other over loopback UDP.
func startPair(t *testing.T) (client, gateway *Tunnel) {
	t.Helper()
	cPriv, cPub := newKeyPair(t)
	gPriv, gPub := newKeyPair(t)
	port := freeUDPPort(t)
	logf := func(f string, a ...any) { t.Logf(f, a...) }

	gw, err := Start(context.Background(), Config{
		PrivateKey: gPriv,
		Addresses:  []string{"10.99.0.1/24"},
		ListenPort: port,
		Peers:      []Peer{{PublicKey: cPub, AllowedIPs: []string{"10.99.0.2/32"}}},
	}, logf)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	t.Cleanup(gw.Close)

	cl, err := Start(context.Background(), Config{
		PrivateKey: cPriv,
		Addresses:  []string{"10.99.0.2/32"},
		DNS:        []string{"10.99.0.1"},
		Peers: []Peer{{
			PublicKey:           gPub,
			Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			AllowedIPs:          []string{"10.99.0.0/24"},
			PersistentKeepalive: 1,
		}},
	}, logf)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(cl.Close)
	return cl, gw
}

func TestTCPThroughTunnel(t *testing.T) {
	client, gateway := startPair(t)

	ln, err := gateway.Net().ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "via-tunnel from "+r.RemoteAddr)
	}))

	hc := &http.Client{Transport: &http.Transport{DialContext: client.Net().DialContext}, Timeout: 15 * time.Second}
	resp, err := hc.Get("http://10.99.0.1/")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "via-tunnel from 10.99.0.2:"+portOf(got) {
		t.Fatalf("unexpected body %q", got)
	}

	st := client.Stats()
	if st.LastHandshake.IsZero() || st.RxBytes == 0 || st.TxBytes == 0 {
		t.Fatalf("stats not populated: %+v", st)
	}

	// The same address is not reachable without the tunnel.
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	if c, err := d.Dial("tcp", "10.99.0.1:80"); err == nil {
		c.Close()
		t.Fatal("10.99.0.1 must not be reachable outside the tunnel")
	}
}

func portOf(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[i+1:]
		}
	}
	return ""
}

func TestUDPThroughTunnel(t *testing.T) {
	client, gateway := startPair(t)

	pc, err := gateway.Net().ListenUDP(&net.UDPAddr{Port: 5353})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	conn, err := client.Net().DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.99.0.1:5353"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestRoutedHonoursAllowedIPs(t *testing.T) {
	client, _ := startPair(t)
	if !client.Routed(netip.MustParseAddr("10.99.0.7")) {
		t.Fatal("10.99.0.7 should be routed")
	}
	if client.Routed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("8.8.8.8 should not be routed")
	}
}

func TestValidateRejectsBadConfig(t *testing.T) {
	priv, pub := newKeyPair(t)
	ok := Config{PrivateKey: priv, Addresses: []string{"10.0.0.2/32"},
		Peers: []Peer{{PublicKey: pub, Endpoint: "example.com:51820", AllowedIPs: []string{"0.0.0.0/0"}}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := ok
	bad.PrivateKey = "not-a-key"
	if bad.Validate() == nil {
		t.Fatal("bad private key accepted")
	}
	bad = ok
	bad.Peers = nil
	if bad.Validate() == nil {
		t.Fatal("missing peer accepted")
	}
	bad = ok
	bad.MTU = 100
	if bad.Validate() == nil {
		t.Fatal("bad mtu accepted")
	}
}
