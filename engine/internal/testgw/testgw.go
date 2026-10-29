// Package testgw is a WireGuard gateway used by the integration tests. It lives on loopback
// and offers services that are reachable only through the tunnel (10.99.0.1).
package testgw

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"github.com/silverdragon101195/TunnelPick/engine/internal/tunnel"
)

const (
	GatewayIP = "10.99.0.1"
	ClientIP  = "10.99.0.2"
	Marker    = "VPN-SIDE"
)

// Gateway is the VPN-side peer plus the services behind it.
type Gateway struct {
	T      *tunnel.Tunnel
	Port   int
	Client tunnel.Config // configuration a client needs to reach this gateway
	stop   []func()

	mu       sync.Mutex
	requests []string
}

// Requests returns "path user-agent" for every HTTP request that arrived through the tunnel.
func (g *Gateway) Requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.requests...)
}

func keyPair() (priv, pub string) {
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, _ := curve25519.X25519(k[:], curve25519.Basepoint)
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func freePort() (int, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

// Start brings the gateway up with ephemeral keys. allowedIPs is what the client routes into the tunnel.
func Start(allowedIPs []string, logf tunnel.Logf) (*Gateway, error) {
	cPriv, cPub := keyPair()
	gPriv, gPub := keyPair()
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	t, err := tunnel.Start(context.Background(), tunnel.Config{
		PrivateKey: gPriv,
		Addresses:  []string{GatewayIP + "/24"},
		ListenPort: port,
		Peers:      []tunnel.Peer{{PublicKey: cPub, AllowedIPs: []string{ClientIP + "/32"}}},
	}, logf)
	if err != nil {
		return nil, err
	}
	g := &Gateway{T: t, Port: port}
	g.Client = tunnel.Config{
		PrivateKey: cPriv,
		Addresses:  []string{ClientIP + "/32"},
		DNS:        []string{GatewayIP},
		Peers: []tunnel.Peer{{
			PublicKey: gPub, Endpoint: "127.0.0.1:" + strconv.Itoa(port),
			AllowedIPs: allowedIPs, PersistentKeepalive: 1,
		}},
	}
	if err := g.serve(); err != nil {
		t.Close()
		return nil, err
	}
	return g, nil
}

func (g *Gateway) Close() {
	for _, s := range g.stop {
		s()
	}
	g.T.Close()
}

func (g *Gateway) serve() error {
	n := g.T.Net()

	httpLn, err := n.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		return err
	}
	go http.Serve(httpLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests = append(g.requests, r.URL.RequestURI()+" "+r.UserAgent())
		g.mu.Unlock()
		fmt.Fprintf(w, "%s client=%s", Marker, r.RemoteAddr)
	}))
	g.stop = append(g.stop, func() { httpLn.Close() })

	echo, err := n.ListenUDP(&net.UDPAddr{Port: 5353})
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			k, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), buf[:k]...), from)
		}
	}()
	g.stop = append(g.stop, func() { echo.Close() })

	dnsU, err := n.ListenUDP(&net.UDPAddr{Port: 53})
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			k, from, err := dnsU.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := dnsAnswer(buf[:k]); resp != nil {
				dnsU.WriteTo(resp, from)
			}
		}
	}()
	g.stop = append(g.stop, func() { dnsU.Close() })

	dnsT, err := n.ListenTCP(&net.TCPAddr{Port: 53})
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := dnsT.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				if resp := dnsAnswer(q); resp != nil {
					binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
					c.Write(append(l[:], resp...))
				}
			}()
		}
	}()
	g.stop = append(g.stop, func() { dnsT.Close() })
	return nil
}

// dnsAnswer resolves every *.test name to the gateway address and everything else to NXDOMAIN.
func dnsAnswer(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	i := 12
	var labels []string
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if i+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	i++ // root label
	if i+4 > len(q) {
		return nil
	}
	question := q[12 : i+4]
	name := strings.ToLower(strings.Join(labels, "."))

	resp := make([]byte, 12, 64)
	copy(resp, q[:2]) // id
	if strings.HasSuffix(name, ".test") {
		binary.BigEndian.PutUint16(resp[2:], 0x8180)
		binary.BigEndian.PutUint16(resp[4:], 1)
		binary.BigEndian.PutUint16(resp[6:], 1)
		resp = append(resp, question...)
		ip := netip.MustParseAddr(GatewayIP).As4()
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ip[0], ip[1], ip[2], ip[3])
		return resp
	}
	binary.BigEndian.PutUint16(resp[2:], 0x8183) // NXDOMAIN
	binary.BigEndian.PutUint16(resp[4:], 1)
	return append(resp, question...)
}
