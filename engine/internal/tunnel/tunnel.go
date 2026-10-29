// Package tunnel runs an in-process WireGuard device on top of a userspace
// network stack, so traffic can be dialled through the tunnel without a
// virtual adapter or any change to the system routing table.
package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Config is the normalised WireGuard configuration handed over by the UI.
type Config struct {
	PrivateKey string   `json:"privateKey"` // base64
	Addresses  []string `json:"addresses"`  // CIDR, e.g. 10.0.0.2/32
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	Peers      []Peer   `json:"peers"`
	// ListenPort pins the local UDP port; 0 lets the OS choose. Only a
	// gateway-side peer (and the tests) needs a fixed port.
	ListenPort int `json:"listenPort,omitempty"`
}

type Peer struct {
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey,omitempty"`
	Endpoint            string   `json:"endpoint"` // host:port
	AllowedIPs          []string `json:"allowedIps"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

// Stats is a point-in-time snapshot of the tunnel counters.
type Stats struct {
	RxBytes       uint64    `json:"rxBytes"`
	TxBytes       uint64    `json:"txBytes"`
	LastHandshake time.Time `json:"lastHandshake"` // zero when no handshake happened yet
}

// Tunnel is a running WireGuard device plus its userspace network stack.
type Tunnel struct {
	net     *netstack.Net
	dev     *device.Device
	routes  []netip.Prefix
	dns     []netip.Addr
	hasV6   bool
	closeMu sync.Once
}

// Logf receives diagnostic lines; it must redact secrets itself.
type Logf func(format string, args ...any)

const defaultMTU = 1420

// Validate rejects configurations the engine cannot run.
func (c *Config) Validate() error {
	if _, err := decodeKey(c.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if len(c.Addresses) == 0 {
		return errors.New("interface has no Address")
	}
	for _, a := range c.Addresses {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("address %q: %w", a, err)
		}
	}
	for _, d := range c.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("dns %q: %w", d, err)
		}
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 1500) {
		return fmt.Errorf("mtu %d out of range 576-1500", c.MTU)
	}
	if len(c.Peers) == 0 {
		return errors.New("no peer defined")
	}
	for i, p := range c.Peers {
		if _, err := decodeKey(p.PublicKey); err != nil {
			return fmt.Errorf("peer %d public key: %w", i+1, err)
		}
		if p.PresharedKey != "" {
			if _, err := decodeKey(p.PresharedKey); err != nil {
				return fmt.Errorf("peer %d preshared key: %w", i+1, err)
			}
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d has no AllowedIPs", i+1)
		}
		for _, ip := range p.AllowedIPs {
			if _, err := netip.ParsePrefix(ip); err != nil {
				return fmt.Errorf("peer %d allowed ip %q: %w", i+1, ip, err)
			}
		}
		if p.Endpoint != "" {
			if _, _, err := net.SplitHostPort(p.Endpoint); err != nil {
				return fmt.Errorf("peer %d endpoint %q: %w", i+1, p.Endpoint, err)
			}
		}
	}
	return nil
}

func decodeKey(b64 string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(k) != 32 {
		return nil, errors.New("must be a base64 encoded 32 byte key")
	}
	return k, nil
}

// Start brings the tunnel up. Endpoint host names are resolved here, on the
// normal network, because the tunnel does not exist yet.
func Start(ctx context.Context, cfg Config, logf Logf) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	var local []netip.Addr
	hasV6 := false
	for _, a := range cfg.Addresses {
		p, _ := netip.ParsePrefix(a)
		local = append(local, p.Addr())
		if p.Addr().Is6() {
			hasV6 = true
		}
	}
	var dns []netip.Addr
	for _, d := range cfg.DNS {
		a, _ := netip.ParseAddr(d)
		dns = append(dns, a)
	}

	tun, tnet, err := netstack.CreateNetTUN(local, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %w", err)
	}

	uapi, routes, err := buildUAPI(ctx, cfg)
	if err != nil {
		tun.Close()
		return nil, err
	}

	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { logf("wireguard: "+f, a...) },
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}
	return &Tunnel{net: tnet, dev: dev, routes: routes, dns: dns, hasV6: hasV6}, nil
}

func buildUAPI(ctx context.Context, cfg Config) (string, []netip.Prefix, error) {
	var sb strings.Builder
	priv, _ := decodeKey(cfg.PrivateKey)
	sb.WriteString("private_key=" + hex.EncodeToString(priv) + "\n")
	if cfg.ListenPort > 0 {
		sb.WriteString("listen_port=" + strconv.Itoa(cfg.ListenPort) + "\n")
	}
	sb.WriteString("replace_peers=true\n")
	var routes []netip.Prefix
	for _, p := range cfg.Peers {
		pub, _ := decodeKey(p.PublicKey)
		sb.WriteString("public_key=" + hex.EncodeToString(pub) + "\n")
		if p.PresharedKey != "" {
			psk, _ := decodeKey(p.PresharedKey)
			sb.WriteString("preshared_key=" + hex.EncodeToString(psk) + "\n")
		}
		if p.Endpoint != "" {
			ep, err := resolveEndpoint(ctx, p.Endpoint)
			if err != nil {
				return "", nil, err
			}
			sb.WriteString("endpoint=" + ep + "\n")
		}
		sb.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			pfx, _ := netip.ParsePrefix(ip)
			routes = append(routes, pfx.Masked())
			sb.WriteString("allowed_ip=" + ip + "\n")
		}
		if p.PersistentKeepalive > 0 {
			sb.WriteString("persistent_keepalive_interval=" + strconv.Itoa(p.PersistentKeepalive) + "\n")
		}
	}
	return sb.String(), routes, nil
}

func resolveEndpoint(ctx context.Context, hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("endpoint port %q: %w", port, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, uint16(p)).String(), nil
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve endpoint %q: %v", host, err)
	}
	// Prefer IPv4: the engine's own WireGuard socket must work on every network.
	pick := ips[0]
	for _, ip := range ips {
		if ip.Is4() {
			pick = ip
			break
		}
	}
	return netip.AddrPortFrom(pick.Unmap(), uint16(p)).String(), nil
}

// Net returns the userspace stack used to dial through the tunnel.
func (t *Tunnel) Net() *netstack.Net { return t.net }

// DNS returns the resolvers configured for the tunnel.
func (t *Tunnel) DNS() []netip.Addr { return t.dns }

// HasIPv6 reports whether the tunnel interface owns an IPv6 address.
func (t *Tunnel) HasIPv6() bool { return t.hasV6 }

// Routed reports whether ip is covered by a peer's AllowedIPs.
func (t *Tunnel) Routed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, r := range t.routes {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// Stats reads the counters from the device. It never exposes key material.
func (t *Tunnel) Stats() Stats {
	var s Stats
	dump, err := t.dev.IpcGet()
	if err != nil {
		return s
	}
	var sec, nsec int64
	sc := bufio.NewScanner(strings.NewReader(dump))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "rx_bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			s.RxBytes += n
		case "tx_bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			s.TxBytes += n
		case "last_handshake_time_sec":
			n, _ := strconv.ParseInt(v, 10, 64)
			if n > sec {
				sec = n
			}
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if sec > 0 {
		s.LastHandshake = time.Unix(sec, nsec)
	}
	return s
}

// Close tears the device down. It is safe to call more than once.
func (t *Tunnel) Close() {
	t.closeMu.Do(func() { t.dev.Close() })
}
