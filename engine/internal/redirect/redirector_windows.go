// Package redirect diverts the traffic of selected processes into the WireGuard tunnel.
//
// Outbound packets are captured with WinDivert at the network layer. The owner of each new
// flow is looked up in the IP Helper socket tables; flows of selected processes are either
// bounced to a local TCP relay (TCP) or carried as datagrams over a tunnel socket (UDP).
// Everything else is re-injected unchanged. A selected flow is never re-injected as-is:
// when the tunnel is down or the destination is not routed it is reset or dropped.
package redirect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/silverdragon101195/TunnelPick/engine/internal/policy"
	"github.com/silverdragon101195/TunnelPick/engine/internal/tunnel"
	"github.com/silverdragon101195/TunnelPick/engine/internal/windivert"
)

type action int

const (
	actPass action = iota
	actBlock
	actTunnel
)

const (
	tcpIdle      = 3 * time.Minute
	udpIdle      = 90 * time.Second
	cacheIdle    = 2 * time.Minute
	blockRecheck = 2 * time.Second // blocked UDP is re-evaluated so it can recover when the tunnel returns
)

type flowKey struct {
	udp bool
	src netip.AddrPort
	dst netip.AddrPort // zero for TCP: the source port identifies the connection
}

type cacheEntry struct {
	act  action
	last time.Time
}

type tcpFlow struct {
	src  netip.AddrPort
	orig netip.AddrPort
	pid  uint32
	rule string
	last atomic.Int64 // unix nano
	done atomic.Bool  // relay finished
}

type udpFlow struct {
	src, dst netip.AddrPort
	ifIdx    uint32
	pid      uint32
	rule     string
	conn     net.Conn
	last     atomic.Int64
}

// Stats counts what the redirector did since it started.
type Stats struct {
	Active           bool   `json:"active"` // WinDivert handle open
	TCPFlows         int    `json:"tcpFlows"`
	UDPFlows         int    `json:"udpFlows"`
	BlockedTCP       uint64 `json:"blockedTcp"`
	BlockedUDP       uint64 `json:"blockedUdp"`
	BlockedIPv6      uint64 `json:"blockedIpv6"`
	PreexistingReset uint64 `json:"preexistingDropped"`
	OutsideRoutes    uint64 `json:"outsideAllowedIps"`
	RefusedTunnelOff uint64 `json:"refusedTunnelDown"`
}

// FlowInfo describes one flow currently carried by the tunnel.
type FlowInfo struct {
	Proto string `json:"proto"`
	PID   uint32 `json:"pid"`
	Exe   string `json:"exe"`
	Dst   string `json:"dst"`
	Rule  string `json:"rule"`
}

type Redirector struct {
	logf    func(string, ...any)
	procs   policy.Resolver
	selfPID uint32

	rules atomic.Pointer[policy.Set]
	tun   atomic.Pointer[tunnel.Tunnel]

	relay     net.Listener
	relayPort uint16

	mu  sync.Mutex
	tcp map[netip.AddrPort]*tcpFlow
	udp map[flowKey]*udpFlow

	hmu sync.Mutex // guards h and serialises sends
	h   *windivert.Handle

	cmu   sync.Mutex
	cache map[flowKey]*cacheEntry // per-flow decisions for flows that are not tunnelled

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	logMu   sync.Mutex
	logLast map[string]time.Time

	blockedTCP, blockedUDP, blockedV6, preexisting, outside, tunnelOff atomic.Uint64
}

// New starts the local relay. WinDivert itself is opened on demand by SetPolicy.
func New(procs policy.Resolver, logf func(string, ...any)) (*Redirector, error) {
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Redirector{
		logf: logf, procs: procs, selfPID: uint32(os.Getpid()),
		relay: ln, relayPort: uint16(ln.Addr().(*net.TCPAddr).Port),
		tcp: map[netip.AddrPort]*tcpFlow{}, udp: map[flowKey]*udpFlow{},
		cache: map[flowKey]*cacheEntry{}, ctx: ctx, cancel: cancel,
		logLast: map[string]time.Time{},
	}
	r.rules.Store(&policy.Set{})
	r.wg.Add(2)
	go r.acceptLoop()
	go r.gcLoop()
	return r, nil
}

// SetTunnel installs (or, with nil, removes) the tunnel selected flows are sent into.
func (r *Redirector) SetTunnel(t *tunnel.Tunnel) { r.tun.Store(t) }

// SetPolicy replaces the rule set. Existing tunnelled flows keep their route until they end;
// the new rules apply to connections opened afterwards.
func (r *Redirector) SetPolicy(s *policy.Set) error {
	r.rules.Store(s)
	// Cached pass/block decisions were made under the old rules. Dropping them makes packets of
	// connections that already exist be judged again, so a newly selected process is cut off from
	// its old direct connections instead of keeping them.
	r.cmu.Lock()
	r.cache = map[flowKey]*cacheEntry{}
	r.cmu.Unlock()
	return r.syncHandle()
}

func (r *Redirector) syncHandle() error {
	r.hmu.Lock()
	defer r.hmu.Unlock()
	if r.h != nil || r.rules.Load().Enabled() == 0 {
		return nil
	}
	// Priority 0 keeps this handle below any other WinDivert user's.
	h, err := windivert.Open("outbound and (tcp or udp)", windivert.LayerNetwork, 0, 0)
	if err != nil {
		return err
	}
	r.h = h
	r.wg.Add(1)
	go r.loop(h)
	r.logf("redirector active: relay port %d", r.relayPort)
	return nil
}

func (r *Redirector) closeHandleLocked() {
	if r.h == nil {
		return
	}
	r.h.Shutdown()
	r.h.Close()
	r.h = nil
}

// Close stops redirecting. Packets of selected processes are no longer held back.
func (r *Redirector) Close() {
	r.cancel()
	r.relay.Close()
	r.hmu.Lock()
	r.closeHandleLocked()
	r.hmu.Unlock()
	r.mu.Lock()
	for _, f := range r.udp {
		f.conn.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *Redirector) Stats() Stats {
	r.hmu.Lock()
	active := r.h != nil
	r.hmu.Unlock()
	r.mu.Lock()
	tcp, udp := len(r.tcp), len(r.udp)
	r.mu.Unlock()
	return Stats{Active: active, TCPFlows: tcp, UDPFlows: udp,
		BlockedTCP: r.blockedTCP.Load(), BlockedUDP: r.blockedUDP.Load(), BlockedIPv6: r.blockedV6.Load(),
		PreexistingReset: r.preexisting.Load(), OutsideRoutes: r.outside.Load(), RefusedTunnelOff: r.tunnelOff.Load()}
}

// Flows lists the flows currently carried by the tunnel.
func (r *Redirector) Flows() []FlowInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]FlowInfo, 0, len(r.tcp)+len(r.udp))
	for _, f := range r.tcp {
		out = append(out, FlowInfo{"tcp", f.pid, r.exe(f.pid), f.orig.String(), f.rule})
	}
	for _, f := range r.udp {
		out = append(out, FlowInfo{"udp", f.pid, r.exe(f.pid), f.dst.String(), f.rule})
	}
	return out
}

func (r *Redirector) exe(pid uint32) string {
	if p, ok := r.procs.Lookup(pid); ok {
		return p.Path
	}
	return ""
}

// rateLog emits a line at most once per interval for the same key.
func (r *Redirector) rateLog(key string, every time.Duration, format string, args ...any) {
	r.logMu.Lock()
	last := r.logLast[key]
	if time.Since(last) < every {
		r.logMu.Unlock()
		return
	}
	r.logLast[key] = time.Now()
	r.logMu.Unlock()
	r.logf(format, args...)
}

// ---- packet loop ----------------------------------------------------------------------

func (r *Redirector) loop(h *windivert.Handle) {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	var addr windivert.Address
	for {
		n, err := h.Recv(buf, &addr)
		if err != nil {
			if r.ctx.Err() != nil || !r.isCurrent(h) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		r.handle(buf[:n], &addr)
	}
}

func (r *Redirector) isCurrent(h *windivert.Handle) bool {
	r.hmu.Lock()
	defer r.hmu.Unlock()
	return r.h == h
}

func (r *Redirector) send(pkt []byte, addr *windivert.Address) {
	r.hmu.Lock()
	h := r.h
	if h != nil {
		h.Send(pkt, addr)
	}
	r.hmu.Unlock()
}

func (r *Redirector) sendChecked(p *packet, addr *windivert.Address) {
	windivert.CalcChecksums(p.raw, addr)
	r.send(p.raw, addr)
}

func (r *Redirector) handle(pkt []byte, addr *windivert.Address) {
	p, ok := parse(pkt)
	if !ok || p.frag {
		r.send(pkt, addr)
		return
	}
	if p.proto == protoTCP {
		r.handleTCP(&p, addr)
	} else {
		r.handleUDP(&p, addr)
	}
}

func (r *Redirector) lookupTCP(k netip.AddrPort) *tcpFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tcp[k]
}

func (r *Redirector) handleTCP(p *packet, addr *windivert.Address) {
	now := time.Now()

	// Reply travelling from the relay back to the client: make it look like the remote server.
	if p.sport == r.relayPort && !p.v6 {
		if f := r.lookupTCP(netip.AddrPortFrom(p.dst, p.dport)); f != nil {
			f.last.Store(now.UnixNano())
			p.setSrc(f.orig.Addr(), f.orig.Port())
			addr.SetOutbound(false)
			r.sendChecked(p, addr)
			return
		}
	}

	src := netip.AddrPortFrom(p.src, p.sport)
	flags := p.tcpFlags()
	isSYN := flags&tcpSYN != 0 && flags&tcpACK == 0

	if f := r.lookupTCP(src); f != nil && f.orig == netip.AddrPortFrom(p.dst, p.dport) {
		f.last.Store(now.UnixNano())
		r.bounceToRelay(p, addr)
		return
	}

	key := flowKey{src: src}
	if !isSYN {
		if c, ok := r.cacheGet(key); ok {
			if c.act == actPass {
				r.cacheTouch(key, now)
				r.send(p.raw, addr)
			} else if flags&tcpRST == 0 && !p.v6 {
				r.reset(p, addr)
			}
			return
		}
	}

	act, pid, rule := r.classify(p)
	switch act {
	case actPass:
		r.cachePut(key, actPass, now)
		r.send(p.raw, addr)
	case actBlock:
		r.cachePut(key, actBlock, now)
		r.blockedTCP.Add(1)
		if flags&tcpRST == 0 && !p.v6 {
			r.reset(p, addr)
		}
	case actTunnel:
		if !isSYN {
			// The connection was opened before it was selected. It cannot be moved into the tunnel,
			// so it is cut; the application reconnects and the new connection goes through the tunnel.
			r.cachePut(key, actBlock, now)
			r.preexisting.Add(1)
			r.rateLog("pre", 5*time.Second, "reset an existing connection of pid %d; it must reconnect to use the VPN", pid)
			if flags&tcpRST == 0 && !p.v6 {
				r.reset(p, addr)
			}
			return
		}
		r.cacheDel(key)
		f := &tcpFlow{src: src, orig: netip.AddrPortFrom(p.dst, p.dport), pid: pid, rule: rule}
		f.last.Store(now.UnixNano())
		r.mu.Lock()
		r.tcp[src] = f
		r.mu.Unlock()
		r.bounceToRelay(p, addr)
	}
}

// bounceToRelay turns an outbound client segment into an inbound one aimed at the local relay.
func (r *Redirector) bounceToRelay(p *packet, addr *windivert.Address) {
	p.setDst(p.src, r.relayPort)
	addr.SetOutbound(false)
	r.sendChecked(p, addr)
}

func (r *Redirector) reset(p *packet, addr *windivert.Address) {
	rst := buildRST4(p)
	a := windivert.Address{IfIdx: addr.IfIdx, SubIfIdx: addr.SubIfIdx}
	windivert.CalcChecksums(rst, &a)
	r.send(rst, &a)
}

func (r *Redirector) handleUDP(p *packet, addr *windivert.Address) {
	now := time.Now()
	src := netip.AddrPortFrom(p.src, p.sport)
	dst := netip.AddrPortFrom(p.dst, p.dport)
	key := flowKey{udp: true, src: src, dst: dst}

	r.mu.Lock()
	f := r.udp[key]
	r.mu.Unlock()
	if f != nil {
		f.last.Store(now.UnixNano())
		f.conn.Write(p.raw[p.payload:])
		return
	}
	if c, ok := r.cacheGet(key); ok {
		if c.act == actPass {
			r.cacheTouch(key, now)
			r.send(p.raw, addr)
			return
		}
		if now.Sub(c.last) < blockRecheck {
			r.blockedUDP.Add(1)
			return
		}
	}

	act, pid, rule := r.classify(p)
	switch act {
	case actPass:
		r.cachePut(key, actPass, now)
		r.send(p.raw, addr)
	case actBlock:
		r.cachePut(key, actBlock, now)
		r.blockedUDP.Add(1)
	case actTunnel:
		tun := r.tun.Load()
		if tun == nil {
			r.cachePut(key, actBlock, now)
			r.tunnelOff.Add(1)
			r.blockedUDP.Add(1)
			r.rateLog("udpoff", 5*time.Second, "dropped UDP from pid %d: tunnel is down", pid)
			return
		}
		target := dst
		if dst.Port() == 53 && len(tun.DNS()) > 0 {
			target = netip.AddrPortFrom(tun.DNS()[0], 53)
		}
		conn, err := tun.Net().DialUDPAddrPort(netip.AddrPort{}, target)
		if err != nil {
			r.blockedUDP.Add(1)
			r.rateLog("udpdial", 5*time.Second, "tunnel UDP dial failed for pid %d: %v", pid, err)
			return
		}
		nf := &udpFlow{src: src, dst: dst, ifIdx: addr.IfIdx, pid: pid, rule: rule, conn: conn}
		nf.last.Store(now.UnixNano())
		r.mu.Lock()
		r.udp[key] = nf
		r.mu.Unlock()
		r.wg.Add(1)
		go r.udpReadLoop(key, nf)
		conn.Write(p.raw[p.payload:])
	}
}

func (r *Redirector) udpReadLoop(key flowKey, f *udpFlow) {
	defer r.wg.Done()
	defer func() {
		f.conn.Close()
		r.mu.Lock()
		if r.udp[key] == f {
			delete(r.udp, key)
		}
		r.mu.Unlock()
	}()
	buf := make([]byte, 65535)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			return
		}
		f.last.Store(time.Now().UnixNano())
		b := buildUDP4(f.dst, f.src, buf[:n])
		a := windivert.Address{IfIdx: f.ifIdx}
		windivert.CalcChecksums(b, &a)
		r.send(b, &a)
	}
}

// classify decides what happens to the first packet of a flow.
func (r *Redirector) classify(p *packet) (action, uint32, string) {
	set := r.rules.Load()
	if set.Enabled() == 0 {
		return actPass, 0, ""
	}
	pid, ok := ownerPID(p.proto == protoTCP, p.src, p.sport, p.dst, p.dport)
	if !ok || pid == r.selfPID {
		return actPass, pid, ""
	}
	rule, selected := set.Match(r.procs, pid)
	if !selected {
		return actPass, pid, ""
	}

	dst := p.dst.Unmap()
	if dst.IsLoopback() || dst.IsUnspecified() {
		return actPass, pid, rule
	}
	if p.v6 && !dst.Is4() {
		r.blockedV6.Add(1)
		r.rateLog("v6", 10*time.Second, "blocked IPv6 from selected pid %d: the redirector carries IPv4 only", pid)
		return actBlock, pid, rule
	}
	// DNS of a selected process is answered by the tunnel's resolver, whatever server it asked.
	if tun := r.tun.Load(); tun != nil && p.dport == 53 && len(tun.DNS()) > 0 {
		if !tun.Routed(tun.DNS()[0]) {
			r.outside.Add(1)
			return actBlock, pid, rule
		}
		return actTunnel, pid, rule
	}
	local := dst.IsPrivate() || dst.IsLinkLocalUnicast() || dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255})
	if local && set.BypassLAN {
		return actPass, pid, rule
	}
	if dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return actBlock, pid, rule
	}
	if tun := r.tun.Load(); tun != nil && !tun.Routed(dst) {
		r.outside.Add(1)
		r.rateLog("route", 10*time.Second, "blocked %s from selected pid %d: destination is outside the tunnel's AllowedIPs", dst, pid)
		return actBlock, pid, rule
	}
	r.rateLog("sel", time.Minute, "pid %d (%s) selected by rule %s: routing through the tunnel", pid, r.exe(pid), rule)
	return actTunnel, pid, rule
}

// ---- TCP relay ------------------------------------------------------------------------

func (r *Redirector) acceptLoop() {
	defer r.wg.Done()
	for {
		c, err := r.relay.Accept()
		if err != nil {
			if r.ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		r.wg.Add(1)
		go r.serve(c)
	}
}

func (r *Redirector) serve(c net.Conn) {
	defer r.wg.Done()
	defer c.Close()
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	ip, _ := netip.AddrFromSlice(ra.IP)
	f := r.lookupTCP(netip.AddrPortFrom(ip.Unmap(), uint16(ra.Port)))
	if f == nil {
		return
	}
	defer f.done.Store(true)

	tun := r.tun.Load()
	if tun == nil {
		r.tunnelOff.Add(1)
		r.rateLog("tcpoff", 5*time.Second, "refused connection from pid %d: tunnel is down", f.pid)
		return
	}
	target := f.orig
	if target.Port() == 53 && len(tun.DNS()) > 0 {
		target = netip.AddrPortFrom(tun.DNS()[0], 53)
	}
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	up, err := tun.Net().DialContextTCPAddrPort(ctx, target)
	cancel()
	if err != nil {
		r.rateLog("tcpdial"+target.String(), 5*time.Second, "tunnel dial to %s failed: %v", target, err)
		return
	}
	defer up.Close()
	pipe(c, up)
}

type closeWriter interface{ CloseWrite() error }

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// ---- housekeeping ---------------------------------------------------------------------

func (r *Redirector) gcLoop() {
	defer r.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			r.gc()
		}
	}
}

func (r *Redirector) gc() {
	now := time.Now()
	r.mu.Lock()
	for k, f := range r.tcp {
		if f.done.Load() && now.Sub(time.Unix(0, f.last.Load())) > tcpIdle {
			delete(r.tcp, k)
		}
	}
	var stale []*udpFlow
	for _, f := range r.udp {
		if now.Sub(time.Unix(0, f.last.Load())) > udpIdle {
			stale = append(stale, f)
		}
	}
	idle := len(r.tcp) == 0 && len(r.udp) == len(stale)
	r.mu.Unlock()
	for _, f := range stale {
		f.conn.Close() // its read loop removes the flow
	}

	r.cmu.Lock()
	for k, c := range r.cache {
		if now.Sub(c.last) > cacheIdle {
			delete(r.cache, k)
		}
	}
	r.cmu.Unlock()

	if idle && r.rules.Load().Enabled() == 0 {
		r.hmu.Lock()
		r.closeHandleLocked()
		r.hmu.Unlock()
		r.logf("redirector idle: WinDivert handle released")
	}
}

func (r *Redirector) cacheGet(k flowKey) (cacheEntry, bool) {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	if c, ok := r.cache[k]; ok {
		return *c, true
	}
	return cacheEntry{}, false
}

func (r *Redirector) cachePut(k flowKey, a action, now time.Time) {
	r.cmu.Lock()
	r.cache[k] = &cacheEntry{act: a, last: now}
	r.cmu.Unlock()
}

func (r *Redirector) cacheTouch(k flowKey, now time.Time) {
	r.cmu.Lock()
	if c, ok := r.cache[k]; ok {
		c.last = now
	}
	r.cmu.Unlock()
}

func (r *Redirector) cacheDel(k flowKey) {
	r.cmu.Lock()
	delete(r.cache, k)
	r.cmu.Unlock()
}
