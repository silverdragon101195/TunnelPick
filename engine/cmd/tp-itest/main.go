// tp-itest is the integration test for per-process redirection. It must run elevated: it opens
// WinDivert. It starts a loopback WireGuard gateway, the engine in-process, and probe processes
// that are selected (or not) by rules, then checks which path each one took.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/silverdragon101195/TunnelPick/engine/internal/engine"
	"github.com/silverdragon101195/TunnelPick/engine/internal/policy"
	"github.com/silverdragon101195/TunnelPick/engine/internal/testgw"
	"github.com/silverdragon101195/TunnelPick/engine/internal/winproc"
)

var (
	failures int
	binDir   string
	workDir  string
	procs    winproc.Cache
)

func check(name string, ok bool, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %s - %s\n", status, name, detail)
}

func note(format string, a ...any) { fmt.Printf("[info] "+format+"\n", a...) }

// ---- canary: a plain server on the LAN address; reaching it means "went out directly" ----

type canary struct {
	ln    net.Listener
	mu    sync.Mutex
	lines []string
}

func startCanary(ip string) (*canary, error) {
	ln, err := net.Listen("tcp4", ip+":0")
	if err != nil {
		return nil, err
	}
	c := &canary{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	return c, nil
}

func (c *canary) serve(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Text()
		c.mu.Lock()
		c.lines = append(c.lines, line)
		c.mu.Unlock()
		fmt.Fprintf(conn, "canary:%s\n", line)
		if line == "hello" {
			return
		}
	}
}

func (c *canary) addr() string { return c.ln.Addr().String() }
func (c *canary) count() int   { c.mu.Lock(); defer c.mu.Unlock(); return len(c.lines) }
func (c *canary) saw(s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		if l == s {
			return true
		}
	}
	return false
}

// ---- probes ----

type probe struct {
	cmd    *exec.Cmd
	goFile string
	out    strings.Builder
	done   chan struct{}
	pid    uint32
}

var goSeq int

func startProbe(exe string, action ...string) *probe {
	goSeq++
	p := &probe{goFile: filepath.Join(workDir, fmt.Sprintf("go-%d", goSeq)), done: make(chan struct{})}
	p.cmd = exec.Command(filepath.Join(binDir, exe), append([]string{"--go", p.goFile}, action...)...)
	p.cmd.Stdout = &p.out
	p.cmd.Stderr = &p.out
	if err := p.cmd.Start(); err != nil {
		p.out.WriteString("FAIL start " + err.Error())
		close(p.done)
		return p
	}
	p.pid = uint32(p.cmd.Process.Pid)
	go func() { p.cmd.Wait(); close(p.done) }()
	return p
}

func (p *probe) release() { os.WriteFile(p.goFile, []byte("go"), 0o644) }

func (p *probe) wait(d time.Duration) string {
	select {
	case <-p.done:
	case <-time.After(d):
		p.cmd.Process.Kill()
		<-p.done
		return "FAIL timeout"
	}
	return strings.TrimSpace(p.out.String())
}

func (p *probe) proc() policy.Proc {
	pr, _ := procs.Lookup(p.pid)
	return pr
}

// run starts, releases and waits for one probe.
func run(exe string, action ...string) string {
	p := startProbe(exe, action...)
	p.release()
	return p.wait(20 * time.Second)
}

func setRules(e *engine.Engine, bypassLAN bool, rules ...policy.Rule) {
	for i := range rules {
		rules[i].Enabled = true
		if rules[i].ID == "" {
			rules[i].ID = fmt.Sprintf("r%d", i+1)
		}
	}
	if err := e.SetPolicy(policy.Set{Rules: rules, BypassLAN: bypassLAN}); err != nil {
		note("SetPolicy error: %v", err)
	}
}

func exeRule(exe string) policy.Rule {
	return policy.Rule{Kind: policy.KindExecutable, Path: filepath.Join(binDir, exe)}
}

func instRule(p *probe, children bool) policy.Rule {
	pr := p.proc()
	return policy.Rule{Kind: policy.KindInstance, PID: pr.PID, Created: pr.Created, Children: children}
}

func ok(s string) bool   { return strings.HasPrefix(s, "OK") }
func fail(s string) bool { return strings.HasPrefix(s, "FAIL") || strings.HasPrefix(s, "NXDOMAIN") }

func waitConnected(e *engine.Engine) bool {
	for i := 0; i < 100; i++ {
		if e.Status().State == "connected" {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func lanIP() string {
	c, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

var syncDir string

func main() {
	for i, a := range os.Args {
		if a == "--sync-dir" && i+1 < len(os.Args) {
			syncDir = os.Args[i+1]
		}
	}
	for i, a := range os.Args {
		if a == "--gateway-only" && i+1 < len(os.Args) {
			gatewayOnly(os.Args[i+1])
			return
		}
	}
	exe, _ := os.Executable()
	binDir = filepath.Dir(exe)
	workDir, _ = os.MkdirTemp("", "tp-itest-")
	defer os.RemoveAll(workDir)

	// A second executable path lets us prove that an exe rule does not touch other programs.
	src, _ := os.ReadFile(filepath.Join(binDir, "tp-probe.exe"))
	os.WriteFile(filepath.Join(binDir, "tp-probe-control.exe"), src, 0o755)

	gw, err := testgw.Start([]string{"10.99.0.0/24"}, func(f string, a ...any) { note("gateway: "+f, a...) })
	if err != nil {
		fmt.Println("gateway:", err)
		os.Exit(1)
	}
	defer gw.Close()

	e, err := engine.New(filepath.Join(workDir, "data"))
	if err != nil {
		fmt.Println("engine:", err)
		os.Exit(1)
	}
	defer e.Close()

	ip := lanIP()
	note("LAN address used for the direct-path canary: %s", ip)
	can, err := startCanary(ip)
	if err != nil {
		fmt.Println("canary:", err)
		os.Exit(1)
	}
	canTarget := can.addr()
	const vpnURL = "http://" + testgw.GatewayIP + "/"

	// T0 baseline: nothing selected, tunnel not connected.
	r := run("tp-probe.exe", "http", vpnURL)
	check("T0 baseline: tunnel-only address is unreachable without VPN/selection", fail(r), r)

	if err := e.Connect(gw.Client); err != nil {
		fmt.Println("connect:", err)
		os.Exit(1)
	}
	check("T0 tunnel handshake", waitConnected(e), fmt.Sprintf("state=%s", e.Status().State))

	r = run("tp-probe.exe", "http", vpnURL)
	check("T0 VPN connected but nothing selected: process still cannot reach tunnel-only address", fail(r), r)

	// T1 executable rule: selected exe goes through the tunnel, a different exe does not.
	setRules(e, false, exeRule("tp-probe.exe"))
	a := startProbe("tp-probe.exe", "http", vpnURL)
	b := startProbe("tp-probe-control.exe", "http", vpnURL)
	a.release()
	b.release()
	ra, rb := a.wait(20*time.Second), b.wait(20*time.Second)
	check("T1 selected exe reaches the VPN-side server", ok(ra) && strings.Contains(ra, testgw.Marker), ra)
	check("T1 server sees the tunnel address as the source", strings.Contains(ra, "client="+testgw.ClientIP), ra)
	check("T1 control exe (not selected) does not", fail(rb), rb)

	// T2 UDP
	a = startProbe("tp-probe.exe", "udp", testgw.GatewayIP+":5353")
	b = startProbe("tp-probe-control.exe", "udp", testgw.GatewayIP+":5353")
	a.release()
	b.release()
	ra, rb = a.wait(10*time.Second), b.wait(10*time.Second)
	check("T2 UDP: selected exe gets an answer through the tunnel", ok(ra) && strings.Contains(ra, "echo:ping"), ra)
	check("T2 UDP: control exe gets none", fail(rb), rb)

	// T3 DNS goes to the tunnel resolver even when the app asks a public one.
	a = startProbe("tp-probe.exe", "dns", "8.8.8.8:53", "vpn-only.test")
	b = startProbe("tp-probe-control.exe", "dns", "8.8.8.8:53", "vpn-only.test")
	a.release()
	b.release()
	ra, rb = a.wait(10*time.Second), b.wait(10*time.Second)
	check("T3 DNS: selected exe resolves a VPN-only name via the tunnel resolver", ok(ra) && strings.Contains(ra, "10.99.0.1"), ra)
	check("T3 DNS: control exe asking 8.8.8.8 does not get that answer", !strings.Contains(rb, "10.99.0.1"), rb)

	// T4 direct-path canary: selected never reaches it, control does.
	before := can.count()
	a = startProbe("tp-probe.exe", "tcp", canTarget)
	b = startProbe("tp-probe-control.exe", "tcp", canTarget)
	a.release()
	b.release()
	ra, rb = a.wait(10*time.Second), b.wait(10*time.Second)
	check("T4 selected exe cannot reach a LAN server directly (destination is outside AllowedIPs)", fail(ra) && !strings.Contains(ra, "canary"), ra)
	check("T4 control exe reaches the same LAN server directly", ok(rb) && strings.Contains(rb, "canary"), rb)
	check("T4 canary saw exactly one (the control's) connection", can.count() == before+1, fmt.Sprintf("lines %d -> %d", before, can.count()))

	// T5 kill switch: tunnel gone.
	e.Disconnect()
	before = can.count()
	t0 := time.Now()
	a = startProbe("tp-probe.exe", "http", vpnURL)
	b = startProbe("tp-probe.exe", "tcp", canTarget)
	c := startProbe("tp-probe.exe", "udp", testgw.GatewayIP+":5353")
	d := startProbe("tp-probe-control.exe", "tcp", canTarget)
	for _, p := range []*probe{a, b, c, d} {
		p.release()
	}
	ra, rb = a.wait(15*time.Second), b.wait(15*time.Second)
	rc, rd := c.wait(15*time.Second), d.wait(15*time.Second)
	check("T5 kill switch: selected TCP fails when the tunnel is down", fail(ra), ra)
	check("T5 kill switch: selected exe does not fall back to the direct network", fail(rb) && !strings.Contains(rb, "canary"), rb)
	check("T5 kill switch: selected UDP is dropped", fail(rc), rc)
	check("T5 kill switch: unselected exe keeps normal network access", ok(rd) && strings.Contains(rd, "canary"), rd)
	check("T5 canary only saw the unselected exe", can.count() == before+1, fmt.Sprintf("lines %d -> %d", before, can.count()))
	check("T5 refusal is fast (not a long timeout)", time.Since(t0) < 12*time.Second, time.Since(t0).Round(100*time.Millisecond).String())
	st := e.Status()
	check("T5 status states the policy plainly", strings.Contains(st.Enforcement, "kill switch"), st.Enforcement)

	// T5b recovery.
	if err := e.Connect(gw.Client); err != nil {
		note("reconnect: %v", err)
	}
	waitConnected(e)
	r = run("tp-probe.exe", "http", vpnURL)
	check("T5 reconnecting restores access for the selected exe", ok(r), r)

	// T6 two instances of the same executable, different policy.
	pa := startProbe("tp-probe.exe", "http", vpnURL)
	pb := startProbe("tp-probe.exe", "http", vpnURL)
	setRules(e, false, instRule(pa, false))
	pa.release()
	pb.release()
	ra, rb = pa.wait(20*time.Second), pb.wait(20*time.Second)
	check("T6 instance rule: the selected instance uses the VPN", ok(ra), ra)
	check("T6 instance rule: a second instance of the same exe does not", fail(rb), rb)

	// T7 children.
	pp := startProbe("tp-probe.exe", "spawn", filepath.Join(workDir, "child-go"), "http", vpnURL)
	setRules(e, false, instRule(pp, false))
	pp.release()
	os.WriteFile(filepath.Join(workDir, "child-go"), []byte("go"), 0o644)
	rp := pp.wait(25 * time.Second)
	check("T7 children excluded: child of a selected process is not selected", fail(rp), rp)

	os.Remove(filepath.Join(workDir, "child-go"))
	pp = startProbe("tp-probe.exe", "spawn", filepath.Join(workDir, "child-go"), "http", vpnURL)
	setRules(e, false, instRule(pp, true))
	pp.release()
	os.WriteFile(filepath.Join(workDir, "child-go"), []byte("go"), 0o644)
	rp = pp.wait(25 * time.Second)
	check("T7 children included: child of a selected process uses the VPN", ok(rp), rp)

	// T8 connection that existed before selection.
	setRules(e, false)
	ready, release := filepath.Join(workDir, "ready"), filepath.Join(workDir, "release")
	h := startProbe("tp-probe.exe", "hold", canTarget, ready, release)
	h.release()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	check("T8 connection opened before selection reached the LAN server", can.saw("before"), "canary saw 'before'")
	setRules(e, false, exeRule("tp-probe.exe"))
	os.WriteFile(release, []byte("go"), 0o644)
	rh := h.wait(20 * time.Second)
	time.Sleep(300 * time.Millisecond)
	check("T8 existing connection is cut once the process is selected (not left on the direct path)",
		strings.HasPrefix(rh, "CUT") && !can.saw("after"), rh)

	// T9 IPv6 is blocked, not leaked.
	setRules(e, false, exeRule("tp-probe.exe"))
	before6 := e.Status().Redirector.BlockedIPv6
	r = run("tp-probe.exe", "tcp6", "[2606:4700:4700::1111]:443")
	after6 := e.Status().Redirector.BlockedIPv6
	check("T9 IPv6 from a selected process does not connect", fail(r), r)
	if after6 > before6 {
		note("IPv6 packets blocked by the redirector: %d", after6-before6)
	} else {
		note("no IPv6 packet reached the redirector (host has no IPv6 route; the OS refused it earlier)")
	}

	// T10 BypassLAN: LAN becomes reachable directly, only when asked.
	setRules(e, true, exeRule("tp-probe.exe"))
	before = can.count()
	r = run("tp-probe.exe", "tcp", canTarget)
	if isPrivate(ip) {
		check("T10 BypassLAN=true lets a selected exe reach a private LAN address directly", ok(r) && can.count() == before+1, r)
	} else {
		note("T10 skipped: %s is not a private address", ip)
	}
	setRules(e, false, exeRule("tp-probe.exe"))

	chromeTest(e, gw, syncDir)

	fmt.Printf("\nredirector stats: %+v\n", e.Status().Redirector)
	if failures > 0 {
		fmt.Printf("\n%d CHECK(S) FAILED\n", failures)
		finish(1)
	}
	fmt.Println("\nALL CHECKS PASSED")
	finish(0)
}

// finish tells the driver script the run is over, then exits.
func finish(code int) {
	if syncDir != "" {
		os.WriteFile(filepath.Join(syncDir, "itest.finished"), []byte(fmt.Sprint(code)), 0o644)
	}
	os.Exit(code)
}

func isPrivate(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && a.IsPrivate()
}

// gatewayOnly serves the loopback gateway for an externally started engine (the installed service).
// It writes the client configuration to path and runs until path+".stop" appears.
func gatewayOnly(path string) {
	gw, err := testgw.Start([]string{"10.99.0.0/24"}, func(f string, a ...any) { note("gateway: "+f, a...) })
	if err != nil {
		fmt.Println("gateway:", err)
		os.Exit(1)
	}
	defer gw.Close()
	b, _ := json.MarshalIndent(gw.Client, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("gateway ready")
	for {
		if _, err := os.Stat(path + ".stop"); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}
