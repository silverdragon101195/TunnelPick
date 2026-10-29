// Package engine ties the tunnel, the redirector and the rule set together.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/silverdragon101195/TunnelPick/engine/internal/logbuf"
	"github.com/silverdragon101195/TunnelPick/engine/internal/policy"
	"github.com/silverdragon101195/TunnelPick/engine/internal/redirect"
	"github.com/silverdragon101195/TunnelPick/engine/internal/tunnel"
	"github.com/silverdragon101195/TunnelPick/engine/internal/winproc"
)

const Version = "0.1.0"

// Status is what the UI shows.
type Status struct {
	Version       string         `json:"version"`
	State         string         `json:"state"` // disconnected | connecting | connected
	LastHandshake int64          `json:"lastHandshakeUnix"`
	RxBytes       uint64         `json:"rxBytes"`
	TxBytes       uint64         `json:"txBytes"`
	Error         string         `json:"error,omitempty"`
	RedirectError string         `json:"redirectError,omitempty"`
	Redirector    redirect.Stats `json:"redirector"`
	EnabledRules  int            `json:"enabledRules"`
	BypassLAN     bool           `json:"bypassLan"`
	// Enforcement spells out what happens to selected processes right now.
	Enforcement string `json:"enforcement"`
	HasIPv6     bool   `json:"tunnelHasIpv6"`
}

type Engine struct {
	Log     *logbuf.Buffer
	dataDir string
	procs   winproc.Cache
	red     *redirect.Redirector

	mu      sync.Mutex
	tun     *tunnel.Tunnel
	err     string
	redErr  string
	set     policy.Set
	started time.Time
}

// New creates the engine and re-applies the stored policy, so selected processes stay
// blocked (not direct) between a restart and the next connect.
func New(dataDir string) (*Engine, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	e := &Engine{Log: logbuf.New(500), dataDir: dataDir}
	if err := e.Log.SetFile(filepath.Join(dataDir, "engine.log")); err != nil {
		return nil, err
	}
	red, err := redirect.New(e.procs, e.Log.Printf)
	if err != nil {
		return nil, err
	}
	e.red = red
	e.Log.Printf("engine %s started", Version)
	if err := e.loadPolicy(); err != nil {
		e.Log.Printf("stored policy ignored: %v", err)
	}
	return e, nil
}

func (e *Engine) policyPath() string { return filepath.Join(e.dataDir, "policy.json") }

func (e *Engine) loadPolicy() error {
	b, err := os.ReadFile(e.policyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s policy.Set
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return e.applyPolicy(s, false)
}

func (e *Engine) applyPolicy(s policy.Set, persist bool) error {
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule %d has no id", i+1)
		}
		switch r.Kind {
		case policy.KindInstance:
			if r.PID == 0 || r.Created == 0 {
				return fmt.Errorf("instance rule %q needs pid and created", r.ID)
			}
		case policy.KindExecutable:
			if strings.TrimSpace(r.Path) == "" {
				return fmt.Errorf("executable rule %q needs a path", r.ID)
			}
		default:
			return fmt.Errorf("rule %q has unknown kind %q", r.ID, r.Kind)
		}
	}
	e.mu.Lock()
	e.set = s
	e.mu.Unlock()

	err := e.red.SetPolicy(&s)
	e.mu.Lock()
	if err != nil {
		e.redErr = err.Error()
	} else {
		e.redErr = ""
	}
	e.mu.Unlock()
	if err != nil {
		e.Log.Printf("cannot enforce policy: %v", err)
	}
	if persist {
		b, _ := json.MarshalIndent(s, "", "  ")
		if werr := os.WriteFile(e.policyPath(), b, 0o644); werr != nil {
			return werr
		}
	}
	return err
}

// SetPolicy stores and enforces the rule set. The policy is stored even when enforcement
// failed, because the next start must try again.
func (e *Engine) SetPolicy(s policy.Set) error { return e.applyPolicy(s, true) }

func (e *Engine) Policy() policy.Set {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.set
}

// Connect replaces any running tunnel. It returns once the device is up; the handshake
// completes asynchronously and shows up in Status.
func (e *Engine) Connect(cfg tunnel.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.Disconnect()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t, err := tunnel.Start(ctx, cfg, e.Log.Printf)
	if err != nil {
		e.mu.Lock()
		e.err = err.Error()
		e.mu.Unlock()
		e.Log.Printf("connect failed: %v", err)
		return err
	}
	e.mu.Lock()
	e.tun, e.err, e.started = t, "", time.Now()
	e.mu.Unlock()
	e.red.SetTunnel(t)
	e.Log.Printf("tunnel up: %d peer(s), %d address(es)", len(cfg.Peers), len(cfg.Addresses))
	return nil
}

// Disconnect closes the tunnel. Selected processes stay blocked while rules are enabled.
func (e *Engine) Disconnect() {
	e.mu.Lock()
	t := e.tun
	e.tun, e.err = nil, ""
	e.mu.Unlock()
	if t == nil {
		return
	}
	e.red.SetTunnel(nil)
	t.Close()
	e.Log.Printf("tunnel closed")
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	t, errMsg, redErr, set, started := e.tun, e.err, e.redErr, e.set, e.started
	e.mu.Unlock()

	s := Status{Version: Version, State: "disconnected", Error: errMsg, RedirectError: redErr,
		Redirector: e.red.Stats(), EnabledRules: set.Enabled(), BypassLAN: set.BypassLAN}
	if t != nil {
		st := t.Stats()
		s.RxBytes, s.TxBytes, s.HasIPv6 = st.RxBytes, st.TxBytes, t.HasIPv6()
		if st.LastHandshake.IsZero() {
			s.State = "connecting"
			if time.Since(started) > 20*time.Second {
				s.Error = "no handshake with the server yet; check the endpoint, the keys and that UDP is not blocked"
			}
		} else {
			s.State = "connected"
			s.LastHandshake = st.LastHandshake.Unix()
		}
	}
	s.Enforcement = enforcement(s, set)
	return s
}

func enforcement(s Status, set policy.Set) string {
	switch {
	case s.RedirectError != "":
		return "NOT ENFORCED: " + s.RedirectError
	case set.Enabled() == 0:
		return "No process is selected; all traffic uses the normal network."
	case s.State == "disconnected":
		return "VPN is off: selected processes are blocked from the network (kill switch). Other processes are unaffected."
	case s.State == "connecting":
		return "Waiting for the handshake: selected processes are blocked until the tunnel is up."
	default:
		return "Selected processes are routed through the VPN; other processes use the normal network."
	}
}

// Logs returns the last n diagnostic lines.
func (e *Engine) Logs(n int) []string { return e.Log.Tail(n) }

// Flows lists what the tunnel currently carries for selected processes.
func (e *Engine) Flows() []redirect.FlowInfo { return e.red.Flows() }

// Egress fetches a public-IP echo service through the tunnel, so the answer is the address
// the VPN server presents to the Internet.
func (e *Engine) Egress(ctx context.Context) (string, error) {
	e.mu.Lock()
	t := e.tun
	e.mu.Unlock()
	if t == nil {
		return "", errors.New("VPN is not connected")
	}
	hc := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: t.Net().DialContext, DisableKeepAlives: true},
	}
	var last error
	for _, u := range []string{"https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return strings.TrimSpace(string(body)), nil
		}
		last = fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	return "", last
}

// Close stops the tunnel and the redirector.
func (e *Engine) Close() {
	e.Disconnect()
	e.red.Close()
	e.Log.Printf("engine stopped")
}
