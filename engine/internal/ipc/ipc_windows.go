// Package ipc serves the engine API over a named pipe restricted by ACL.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/silverdragon101195/TunnelPick/engine/internal/engine"
	"github.com/silverdragon101195/TunnelPick/engine/internal/policy"
	"github.com/silverdragon101195/TunnelPick/engine/internal/tunnel"
)

const PipeName = `\\.\pipe\TunnelPick`

// maxMessage bounds one request line; a config or rule set is far smaller.
const maxMessage = 1 << 20

type request struct {
	ID     int64           `json:"id"`
	Cmd    string          `json:"cmd"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID    int64  `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

// SDDL builds the pipe's security descriptor: SYSTEM and Administrators get full control,
// each listed user SID may read and write. Nobody else, and no remote client, can connect.
func SDDL(userSIDs []string) string {
	var sb strings.Builder
	sb.WriteString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	for _, sid := range userSIDs {
		sb.WriteString("(A;;GRGW;;;" + sid + ")")
	}
	return sb.String()
}

type Server struct {
	eng        *engine.Engine
	ln         net.Listener
	onShutdown func()
}

// Listen opens the pipe. The caller must run Serve. onShutdown is called when a client sends "shutdown".
func Listen(eng *engine.Engine, userSIDs []string, onShutdown func()) (*Server, error) {
	ln, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: SDDL(userSIDs),
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", PipeName, err)
	}
	return &Server{eng: eng, ln: ln, onShutdown: onShutdown}, nil
}

func (s *Server) Close() { s.ln.Close() }

func (s *Server) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.conn(c)
	}
}

func (s *Server) conn(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64*1024), maxMessage)
	enc := json.NewEncoder(c)
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			enc.Encode(response{Error: "malformed request"})
			continue
		}
		enc.Encode(s.dispatch(req))
	}
}

func (s *Server) dispatch(req request) response {
	res := response{ID: req.ID, OK: true}
	fail := func(err error) response { return response{ID: req.ID, Error: err.Error()} }

	switch req.Cmd {
	case "ping":
		res.Data = map[string]string{"version": engine.Version}
	case "status":
		res.Data = s.eng.Status()
	case "connect":
		var cfg tunnel.Config
		if err := json.Unmarshal(req.Params, &cfg); err != nil {
			return fail(fmt.Errorf("invalid config: %w", err))
		}
		if err := s.eng.Connect(cfg); err != nil {
			return fail(err)
		}
	case "disconnect":
		s.eng.Disconnect()
	case "shutdown":
		// The reply is written before the engine goes down.
		go s.onShutdown()
	case "setPolicy":
		var set policy.Set
		if err := json.Unmarshal(req.Params, &set); err != nil {
			return fail(fmt.Errorf("invalid policy: %w", err))
		}
		if err := s.eng.SetPolicy(set); err != nil {
			return fail(err)
		}
	case "getPolicy":
		res.Data = s.eng.Policy()
	case "logs":
		var p struct {
			N int `json:"n"`
		}
		json.Unmarshal(req.Params, &p)
		res.Data = s.eng.Logs(p.N)
	case "flows":
		res.Data = s.eng.Flows()
	case "egress":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ip, err := s.eng.Egress(ctx)
		if err != nil {
			return fail(err)
		}
		res.Data = map[string]string{"ip": ip}
	default:
		return fail(fmt.Errorf("unknown command %q", req.Cmd))
	}
	return res
}
