// Package policy decides whether a process is routed through the VPN.
package policy

import (
	"path/filepath"
	"strings"
)

type Kind string

const (
	// KindInstance targets one running process, identified by PID and start time.
	KindInstance Kind = "instance"
	// KindExecutable targets every process started from an executable.
	KindExecutable Kind = "executable"
)

// Rule selects processes. All populated fields must match.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Kind        Kind   `json:"kind"`
	PID         uint32 `json:"pid,omitempty"`
	Created     uint64 `json:"created,omitempty"`     // FILETIME of the process start; instance rules only
	Path        string `json:"path,omitempty"`        // full executable path; executable rules only
	CmdContains string `json:"cmdContains,omitempty"` // case-insensitive substring of the command line
	Children    bool   `json:"children"`              // also select descendants of a matching process
	Enabled     bool   `json:"enabled"`
}

// Proc is the identity of a running process. PID alone is not an identity because
// Windows reuses PIDs; Created disambiguates.
type Proc struct {
	PID     uint32
	Created uint64
	Parent  uint32
	Path    string
	Cmd     string
}

// Resolver looks a live process up. It must return false when the PID is gone.
type Resolver interface {
	Lookup(pid uint32) (Proc, bool)
}

// Set is an immutable collection of rules plus the options that shape them.
type Set struct {
	Rules     []Rule `json:"rules"`
	BypassLAN bool   `json:"bypassLan"` // private, link-local and multicast destinations bypass the tunnel
}

const maxAncestors = 32

// Enabled counts the rules that can select something.
func (s *Set) Enabled() int {
	if s == nil {
		return 0
	}
	n := 0
	for _, r := range s.Rules {
		if r.Enabled {
			n++
		}
	}
	return n
}

// Match returns the ID of the rule selecting pid, if any. A rule with Children set
// also selects every descendant whose ancestry can be proven.
func (s *Set) Match(res Resolver, pid uint32) (string, bool) {
	if s.Enabled() == 0 {
		return "", false
	}
	cur, ok := res.Lookup(pid)
	if !ok {
		return "", false
	}
	for depth := 0; depth < maxAncestors; depth++ {
		for _, r := range s.Rules {
			if !r.Enabled || (depth > 0 && !r.Children) {
				continue
			}
			if r.matches(cur) {
				return r.ID, true
			}
		}
		if cur.Parent == 0 || cur.Parent == cur.PID {
			return "", false
		}
		parent, ok := res.Lookup(cur.Parent)
		// A parent that started after its child is a recycled PID, not the real parent.
		if !ok || parent.Created > cur.Created {
			return "", false
		}
		cur = parent
	}
	return "", false
}

func (r *Rule) matches(p Proc) bool {
	switch r.Kind {
	case KindInstance:
		if r.PID != p.PID || r.Created != p.Created {
			return false
		}
	case KindExecutable:
		if r.Path == "" || !samePath(r.Path, p.Path) {
			return false
		}
	default:
		return false
	}
	if r.CmdContains != "" && !strings.Contains(strings.ToLower(p.Cmd), strings.ToLower(r.CmdContains)) {
		return false
	}
	return true
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
