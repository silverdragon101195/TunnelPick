// Package logbuf keeps a bounded, redacted diagnostic log in memory and, optionally, on disk.
package logbuf

import (
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

// secretPattern matches WireGuard-style 32-byte base64 keys and key=value pairs naming a secret.
var secretPattern = regexp.MustCompile(`(?i)(private_key|preshared_key|privatekey|presharedkey)\s*[=:]\s*\S+|[A-Za-z0-9+/]{43}=`)

const maxFileBytes = 1 << 20

// Buffer is a fixed-capacity ring of log lines. It is safe for concurrent use.
type Buffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	file  *os.File
}

func New(max int) *Buffer { return &Buffer{max: max} }

// Redact removes anything that looks like key material from s.
func Redact(s string) string { return secretPattern.ReplaceAllString(s, "[redacted]") }

// SetFile mirrors every line to path. An existing file larger than 1 MiB is truncated first.
func (b *Buffer) SetFile(path string) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if st, err := os.Stat(path); err == nil && st.Size() > maxFileBytes {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.file = f
	b.mu.Unlock()
	return nil
}

// Printf appends a redacted, timestamped line.
func (b *Buffer) Printf(format string, args ...any) {
	line := fmt.Sprintf("%s %s", time.Now().Format("15:04:05.000"), Redact(fmt.Sprintf(format, args...)))
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.lines) >= b.max {
		copy(b.lines, b.lines[1:])
		b.lines = b.lines[:len(b.lines)-1]
	}
	b.lines = append(b.lines, line)
	if b.file != nil {
		fmt.Fprintln(b.file, line)
	}
}

// Tail returns the last n lines (all of them when n <= 0).
func (b *Buffer) Tail(n int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || n > len(b.lines) {
		n = len(b.lines)
	}
	out := make([]string, n)
	copy(out, b.lines[len(b.lines)-n:])
	return out
}
