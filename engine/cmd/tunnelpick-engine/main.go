// tunnelpick-engine runs the WireGuard tunnel and the per-process redirector.
// TunnelPick.exe starts it elevated and it ends with the app; it leaves nothing installed.
//
//	run      run in the foreground; needs an elevated shell
//	version  print the version
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/silverdragon101195/TunnelPick/engine/internal/engine"
	"github.com/silverdragon101195/TunnelPick/engine/internal/ipc"
)

// defaultDataDir is data\engine next to the folder that holds this executable (dist\engine\ -> dist\data\engine).
func defaultDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("data", "engine")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(exe)), "data", "engine")
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	allow := fs.String("allow-sid", "", "comma separated SIDs of the users allowed to talk to the engine")
	data := fs.String("data-dir", defaultDataDir(), "directory for the policy and log files")
	parent := fs.Uint("parent-pid", 0, "exit when this process exits")
	fs.Parse(args)

	var err error
	switch cmd {
	case "run":
		err = run(*data, splitSIDs(*allow), uint32(*parent))
	case "version":
		fmt.Println(engine.Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tunnelpick-engine run|version [--allow-sid SID[,SID]] [--data-dir DIR] [--parent-pid PID]")
	os.Exit(2)
}

func splitSIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// singleInstance takes a machine-wide mutex: a second engine would remove the first one's firewall rule.
func singleInstance() (release func(), err error) {
	name, _ := windows.UTF16PtrFromString(`Global\TunnelPickEngine`)
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, errors.New("another TunnelPick engine is already running")
	}
	if err != nil {
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}

// watchParent calls quit when the process with the given id exits. It does nothing for id 0.
func watchParent(pid uint32, quit func()) {
	if pid == 0 {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		// ERROR_INVALID_PARAMETER: no such process, so the parent is already gone.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			quit()
		}
		return
	}
	defer windows.CloseHandle(h)
	windows.WaitForSingleObject(h, windows.INFINITE)
	quit()
}

// run brings everything up, waits for Ctrl+C, the shutdown command or the parent's exit, and takes it
// all down again, including the firewall rule.
func run(data string, sids []string, parent uint32) error {
	release, err := singleInstance()
	if err != nil {
		return err
	}
	defer release()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// The rule must exist before the relay starts listening, or Windows asks for (and keeps) its own.
	if err := addFirewallRule(exe); err != nil {
		return err
	}
	defer removeFirewallRule()
	defer removeDriverService()

	done := make(chan struct{})
	var once sync.Once
	quit := func() { once.Do(func() { close(done) }) }

	stop, err := start(data, sids, quit)
	if err != nil {
		return err
	}
	go watchParent(parent, quit)

	fmt.Println("tunnelpick-engine running; press Ctrl+C to stop")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-done:
	}
	stop()
	return nil
}

// start brings up the engine and its pipe; stop undoes both.
func start(data string, sids []string, onShutdown func()) (stop func(), err error) {
	eng, err := engine.New(data)
	if err != nil {
		return nil, err
	}
	srv, err := ipc.Listen(eng, sids, onShutdown)
	if err != nil {
		eng.Close()
		return nil, err
	}
	go srv.Serve()
	return func() { srv.Close(); eng.Close() }, nil
}
