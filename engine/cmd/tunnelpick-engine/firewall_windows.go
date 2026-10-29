package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// firewallRuleName is the only firewall rule TunnelPick owns.
const firewallRuleName = "TunnelPick engine relay"

// The rule exists only while the engine runs: run adds it before the relay listens and removes it on
// exit; the next start also removes one left behind by a killed engine.
//
// The redirector bounces the packets of a selected process to a TCP relay inside the engine, and
// Windows Firewall drops those inbound packets unless the engine is allowed to receive them.
// The rule is as narrow as the traffic allows: this executable only, TCP only, and only from
// addresses of the local subnet, which is where a bounced packet comes from (the machine itself).

func netsh(args ...string) (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	out, err := exec.Command(filepath.Join(dir, "netsh.exe"), append([]string{"advfirewall", "firewall"}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func addFirewallRule(engineExe string) error {
	if err := removeFirewallRule(); err != nil {
		return err
	}
	out, err := netsh("add", "rule", "name="+firewallRuleName, "dir=in", "action=allow",
		"program="+engineExe, "protocol=TCP", "remoteip=LocalSubnet", "profile=any", "enable=yes")
	if err != nil {
		return fmt.Errorf("create the firewall rule: %w: %s", err, out)
	}
	return nil
}

func removeFirewallRule() error {
	// "show rule" fails when no rule has the name; netsh words that failure per language, so the
	// exit status is the only thing checked.
	if _, err := netsh("show", "rule", "name="+firewallRuleName); err != nil {
		return nil
	}
	out, err := netsh("delete", "rule", "name="+firewallRuleName)
	if err != nil {
		return fmt.Errorf("delete the firewall rule: %w: %s", err, out)
	}
	return nil
}
