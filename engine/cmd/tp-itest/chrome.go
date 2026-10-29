package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/silverdragon101195/TunnelPick/engine/internal/engine"
	"github.com/silverdragon101195/TunnelPick/engine/internal/policy"
	"github.com/silverdragon101195/TunnelPick/engine/internal/testgw"
)

func findChrome() string {
	for _, p := range []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// chromeTest selects the Chrome whose command line carries the VPN profile path, then hands over
// to the (non-elevated) driver script through syncDir: Chrome refuses to stay elevated and
// relaunches itself de-elevated, so the browsers must be started by a normal-user process, as
// in real use. The driver starts two headless Chrome instances and writes chrome.done.
// Only the VPN profile's request may reach the VPN-only server.
func chromeTest(e *engine.Engine, gw *testgw.Gateway, syncDir string) {
	chrome := findChrome()
	if chrome == "" || syncDir == "" {
		note("Chrome test skipped (chrome.exe found: %v, driver attached: %v)", chrome != "", syncDir != "")
		return
	}
	vpnProfile := filepath.Join(workDir, "chrome-vpn")
	normalProfile := filepath.Join(workDir, "chrome-normal")
	setRules(e, false, policy.Rule{Kind: policy.KindExecutable, Path: chrome, CmdContains: vpnProfile, Children: true})

	// One "tag|profile|url" line per browser. The VPN profiles share the "chrome-vpn" prefix the rule matches.
	base := "http://" + testgw.GatewayIP + "/?p="
	lines := []string{
		"chrome-vpn|" + vpnProfile + "|" + base + "chrome-vpn",
		"chrome-normal|" + normalProfile + "|" + base + "chrome-normal",
		"chrome-vpn-dns|" + vpnProfile + "2|http://vpn-only.test/?p=chrome-vpn-dns",
	}
	os.WriteFile(filepath.Join(syncDir, "chrome.ready"), []byte(strings.Join(lines, "\n")), 0o644)
	done := filepath.Join(syncDir, "chrome.done")
	for i := 0; i < 600; i++ {
		if _, err := os.Stat(done); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	var vpnHits, normalHits, dnsHits int
	note("requests that reached the gateway: %q", gw.Requests())
	for _, r := range gw.Requests() {
		switch {
		case strings.Contains(r, "p=chrome-vpn-dns") && strings.Contains(r, "Chrome"):
			dnsHits++
		case strings.Contains(r, "p=chrome-vpn") && strings.Contains(r, "Chrome"):
			vpnHits++
		case strings.Contains(r, "p=chrome-normal"):
			normalHits++
		}
	}
	check("T11 Chrome with the VPN profile reached the VPN-only server", vpnHits > 0, fmt.Sprintf("%d request(s) with a Chrome user agent", vpnHits))
	check("T11 normal Chrome running at the same time did not", normalHits == 0, fmt.Sprintf("%d request(s)", normalHits))
	check("T12 Chrome VPN resolved a tunnel-only DNS name (its DNS goes through the tunnel)", dnsHits > 0, fmt.Sprintf("%d request(s)", dnsHits))
	setRules(e, false)
}
