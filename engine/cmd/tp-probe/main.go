// tp-probe is a tiny network client used by the integration tests. Every action waits for
// the go-file to exist, so the test can select this process before it touches the network.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "--go" {
		fmt.Println("FAIL usage: tp-probe --go FILE ACTION ARGS...")
		os.Exit(2)
	}
	goFile, action, rest := args[1], args[2], args[3:]
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(goFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Println("FAIL never released")
			os.Exit(2)
		}
		time.Sleep(30 * time.Millisecond)
	}

	switch action {
	case "http":
		fmt.Println(httpGet(rest[0]))
	case "tcp":
		fmt.Println(tcpHello(rest[0]))
	case "udp":
		fmt.Println(udpEcho(rest[0]))
	case "dns":
		fmt.Println(dnsQuery(rest[0], rest[1]))
	case "tcp6":
		c, err := net.DialTimeout("tcp6", rest[0], 3*time.Second)
		if err != nil {
			fmt.Println("FAIL", err)
		} else {
			c.Close()
			fmt.Println("OK connected")
		}
	case "hold":
		fmt.Println(hold(rest[0], rest[1], rest[2]))
	case "spawn":
		// spawn GOFILE ACTION ARGS...: run this program again as a child.
		cmd := exec.Command(os.Args[0], append([]string{"--go", rest[0]}, rest[1:]...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("FAIL child:", err, strings.TrimSpace(string(out)))
			return
		}
		fmt.Print(string(out))
	default:
		fmt.Println("FAIL unknown action", action)
	}
}

func httpGet(url string) string {
	c := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return "FAIL " + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	return "OK " + strings.TrimSpace(string(b))
}

func tcpHello(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return "FAIL " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write([]byte("hello\n")); err != nil {
		return "FAIL " + err.Error()
	}
	b, err := io.ReadAll(c)
	if len(b) == 0 && err != nil {
		return "FAIL " + err.Error()
	}
	if len(b) == 0 {
		return "FAIL closed without data"
	}
	return "OK " + strings.TrimSpace(string(b))
}

func udpEcho(addr string) string {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return "FAIL " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("ping"))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return "FAIL " + err.Error()
	}
	return "OK " + string(buf[:n])
}

func dnsQuery(server, name string) string {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:], 0x4242)
	binary.BigEndian.PutUint16(q[2:], 0x0100)
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)

	c, err := net.Dial("udp", server)
	if err != nil {
		return "FAIL " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(q)
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return "FAIL " + err.Error()
	}
	r := buf[:n]
	if len(r) < 12 {
		return "FAIL short answer"
	}
	rcode := r[3] & 0x0f
	if rcode != 0 {
		return fmt.Sprintf("NXDOMAIN rcode=%d", rcode)
	}
	if binary.BigEndian.Uint16(r[6:]) == 0 {
		return "FAIL no answer"
	}
	return fmt.Sprintf("OK %d.%d.%d.%d", r[n-4], r[n-3], r[n-2], r[n-1])
}

// hold opens a connection, signals readiness, waits for the test to select this process, then
// keeps using the same connection.
func hold(addr, readyFile, releaseFile string) string {
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return "FAIL dial " + err.Error()
	}
	defer c.Close()
	if _, err := c.Write([]byte("before\n")); err != nil {
		return "FAIL first write " + err.Error()
	}
	os.WriteFile(readyFile, []byte("ready"), 0o644)
	for i := 0; i < 600; i++ {
		if _, err := os.Stat(releaseFile); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := c.Write([]byte("after\n")); err != nil {
		return "CUT write " + err.Error()
	}
	buf := make([]byte, 128)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return "CUT read " + err.Error()
		}
		if strings.Contains(string(buf[:n]), "after") {
			return "STILL-DIRECT"
		}
	}
}
