package app

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func testSocks5Forwarder(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSocks5(conn)
		}
	}()
	return ln.Addr().String()
}

func serveTestSocks5(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(br, request); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	var host string
	switch request[3] {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 3:
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		addr := make([]byte, int(n))
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		host = string(addr)
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, stringPort(portBytes)))
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(target, br); _ = target.Close() }()
	_, _ = io.Copy(conn, target)
}

func stringPort(b []byte) string {
	return fmt.Sprintf("%d", int(b[0])<<8|int(b[1]))
}

func TestDirectThenProxy429QuarantinesAndRotates(t *testing.T) {
	oldPath := configPath
	oldProxies := append([]Socks5Proxy(nil), socks5Proxies...)
	oldClients := socks5BoundClients
	configPath = t.TempDir() + "/config.json"
	defer func() {
		configPath = oldPath
		socks5Mu.Lock()
		socks5Proxies = oldProxies
		socks5BoundClients = oldClients
		socks5Mu.Unlock()
	}()

	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read request body: %v", err)
		}
		switch calls.Add(1) {
		case 1, 2:
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"limited"}`)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer upstream.Close()

	p1, p2 := testSocks5Forwarder(t), testSocks5Forwarder(t)
	proxies := []Socks5Proxy{{Addr: p1, Name: "p1"}, {Addr: p2, Name: "p2"}}
	if err := saveConfig(configPath, AppConfig{Socks5Proxies: proxies}); err != nil {
		t.Fatal(err)
	}
	socks5Mu.Lock()
	socks5Proxies = proxies
	socks5BoundClients = map[string]*http.Client{}
	socks5Mu.Unlock()

	req, err := http.NewRequest(http.MethodPost, upstream.URL, bytes.NewBufferString("hello"))
	if err != nil {
		t.Fatal(err)
	}
	resp, _, usedProxy, err := doWithKeyProxyPolicy(req, "key-test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if usedProxy != p2 {
		t.Fatalf("used proxy = %q, want second proxy %q", usedProxy, p2)
	}
	if calls.Load() != 3 {
		t.Fatalf("upstream calls = %d, want direct + two proxies", calls.Load())
	}
	usable := socks5ProxyPoolSnapshot("")
	if len(usable) != 1 || usable[0].Addr != p2 {
		t.Fatalf("usable proxy pool = %#v, want only p2", usable)
	}
	cfg := loadConfig(configPath)
	if !cfg.Socks5Proxies[0].Disabled || cfg.Socks5Proxies[1].Disabled {
		t.Fatalf("persisted proxy disabled states = %#v", cfg.Socks5Proxies)
	}

	// Disabling is durable, and the admin action can explicitly re-enable it.
	enableSocks5Proxy(p1)
	usable = socks5ProxyPoolSnapshot("")
	if len(usable) != 2 {
		t.Fatalf("usable proxies after re-enable = %d, want 2", len(usable))
	}
	if !fileExists(configPath) {
		t.Fatal("config file unexpectedly missing")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
