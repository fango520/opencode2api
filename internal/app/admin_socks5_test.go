package app

import "testing"

func TestParseSocks5Line(t *testing.T) {
	tests := []struct {
		line, addr, user, pass string
	}{
		{"socks5://127.0.0.1:1080", "127.0.0.1:1080", "", ""},
		{"socks5://alice:secret@example.com:443", "example.com:443", "alice", "secret"},
		{"alice:secret@example.com:443", "example.com:443", "alice", "secret"},
		{"alice:secret\\@example.com:443", "example.com:443", "alice", "secret"},
		{"socks5://[::1]:1080", "[::1]:1080", "", ""},
	}
	for _, tc := range tests {
		got, err := parseSocks5Line(tc.line)
		if err != nil {
			t.Fatalf("parseSocks5Line(%q): %v", tc.line, err)
		}
		if got.Addr != tc.addr || got.Username != tc.user || got.Password != tc.pass {
			t.Fatalf("parseSocks5Line(%q) = %#v", tc.line, got)
		}
	}
}

func TestParseSocks5LineRejectsInvalid(t *testing.T) {
	for _, line := range []string{
		"http://127.0.0.1:1080",
		"socks5://127.0.0.1",
		"socks5://127.0.0.1:0",
		"socks5://127.0.0.1:65536",
		"socks5://127.0.0.1:1080/path",
	} {
		if _, err := parseSocks5Line(line); err == nil {
			t.Fatalf("parseSocks5Line(%q) accepted invalid input", line)
		}
	}
}

func TestValidateKeyPoolProxyBindings(t *testing.T) {
	proxies := []Socks5Proxy{{Addr: "127.0.0.1:1080"}}
	if err := validateKeyPoolProxyBindings(KeyPool{Keys: []UpstreamKey{{Key: "k", Socks5Proxy: "127.0.0.1:1080"}}}, proxies); err != nil {
		t.Fatal(err)
	}
	if err := validateKeyPoolProxyBindings(KeyPool{Keys: []UpstreamKey{{Key: "k", Socks5Proxy: "127.0.0.1:1081"}}}, proxies); err == nil {
		t.Fatal("expected unknown proxy binding to fail")
	}
}
