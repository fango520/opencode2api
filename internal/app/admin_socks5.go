package app

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// parseSocks5Line accepts the panel's SOCKS5 forms:
// socks5://host:port, socks5://username:password@host:port, and the common
// provider export username:password@host:port. A backslash-escaped @ used by
// some provider copy buttons is normalized as the authority separator.
func parseSocks5Line(line string) (Socks5Proxy, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, " \t\r\n") {
		return Socks5Proxy{}, fmt.Errorf("must be a non-empty socks5 URI")
	}
	line = strings.ReplaceAll(line, `\@`, "@")
	if !strings.Contains(line, "://") {
		line = "socks5://" + line
	}
	u, err := url.Parse(line)
	if err != nil || u.Scheme != "socks5" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Socks5Proxy{}, fmt.Errorf("expected socks5://[username:password@]host:port or username:password@host:port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || port == "" {
		return Socks5Proxy{}, fmt.Errorf("host and port are required")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Socks5Proxy{}, fmt.Errorf("port must be 1-65535")
	}
	proxy := Socks5Proxy{Addr: net.JoinHostPort(host, port)}
	if u.User != nil {
		proxy.Username = u.User.Username()
		if proxy.Username == "" {
			return Socks5Proxy{}, fmt.Errorf("username cannot be empty")
		}
		if pass, ok := u.User.Password(); ok {
			proxy.Password = pass
		}
	}
	return proxy, nil
}

func adminSocks5ParseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	var out []Socks5Proxy
	seen := map[string]bool{}
	for lineNo, raw := range strings.Split(payload.Text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxy, err := parseSocks5Line(line)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("第 %d 行格式错误: %v", lineNo+1, err)})
			return
		}
		if seen[proxy.Addr+"\x00"+proxy.Username] {
			continue
		}
		seen[proxy.Addr+"\x00"+proxy.Username] = true
		out = append(out, proxy)
	}
	if len(out) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "没有可导入的 SOCKS5 节点"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": out, "added": len(out)})
}
