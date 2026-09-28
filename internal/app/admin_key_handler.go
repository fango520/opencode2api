package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/6Kmfi6HP/opencode2api/internal/logging"
)

// adminKeyTestHandler performs one direct, no-pool request with the selected
// upstream key. It is intentionally independent from normal key-pool retry and
// failover logic so the result identifies this exact key and surface.
func adminKeyTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		ID      string `json:"id"`
		Group   string `json:"group"`
		Model   string `json:"model"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	payload.ID = strings.TrimSpace(payload.ID)
	payload.Group = strings.ToLower(strings.TrimSpace(payload.Group))
	payload.Model = strings.TrimSpace(payload.Model)
	payload.Message = strings.TrimSpace(payload.Message)
	if payload.ID == "" {
		http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest)
		return
	}
	if len(payload.Model) > 200 || len(payload.Message) > 4000 {
		http.Error(w, `{"error":"model or message too long"}`, http.StatusBadRequest)
		return
	}
	var key UpstreamKey
	keypoolMu.RLock()
	for _, candidate := range keypoolEntries {
		if candidate.ID == payload.ID {
			key = candidate
			break
		}
	}
	keypoolMu.RUnlock()
	if key.ID == "" || strings.TrimSpace(key.Key) == "" {
		http.Error(w, `{"error":"key not found"}`, http.StatusNotFound)
		return
	}
	if payload.Group == "" {
		payload.Group = strings.ToLower(strings.TrimSpace(key.Group))
	}
	if payload.Group != "zen" && payload.Group != "go" {
		http.Error(w, `{"error":"group must be zen or go"}`, http.StatusBadRequest)
		return
	}
	if payload.Model == "" {
		if payload.Group == "go" {
			payload.Model = "mimo-v2.5"
		} else {
			payload.Model = "mimo-v2.5-free"
		}
	}
	if payload.Message == "" {
		payload.Message = "hi"
	}

	mode := AuthRouteZen
	useGo := false
	if payload.Group == "go" {
		mode = AuthRouteGo
		useGo = true
	}
	auth := UpstreamAuth{Token: key.Key, Mode: mode, Source: "admin-key-test", Socks5Proxy: strings.TrimSpace(key.Socks5Proxy)}
	bodyMap := map[string]any{
		"model": payload.Model,
		"messages": []any{map[string]any{
			"role": "user", "content": payload.Message,
		}},
		"stream":     false,
		"max_tokens": 64,
	}
	state := initOCSession()
	baseURL, client := selectUpstreamTarget(auth, bodyMap, nil, normalizedTransportScope(state.sessionID))
	proxyNode := keyTestProxyNode(key)
	req, err := buildOCRequestWithSubpathAndState(payload.Model, bodyMap, auth, useGo, baseURL, "chat/completions", state.sessionID, state)
	if err != nil {
		http.Error(w, `{"error":"build upstream request failed"}`, http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	started := time.Now()
	resp, err := client.Do(req.WithContext(ctx))
	latency := time.Since(started).Milliseconds()
	egressIP := detectEgressIP(ctx, client)
	result := map[string]any{
		"ok": false, "key_id": key.ID, "group": payload.Group, "model": payload.Model,
		"surface": payload.Group, "latency_ms": latency, "endpoint": req.URL.String(),
		"proxy_node": proxyNode, "egress_ip": egressIP,
	}
	if err != nil {
		result["error"] = err.Error()
		result["response_summary"] = "请求未获得上游响应：" + err.Error()
		logging.FromContext(r.Context()).Error("admin_key_test", "key_id", key.ID, "group", payload.Group, "model", payload.Model, "endpoint", req.URL.String(), "proxy_node", proxyNode, "egress_ip", egressIP, "latency_ms", latency, "response", result["response_summary"])
		writeJSON(w, http.StatusBadGateway, result)
		return
	}
	defer resp.Body.Close()
	result["status"] = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	result["response_summary"] = summarizeKeyTestResponse(body)
	result["ok"] = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !result["ok"].(bool) {
		result["error"] = fmt.Sprintf("upstream returned HTTP %s", strconv.Itoa(resp.StatusCode))
	}
	logging.FromContext(r.Context()).Info("admin_key_test", "key_id", key.ID, "group", payload.Group, "model", payload.Model, "endpoint", req.URL.String(), "proxy_node", proxyNode, "egress_ip", egressIP, "status", resp.StatusCode, "latency_ms", latency, "response", result["response_summary"])
	status := http.StatusOK
	if !result["ok"].(bool) {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, result)
}

func keyTestProxyNode(key UpstreamKey) string {
	if addr := strings.TrimSpace(key.Socks5Proxy); addr != "" {
		socks5Mu.RLock()
		defer socks5Mu.RUnlock()
		for _, proxy := range socks5Proxies {
			if strings.TrimSpace(proxy.Addr) == addr {
				if name := strings.TrimSpace(proxy.Name); name != "" {
					return name + " (" + addr + ")"
				}
				return addr
			}
		}
		return addr
	}
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	switch activeSocks5 {
	case "":
		return "直连"
	case socks5RR:
		return "全局 SOCKS5 轮询"
	default:
		return "全局 " + activeSocks5
	}
}

func detectEgressIP(ctx context.Context, client *http.Client) string {
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err != nil {
		return "获取失败"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "获取失败"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "获取失败"
	}
	var parsed struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &parsed) == nil && strings.TrimSpace(parsed.IP) != "" {
		return strings.TrimSpace(parsed.IP)
	}
	if ip := strings.TrimSpace(string(body)); ip != "" {
		return ip
	}
	return "获取失败"
}

func summarizeKeyTestResponse(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "上游返回空内容"
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return truncateKeyTestText(text, 2000)
	}
	if m, ok := v.(map[string]any); ok {
		if errObj, ok := m["error"].(map[string]any); ok {
			if msg, ok := errObj["message"].(string); ok && strings.TrimSpace(msg) != "" {
				return strings.TrimSpace(msg)
			}
		}
		for _, key := range []string{"output_text", "text", "message"} {
			if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
				return truncateKeyTestText(strings.TrimSpace(s), 2000)
			}
		}
		if choices, ok := m["choices"].([]any); ok && len(choices) > 0 {
			if c, ok := choices[0].(map[string]any); ok {
				if msg, ok := c["message"].(map[string]any); ok {
					if s, ok := msg["content"].(string); ok && strings.TrimSpace(s) != "" {
						return truncateKeyTestText(strings.TrimSpace(s), 2000)
					}
				}
				if s, ok := c["text"].(string); ok && strings.TrimSpace(s) != "" {
					return truncateKeyTestText(strings.TrimSpace(s), 2000)
				}
			}
		}
	}
	compact, _ := json.Marshal(v)
	return truncateKeyTestText(string(compact), 2000)
}

func truncateKeyTestText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
