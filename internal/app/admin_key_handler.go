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
	auth := UpstreamAuth{Token: key.Key, Mode: mode, Source: "admin-key-test"}
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
	result := map[string]any{
		"ok": false, "key_id": key.ID, "group": payload.Group, "model": payload.Model,
		"surface": payload.Group, "latency_ms": latency,
	}
	if err != nil {
		result["error"] = err.Error()
		writeJSON(w, http.StatusBadGateway, result)
		return
	}
	defer resp.Body.Close()
	result["status"] = resp.StatusCode
	result["endpoint"] = req.URL.String()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	result["response"] = string(body)
	result["ok"] = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !result["ok"].(bool) {
		result["error"] = fmt.Sprintf("upstream returned HTTP %s", strconv.Itoa(resp.StatusCode))
	}
	logging.FromContext(r.Context()).Info("admin_key_test", "key_id", key.ID, "group", payload.Group, "model", payload.Model, "status", resp.StatusCode, "latency_ms", latency)
	status := http.StatusOK
	if !result["ok"].(bool) {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
