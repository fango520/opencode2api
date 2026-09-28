package app

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/6Kmfi6HP/opencode2api/internal/logging"
)

type adminLogEntry struct {
	Line     string `json:"line"`
	Level    string `json:"level"`
	Category string `json:"category"`
	Error    bool   `json:"error"`
}

func logCategory(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "upstream"):
		return "upstream"
	case strings.Contains(l, "key") || strings.Contains(l, "gateway") || strings.Contains(l, "auth"):
		return "auth_key"
	case strings.Contains(l, "config") || strings.Contains(l, "reload"):
		return "config"
	case strings.Contains(l, "request_") || strings.Contains(l, "stream_result") || strings.Contains(l, "http"):
		return "request"
	default:
		return "other"
	}
}

func logLevel(line string) string {
	for _, token := range strings.Fields(line) {
		if strings.HasPrefix(token, "level=") {
			return strings.ToLower(strings.Trim(token[6:], "\"'"))
		}
	}
	return "info"
}

func readLogFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var scanner *bufio.Scanner
	var gz *gzip.Reader
	if strings.HasSuffix(path, ".gz") {
		gz, err = gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		scanner = bufio.NewScanner(gz)
	} else {
		scanner = bufio.NewScanner(f)
	}
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readAllLogLines() ([]string, error) {
	path := logging.LogFilePath()
	if path == "" {
		return nil, errors.New("file logging is disabled")
	}
	paths := []string{path}
	if matches, err := filepath.Glob(path + ".*"); err == nil {
		for _, p := range matches {
			paths = append(paths, p)
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] > paths[j] })
	var all []string
	for _, p := range paths {
		lines, err := readLogFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		all = append(all, lines...)
	}
	return all, nil
}

func adminLogsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		if err := logging.ClearLog(); err != nil {
			http.Error(w, `{"error":"clear log failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	case http.MethodGet:
		// continue below
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	category := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("category")))
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	lines, err := readAllLogLines()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, `{"error":"read log failed"}`, http.StatusInternalServerError)
		return
	}
	entries := make([]adminLogEntry, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		lvl := logLevel(line)
		cat := logCategory(line)
		isErr := lvl == "error" || strings.Contains(strings.ToLower(line), "error")
		if category != "" && category != "all" && cat != category {
			continue
		}
		if level == "error" && !isErr {
			continue
		}
		if level != "" && level != "all" && level != "error" && lvl != level {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(line), query) {
			continue
		}
		entries = append(entries, adminLogEntry{Line: line, Level: lvl, Category: cat, Error: isErr})
	}
	total := len(entries)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items := entries[start:end]
	if items == nil {
		items = []adminLogEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items": items, "page": page, "page_size": pageSize, "total": total,
		"pages": (total + pageSize - 1) / pageSize, "log_path": logging.LogFilePath(),
	})
}
