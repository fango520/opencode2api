package app

import "testing"

func TestAdminLogClassification(t *testing.T) {
	cases := []struct {
		line, level, category string
	}{
		{"time=... level=ERROR msg=upstream error", "error", "upstream"},
		{"time=... level=WARN msg=gateway auth rejected", "warn", "auth_key"},
		{"time=... level=INFO msg=request_done path=/v1/models", "info", "request"},
		{"time=... level=DEBUG msg=config loaded", "debug", "config"},
	}
	for _, tc := range cases {
		if got := logLevel(tc.line); got != tc.level {
			t.Errorf("logLevel(%q)=%q, want %q", tc.line, got, tc.level)
		}
		if got := logCategory(tc.line); got != tc.category {
			t.Errorf("logCategory(%q)=%q, want %q", tc.line, got, tc.category)
		}
	}
}
