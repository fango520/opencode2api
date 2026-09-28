package app

import "testing"

func TestSummarizeKeyTestResponse(t *testing.T) {
	tests := []struct {
		body, want string
	}{
		{`{"choices":[{"message":{"content":"hello"}}]}`, "hello"},
		{`{"error":{"message":"bad key"}}`, "bad key"},
		{`plain upstream text`, "plain upstream text"},
	}
	for _, tc := range tests {
		if got := summarizeKeyTestResponse([]byte(tc.body)); got != tc.want {
			t.Fatalf("summarizeKeyTestResponse(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}
