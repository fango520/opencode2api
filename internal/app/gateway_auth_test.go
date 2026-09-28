package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayAuthSeparatesClientKey(t *testing.T) {
	oldKey, oldRequired, oldPublic, oldRoutes, oldDefault := gatewayRoutingSnapshot()
	t.Cleanup(func() { setGatewayRouting(oldKey, oldRequired, oldPublic, oldRoutes, oldDefault) })
	setGatewayRouting("client-secret", true, false, nil, "zen")

	for _, tc := range []struct {
		name   string
		header string
		code   int
		mode   AuthRouteMode
	}{
		{name: "correct gateway key", header: "client-secret", code: http.StatusOK, mode: AuthRouteGateway},
		{name: "wrong key", header: "wrong", code: http.StatusUnauthorized, mode: AuthRoutePublic},
		{name: "anonymous", header: "", code: http.StatusUnauthorized, mode: AuthRoutePublic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", "Bearer "+tc.header)
			}
			auth := extractUpstreamAuth(req)
			if auth.Mode != tc.mode {
				t.Fatalf("auth mode=%v, want %v", auth.Mode, tc.mode)
			}
			rec := httptest.NewRecorder()
			gatewayAuthMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("status=%d, want %d; body=%s", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
}

func TestGatewayPublicCompatibilityAndModelRoutes(t *testing.T) {
	oldKey, oldRequired, oldPublic, oldRoutes, oldDefault := gatewayRoutingSnapshot()
	t.Cleanup(func() { setGatewayRouting(oldKey, oldRequired, oldPublic, oldRoutes, oldDefault) })
	setGatewayRouting("client-secret", true, true, map[string]string{"mimo-v2.5": "go"}, "zen")

	publicReq := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	auth := extractUpstreamAuth(publicReq)
	if auth.Mode != AuthRoutePublic {
		t.Fatalf("public request mode=%v, want public", auth.Mode)
	}
	if auth.shouldUseGoEndpoint("mimo-v2.5") {
		t.Fatal("public auth must not inherit gateway model route")
	}

	gatewayReq := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	gatewayReq.Header.Set("Authorization", "Bearer client-secret")
	gatewayAuth := extractUpstreamAuth(gatewayReq)
	if gatewayAuth.Mode != AuthRouteGateway || gatewayAuth.Token != "" {
		t.Fatalf("gateway auth=%+v, want empty upstream token", gatewayAuth)
	}
	if !gatewayAuth.shouldUseGoEndpoint("mimo-v2.5") {
		t.Fatal("configured go route not selected")
	}
	if gatewayAuth.shouldUseGoEndpoint("mimo-v2.5-free") {
		t.Fatal("default zen route should not select go")
	}
}
