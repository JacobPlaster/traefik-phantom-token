package traefik_phantom_token_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JacobPlaster/traefik-phantom-token"
)

func TestDemo(t *testing.T) {
	cfg := traefik_phantom_token.CreateConfig()
	cfg.JwksUrl = "http://127.0.0.1:8443/oauth/v2/anonymous/jwks"
	cfg.VerifyJwt = true
	cfg.ForwardedAuthHeader = "X-Forward-User"
	cfg.IntrospectUrl = "http://127.0.0.1:8443/oauth/v2/introspect"
	cfg.ClientId = "Knox"
	cfg.ClientSecret = "1234"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := traefik_phantom_token.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer 67227268-d250-48b2-9c0b-2bbf51d6c1c3")

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder, 200)
	fmt.Println(req.Header.Get(cfg.ForwardedAuthHeader))
	//assertHeader(t, req, cfg.ForwardedAuthHeader, "something")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}

func assertStatus(t *testing.T, recorder *httptest.ResponseRecorder, expected int) {
	t.Helper()

	if recorder.Code != expected {
		t.Errorf("invalid status code: %d", recorder.Code)
	}
}
