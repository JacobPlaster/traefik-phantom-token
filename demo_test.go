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
	cfg.Jwks = "ewogICAgImtleXMiOiBbCiAgICAgIHsKICAgICAgICAia3R5IjogIlJTQSIsCiAgICAgICAgImtpZCI6ICIxODY1NDcyNDcwIiwKICAgICAgICAidXNlIjogInNpZyIsCiAgICAgICAgImFsZyI6ICJQUzI1NiIsCiAgICAgICAgIm4iOiAicVhMckY3dWt5R2ZhTHdvN29vTUN6VUpyZVR0ZU5RWjJJUGJDWjBRZy1pNjNPbHRfR2E4RVZfWTE1V1FiTkc3QmJPZVlDMVN2ZnpvMGF0UFdJMlNPMG41bkRUMl8yUjRZZDNJbWlLNTFmVUYzMjY5OGM1VFpaaFd3T0NyWktnRjc5OFNyeFVybUZ5QW01Zlg0bzFyRzVUUGVMTy1OcXV3cDZ5Tk9oV055ZU40U1hQMmtyY28xenBBODNLSlNDYkQzRktfTGplU0RYTlpVVlRHYjBzcTNTaWc2aG9BckFUdFZMbThZT0xWWl9MaEcwU25hNFlWbFEyWGVrNU1RSE1xelV2SURtUHZsc0QtWjNJN1dlcTdIQVFpb2xDdjNpaFNldWR4T3RRemw2cVZ1Tl93RXJsM25FZVRyTV94RmNGMi1PS3lOYk5UUDVMX1N4Z09xTmViR3d3IiwKICAgICAgICAiZSI6ICJBUUFCIiwKICAgICAgICAieDV0IjogIk12dFpYSU5tWFFpUV9ocHJsVjFSMUFxb0xJbyIKICAgICAgfSwKICAgICAgewogICAgICAgICJrdHkiOiAiUlNBIiwKICAgICAgICAia2lkIjogIjE4NjU0NzI0NzAiLAogICAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgICAiYWxnIjogIlJTMjU2IiwKICAgICAgICAibiI6ICJxWExyRjd1a3lHZmFMd283b29NQ3pVSnJlVHRlTlFaMklQYkNaMFFnLWk2M09sdF9HYThFVl9ZMTVXUWJORzdCYk9lWUMxU3Zmem8wYXRQV0kyU08wbjVuRFQyXzJSNFlkM0ltaUs1MWZVRjMyNjk4YzVUWlpoV3dPQ3JaS2dGNzk4U3J4VXJtRnlBbTVmWDRvMXJHNVRQZUxPLU5xdXdwNnlOT2hXTnllTjRTWFAya3JjbzF6cEE4M0tKU0NiRDNGS19MamVTRFhOWlVWVEdiMHNxM1NpZzZob0FyQVR0VkxtOFlPTFZaX0xoRzBTbmE0WVZsUTJYZWs1TVFITXF6VXZJRG1QdmxzRC1aM0k3V2VxN0hBUWlvbEN2M2loU2V1ZHhPdFF6bDZxVnVOX3dFcmwzbkVlVHJNX3hGY0YyLU9LeU5iTlRQNUxfU3hnT3FOZWJHd3ciLAogICAgICAgICJlIjogIkFRQUIiLAogICAgICAgICJ4NXQiOiAiTXZ0WlhJTm1YUWlRX2hwcmxWMVIxQXFvTElvIgogICAgICB9CiAgICBdCiAgfQ=="
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
	req.Header.Set("Authorization", "Bearer d58fe0ff-0194-4fd5-8562-ecb4b61e4e1a")

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder, 200)
	fmt.Println(req.Header.Get(cfg.ForwardedAuthHeader))
	assertHeader(t, req, cfg.ForwardedAuthHeader, "something")
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
