package phatnomtoken_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JacobPlaster/traefik-phantom-token"
)

func TestDemo(t *testing.T) {
	cfg := phatnomtoken.CreateConfig()
	cfg.Jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1865472470\",\"use\":\"sig\",\"alg\":\"PS256\",\"n\":\"qXLrF7ukyGfaLwo7ooMCzUJreTteNQZ2IPbCZ0Qg-i63Olt_Ga8EV_Y15WQbNG7BbOeYC1Svfzo0atPWI2SO0n5nDT2_2R4Yd3ImiK51fUF32698c5TZZhWwOCrZKgF798SrxUrmFyAm5fX4o1rG5TPeLO-Nquwp6yNOhWNyeN4SXP2krco1zpA83KJSCbD3FK_LjeSDXNZUVTGb0sq3Sig6hoArATtVLm8YOLVZ_LhG0Sna4YVlQ2Xek5MQHMqzUvIDmPvlsD-Z3I7Weq7HAQiolCv3ihSeudxOtQzl6qVuN_wErl3nEeTrM_xFcF2-OKyNbNTP5L_SxgOqNebGww\",\"e\":\"AQAB\",\"x5t\":\"MvtZXINmXQiQ_hprlV1R1AqoLIo\"},{\"kty\":\"RSA\",\"kid\":\"1865472470\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"qXLrF7ukyGfaLwo7ooMCzUJreTteNQZ2IPbCZ0Qg-i63Olt_Ga8EV_Y15WQbNG7BbOeYC1Svfzo0atPWI2SO0n5nDT2_2R4Yd3ImiK51fUF32698c5TZZhWwOCrZKgF798SrxUrmFyAm5fX4o1rG5TPeLO-Nquwp6yNOhWNyeN4SXP2krco1zpA83KJSCbD3FK_LjeSDXNZUVTGb0sq3Sig6hoArATtVLm8YOLVZ_LhG0Sna4YVlQ2Xek5MQHMqzUvIDmPvlsD-Z3I7Weq7HAQiolCv3ihSeudxOtQzl6qVuN_wErl3nEeTrM_xFcF2-OKyNbNTP5L_SxgOqNebGww\",\"e\":\"AQAB\",\"x5t\":\"MvtZXINmXQiQ_hprlV1R1AqoLIo\"}]}"
	cfg.VerifyJwt = true
	cfg.ForwardedAuthHeader = "X-Forward-User"
	cfg.IntrospectUrl = "http://127.0.0.1:8443/oauth/v2/introspect"
	cfg.ClientId = "Knox"
	cfg.ClientSecret = "1234"

	//ctx := context.Background()
	//next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	//
	//handler, err := phatnomtoken.New(ctx, next, cfg, "demo-plugin")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//recorder := httptest.NewRecorder()
	//
	//req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//req.Header.Set("Authorization", "Bearer d58fe0ff-0194-4fd5-8562-ecb4b61e4e1a")
	//
	//handler.ServeHTTP(recorder, req)
	//
	//assertStatus(t, recorder, 200)
	//fmt.Println(req.Header.Get(cfg.ForwardedAuthHeader))
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
