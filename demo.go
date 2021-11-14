// Package plugindemo a demo plugin.
package traefik_phantom_token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	VerifyJwt         bool   `json:"verifyJwks,omitempty"`
	Jwks              string `json:"jwks,omitempty"`
	ClientId          string `json:"clientId,omitempty"`
	ClientSecret      string `json:"clientSecret,omitempty"`
	ForwardedAuthHeader string `json:"forwardUserHeader,omitempty"`
	IntrospectUrl     string `json:"introspectUrl,omitempty"`
}

const (
	defaultJwks = ""
	defaultVerifyJwt = true
	defaultForwardAuthHeader = "X-Forward-Auth"
	defaultIntrospectUrl = ""
	defaultClientId = ""
	defaultClientSecret = ""
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Jwks: defaultJwks,
		VerifyJwt: defaultVerifyJwt,
		ForwardedAuthHeader: defaultForwardAuthHeader,
		IntrospectUrl: defaultIntrospectUrl,
		ClientId: defaultClientId,
		ClientSecret: defaultClientSecret,
	}
}

// Demo a Demo plugin.
type PhantomPlugin struct {
	next     http.Handler
	config   *Config
	jwkSet   jwk.Set
	name     string
	template *template.Template
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.VerifyJwt && len(config.Jwks) == 0 {
		return nil, fmt.Errorf("if veifyJwt is true then jwks cannot be empty")
	}
	if len(config.ForwardedAuthHeader) == 0 {
		return nil, fmt.Errorf("forwardedUserHeader cannot be empty")
	}
	if len(config.IntrospectUrl) == 0 {
		return nil, fmt.Errorf("introspectUrl cannot be empty")
	}

	// load the jwks from the config
	jwks, err := base64.StdEncoding.DecodeString(config.Jwks)
	fmt.Println(string(jwks))
	fmt.Println(config)
	set, err := jwk.Parse(jwks)
	if err != nil {
		return nil, fmt.Errorf("unable to parse jwks: %s", err.Error())
	}
	fmt.Println("****")

	return &PhantomPlugin{
		next:     next,
		name:     name,
		jwkSet:   set,
		config:   config,
		template: template.New("traefik_phantom_token").Delims("[[", "]]"),
	}, nil
}

func (a *PhantomPlugin) ServeHTTP(rw http.ResponseWriter, origReq *http.Request) {
	client := &http.Client{}

	// Forward to introspect URL

	// take token from initial request
	token := origReq.Header.Get("Authorization")
	token = strings.TrimSpace(token)
	token = strings.Replace(token, "Bearer ", "", 1)

	// Body x-www-from-urlencoded
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", a.config.ClientId)
	data.Set("client_secret", a.config.ClientSecret)
	data.Set("token_type_hint", "access_token")

	introspectReq, err := http.NewRequest("POST", a.config.IntrospectUrl, strings.NewReader(data.Encode()))
	// headers
	introspectReq.Header.Set("accept", "application/jwt")
	introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	introspectResp, err := client.Do(introspectReq)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer introspectResp.Body.Close()

	// reject if satus code is not 200
	if introspectResp.StatusCode != http.StatusOK {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("{ error: \"FORBIDDEN\""))
		return
	}

	rawToken, err := io.ReadAll(introspectResp.Body)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Parse the JWT & authenticated JWT signature.
	parsedToken, err := jwt.Parse(string(rawToken), a.getKey)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// remove Authorization header from original request
	origReq.Header.Del("Authorization")

	// add X-Forward-Auth: b64({JSON}) header
	stringClaims, err := json.Marshal(parsedToken.Claims)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	str := base64.StdEncoding.EncodeToString(stringClaims)
	origReq.Header.Set(a.config.ForwardedAuthHeader, str)

	// Forward to microservice
	a.next.ServeHTTP(rw, origReq)
}

func (a *PhantomPlugin) getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key, ok := a.jwkSet.LookupKeyID(keyID); ok {
		var k interface{}
		err := key.Raw(&k)
		if err != nil {
			return nil, err
		}
		return k, nil
	}
	return nil, fmt.Errorf("unable to find key %q", keyID)
}
