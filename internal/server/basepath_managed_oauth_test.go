package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauth"
)

func TestManagedGitHubOAuthUnderUIBasePath(t *testing.T) {
	ms, sessionToken := setupMockStoreWithSession(t)
	vault, err := ms.CreateVault(t.Context(), "github-user")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := ms.GrantVaultRole(t.Context(), "owner-user-id", "user", vault.ID, "admin"); err != nil {
		t.Fatalf("GrantVaultRole: %v", err)
	}

	srv := newTestServerWithBasePath("/vault", withStore(ms), withEncKey(make([]byte, 32)))
	provider := testManagedGitHubProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})
	connectReq := httptest.NewRequest(http.MethodPost, "/vault/v1/credentials/oauth/connect", strings.NewReader(`{"vault":"github-user","key":"GITHUB_TOKEN","provider":"github"}`))
	connectReq.Header.Set("Authorization", "Bearer "+sessionToken)
	connectReq.Header.Set("Content-Type", "application/json")
	connectRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(connectRec, connectReq)
	if connectRec.Code != http.StatusOK {
		t.Fatalf("connect: status = %d, body = %s", connectRec.Code, connectRec.Body.String())
	}
	var connectResp struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.NewDecoder(connectRec.Body).Decode(&connectResp); err != nil {
		t.Fatalf("decode connect response: %v", err)
	}
	authorizationURL, err := url.Parse(connectResp.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	callbackURL := srv.UIURL("/v1/oauth/callback")
	if got := authorizationURL.Query().Get("redirect_uri"); got != callbackURL {
		t.Fatalf("authorization redirect_uri = %q, want %q", got, callbackURL)
	}
	if authorizationURL.Query().Get("state") == "" {
		t.Fatal("authorization URL has no state")
	}

	oldTokenClient := oauth.TokenClient
	oauth.TokenClient = &http.Client{Transport: oauthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read token request: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse token request: %v", err)
		}
		if got := form.Get("redirect_uri"); got != callbackURL {
			t.Errorf("token redirect_uri = %q, want %q", got, callbackURL)
		}
		if form.Get("client_secret") != provider.ClientSecret {
			t.Error("token exchange did not use the managed client secret")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"managed-access","token_type":"bearer"}`)),
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { oauth.TokenClient = oldTokenClient })

	callbackReq := httptest.NewRequest(http.MethodGet, "/vault/v1/oauth/callback?code=authorization-code&state="+url.QueryEscape(authorizationURL.Query().Get("state")), nil)
	callbackRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", callbackRec.Code, callbackRec.Body.String())
	}
	if got := callbackRec.Header().Get("Location"); !strings.HasPrefix(got, srv.UIURL("/oauth/complete")+"?status=success") {
		t.Fatalf("callback Location = %q", got)
	}
	if _, err := ms.GetCredential(t.Context(), vault.ID, "GITHUB_TOKEN"); err != nil {
		t.Fatalf("managed credential missing after callback: %v", err)
	}
}
