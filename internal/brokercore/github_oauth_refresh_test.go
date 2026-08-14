package brokercore

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type githubRefreshStore struct {
	config       *store.CredentialOAuth
	accessCT     []byte
	accessNonce  []byte
	refreshCT    []byte
	refreshNonce []byte
	expiresAt    *time.Time
}

func (s *githubRefreshStore) GetCredentialOAuth(_ context.Context, _, _ string) (*store.CredentialOAuth, error) {
	return s.config, nil
}

func (s *githubRefreshStore) UpdateCredentialOAuthTokens(_ context.Context, _, _ string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error {
	s.accessCT = accessCT
	s.accessNonce = accessNonce
	s.refreshCT = refreshCT
	s.refreshNonce = refreshNonce
	s.expiresAt = expiresAt
	return nil
}

func (s *githubRefreshStore) UpdateCredentialOAuthError(_ context.Context, _, _, _ string) error {
	return nil
}

type refreshRoundTripFunc func(*http.Request) (*http.Response, error)

func (f refreshRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestManagedGitHubOAuthRefreshRotatesEncryptedTokensForGitSmartHTTP(t *testing.T) {
	key := make32(0x61)
	credentialStore := newFakeCredStore()
	credentialStore.setServices(t, "vault-id", []broker.Service{{
		Name: "github-git",
		Host: "github.com",
		Auth: broker.Auth{Type: "basic", Username: "GITHUB_TOKEN", Password: "GITHUB_TOKEN"},
	}})
	credentialStore.setCred(t, key, "vault-id", "GITHUB_TOKEN", "ghu_old-access")
	credentialStore.setCredType(t, "vault-id", "GITHUB_TOKEN", "oauth")

	oldRefreshCT, oldRefreshNonce, err := crypto.Encrypt([]byte("ghr_old-refresh"), key)
	if err != nil {
		t.Fatalf("encrypt old refresh token: %v", err)
	}
	expiresSoon := time.Now().Add(time.Minute)
	oauthStore := &githubRefreshStore{config: &store.CredentialOAuth{
		VaultID:           "vault-id",
		CredentialKey:     "GITHUB_TOKEN",
		TokenURL:          "https://github.com/login/oauth/access_token",
		ClientID:          "github-client-id",
		RefreshTokenCT:    oldRefreshCT,
		RefreshTokenNonce: oldRefreshNonce,
		TokenExpiresAt:    &expiresSoon,
		TokenAuthMethod:   "client_secret_post",
	}}

	oldTokenClient := oauth.TokenClient
	oauth.TokenClient = &http.Client{Transport: refreshRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read refresh request: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse refresh request: %v", err)
		}
		if form.Get("refresh_token") != "ghr_old-refresh" {
			t.Fatalf("refresh token = %q", form.Get("refresh_token"))
		}
		if form.Get("client_id") != "github-client-id" || form.Get("client_secret") != "operator-client-secret" {
			t.Fatalf("refresh did not use current operator client credentials")
		}
		if _, ok := form["scope"]; ok {
			t.Fatalf("managed GitHub refresh sent classic OAuth scope: %v", form)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"ghu_rotated-access","refresh_token":"ghr_rotated-refresh","token_type":"bearer","expires_in":28800}`)),
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { oauth.TokenClient = oldTokenClient })

	provider := &StoreCredentialProvider{
		Store:        credentialStore,
		OAuthStore:   oauthStore,
		EncKey:       key,
		Refresher:    oauth.NewRefresher(),
		OAuthSecrets: staticOAuthClientSecretResolver{secret: "operator-client-secret", ok: true},
	}
	result, err := provider.Inject(t.Context(), "vault-id", "github.com", 443, "/mindroom-ai/agent-vault.git/git-upload-pack")
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("ghu_rotated-access:ghu_rotated-access"))
	if result.Headers["Authorization"] != wantAuthorization {
		t.Fatalf("Authorization = %q", result.Headers["Authorization"])
	}

	storedAccess, err := crypto.Decrypt(oauthStore.accessCT, oauthStore.accessNonce, key)
	if err != nil {
		t.Fatalf("decrypt rotated access token: %v", err)
	}
	storedRefresh, err := crypto.Decrypt(oauthStore.refreshCT, oauthStore.refreshNonce, key)
	if err != nil {
		t.Fatalf("decrypt rotated refresh token: %v", err)
	}
	if string(storedAccess) != "ghu_rotated-access" || string(storedRefresh) != "ghr_rotated-refresh" {
		t.Fatalf("stored rotated tokens = %q / %q", storedAccess, storedRefresh)
	}
	if oauthStore.expiresAt == nil || !oauthStore.expiresAt.After(time.Now()) {
		t.Fatalf("rotated expiry = %v", oauthStore.expiresAt)
	}
}
