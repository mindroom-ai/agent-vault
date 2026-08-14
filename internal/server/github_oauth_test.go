package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type oauthRoundTripFunc func(*http.Request) (*http.Response, error)

func (f oauthRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type oauthReadErrorStore struct {
	Store
	err error
}

func (s oauthReadErrorStore) GetCredentialOAuth(context.Context, string, string) (*store.CredentialOAuth, error) {
	return nil, s.err
}

func TestManagedGitHubOAuthLifecycleUsesSelectedVaultAndEncryptedTokens(t *testing.T) {
	ms, sessionToken := setupMockStoreWithSession(t)
	targetVault, err := ms.CreateVault(t.Context(), "github-user")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := ms.GrantVaultRole(t.Context(), "owner-user-id", "user", targetVault.ID, "admin"); err != nil {
		t.Fatalf("GrantVaultRole: %v", err)
	}

	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))
	provider := testManagedGitHubProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	connectBody := `{
		"vault":"github-user",
		"key":"GITHUB_TOKEN",
		"provider":"github",
		"authorization_url":"https://attacker.example/authorize",
		"token_url":"https://attacker.example/token",
		"client_id":"attacker-client-id",
		"client_secret":"attacker-client-secret",
		"scopes":"repo workflow",
		"disable_pkce":true,
		"token_auth_method":"client_secret_basic"
	}`
	connectReq := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/connect", strings.NewReader(connectBody))
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
	authURL, err := url.Parse(connectResp.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if got := authURL.Scheme + "://" + authURL.Host + authURL.Path; got != provider.AuthorizationURL {
		t.Fatalf("authorization endpoint = %q, want %q", got, provider.AuthorizationURL)
	}
	if _, ok := authURL.Query()["scope"]; ok {
		t.Fatalf("authorization URL contains classic scope: %s", connectResp.AuthorizationURL)
	}
	if authURL.Query().Get("state") == "" || authURL.Query().Get("code_challenge") == "" {
		t.Fatalf("authorization URL missing state or PKCE challenge: %s", connectResp.AuthorizationURL)
	}

	storedConfig, err := ms.GetCredentialOAuth(t.Context(), targetVault.ID, "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("GetCredentialOAuth before callback: %v", err)
	}
	if storedConfig.AuthorizationURL != provider.AuthorizationURL || storedConfig.TokenURL != provider.TokenURL || storedConfig.ClientID != provider.ClientID {
		t.Fatalf("stored managed config was not authoritative: %+v", storedConfig)
	}
	if storedConfig.Scopes != "" {
		t.Fatalf("stored scopes = %q, want empty", storedConfig.Scopes)
	}
	if storedConfig.ManagedProvider == nil || *storedConfig.ManagedProvider != "github" {
		t.Fatalf("stored managed provider = %v, want github", storedConfig.ManagedProvider)
	}
	if storedConfig.DisablePKCE {
		t.Fatal("stored managed GitHub config disabled PKCE")
	}
	if len(storedConfig.ClientSecretCT) != 0 || len(storedConfig.ClientSecretNonce) != 0 {
		t.Fatal("operator client secret was stored in user vault")
	}

	const accessToken = "ghu_user-access-token"
	const refreshToken = "ghr_user-refresh-token"
	oldTokenClient := oauth.TokenClient
	oauth.TokenClient = &http.Client{Transport: oauthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != provider.TokenURL {
			t.Fatalf("token endpoint = %q, want %q", req.URL.String(), provider.TokenURL)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read token request: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse token request: %v", err)
		}
		if form.Get("client_id") != provider.ClientID || form.Get("client_secret") != provider.ClientSecret {
			t.Fatalf("token exchange did not use managed client credentials")
		}
		if form.Get("code") != "authorization-code" || form.Get("code_verifier") == "" {
			t.Fatalf("token exchange missing code or PKCE verifier: %v", form)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"` + accessToken + `","refresh_token":"` + refreshToken + `","token_type":"bearer","expires_in":28800}`)),
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { oauth.TokenClient = oldTokenClient })

	callbackURL := "/v1/oauth/callback?code=authorization-code&state=" + url.QueryEscape(authURL.Query().Get("state"))
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", callbackRec.Code, callbackRec.Body.String())
	}
	location := callbackRec.Header().Get("Location")
	if !strings.Contains(location, "vault=github-user") || !strings.Contains(location, "key=GITHUB_TOKEN") {
		t.Fatalf("callback redirect lost selected vault/key: %q", location)
	}
	for _, secret := range []string{accessToken, refreshToken, provider.ClientSecret} {
		if strings.Contains(location, secret) || strings.Contains(callbackRec.Body.String(), secret) {
			t.Fatalf("callback response exposed secret %q", secret)
		}
	}

	credential, err := ms.GetCredential(t.Context(), targetVault.ID, "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("GetCredential after callback: %v", err)
	}
	if credential.Type != "oauth" {
		t.Fatalf("credential type = %q, want oauth", credential.Type)
	}
	decryptedAccess, err := crypto.Decrypt(credential.Ciphertext, credential.Nonce, encKey)
	if err != nil {
		t.Fatalf("decrypt access token: %v", err)
	}
	if string(decryptedAccess) != accessToken {
		t.Fatalf("decrypted access token = %q", decryptedAccess)
	}
	storedConfig, err = ms.GetCredentialOAuth(t.Context(), targetVault.ID, "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("GetCredentialOAuth after callback: %v", err)
	}
	decryptedRefresh, err := crypto.Decrypt(storedConfig.RefreshTokenCT, storedConfig.RefreshTokenNonce, encKey)
	if err != nil {
		t.Fatalf("decrypt refresh token: %v", err)
	}
	if string(decryptedRefresh) != refreshToken {
		t.Fatalf("decrypted refresh token = %q", decryptedRefresh)
	}

	revealReq := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=github-user&reveal=true&key=GITHUB_TOKEN", nil)
	revealReq.Header.Set("Authorization", "Bearer "+sessionToken)
	revealRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(revealRec, revealReq)
	if revealRec.Code != http.StatusForbidden {
		t.Fatalf("managed GitHub reveal: code = %d, body = %s", revealRec.Code, revealRec.Body.String())
	}
	if strings.Contains(revealRec.Body.String(), accessToken) || strings.Contains(revealRec.Body.String(), refreshToken) {
		t.Fatal("managed GitHub reveal response exposed token material")
	}

	listRevealReq := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=github-user&reveal=true", nil)
	listRevealReq.Header.Set("Authorization", "Bearer "+sessionToken)
	listRevealRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(listRevealRec, listRevealReq)
	if listRevealRec.Code != http.StatusOK {
		t.Fatalf("managed GitHub list reveal: code = %d, body = %s", listRevealRec.Code, listRevealRec.Body.String())
	}
	if strings.Contains(listRevealRec.Body.String(), accessToken) || strings.Contains(listRevealRec.Body.String(), refreshToken) {
		t.Fatal("managed GitHub list reveal exposed token material")
	}
	var listRevealResp credentialsListResponse
	if err := json.NewDecoder(listRevealRec.Body).Decode(&listRevealResp); err != nil {
		t.Fatalf("decode managed GitHub list reveal: %v", err)
	}
	if len(listRevealResp.Credentials) != 1 || listRevealResp.Credentials[0].Value != "" {
		t.Fatalf("managed GitHub list reveal returned a value: %+v", listRevealResp.Credentials)
	}
	if err := ms.UpdateCredentialOAuthError(t.Context(), targetVault.ID, "GITHUB_TOKEN", "provider echoed "+accessToken+" and "+refreshToken); err != nil {
		t.Fatalf("seed legacy refresh error: %v", err)
	}
	metadataReq := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=github-user", nil)
	metadataReq.Header.Set("Authorization", "Bearer "+sessionToken)
	metadataRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(metadataRec, metadataReq)
	if metadataRec.Code != http.StatusOK {
		t.Fatalf("credential metadata: code = %d, body = %s", metadataRec.Code, metadataRec.Body.String())
	}
	if strings.Contains(metadataRec.Body.String(), accessToken) || strings.Contains(metadataRec.Body.String(), refreshToken) {
		t.Fatal("credential metadata exposed persisted refresh error token material")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/v1/credentials/oauth/status?vault=github-user&key=GITHUB_TOKEN", nil)
	statusReq.Header.Set("Authorization", "Bearer "+sessionToken)
	statusRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK || !strings.Contains(statusRec.Body.String(), `"connected":true`) {
		t.Fatalf("status: code = %d, body = %s", statusRec.Code, statusRec.Body.String())
	}
	if strings.Contains(statusRec.Body.String(), accessToken) || strings.Contains(statusRec.Body.String(), refreshToken) {
		t.Fatal("OAuth status exposed persisted refresh error token material")
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/v1/credentials", strings.NewReader(`{"vault":"github-user","keys":["GITHUB_TOKEN"]}`))
	deleteReq.Header.Set("Authorization", "Bearer "+sessionToken)
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("disconnect: code = %d, body = %s", deleteRec.Code, deleteRec.Body.String())
	}
	if _, err := ms.GetCredentialOAuth(t.Context(), targetVault.ID, "GITHUB_TOKEN"); err == nil {
		t.Fatal("disconnect left GitHub OAuth configuration in vault")
	}
	if _, err := ms.GetCredential(t.Context(), targetVault.ID, "GITHUB_TOKEN"); err == nil {
		t.Fatal("disconnect left GitHub access token in vault")
	}
}

func TestGenericGitHubTupleDoesNotResolveManagedClientSecret(t *testing.T) {
	ms, sessionToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms), withEncKey(make([]byte, 32)))
	provider := testManagedGitHubProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	connectBody := `{
		"vault":"default",
		"key":"GENERIC_GITHUB",
		"authorization_url":"https://github.com/login/oauth/authorize",
		"token_url":"https://github.com/login/oauth/access_token",
		"client_id":"managed-github-client-id",
		"token_auth_method":"client_secret_post"
	}`
	connectReq := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/connect", strings.NewReader(connectBody))
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
	authURL, err := url.Parse(connectResp.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	storedConfig, err := ms.GetCredentialOAuth(t.Context(), "root-ns-id", "GENERIC_GITHUB")
	if err != nil {
		t.Fatalf("GetCredentialOAuth: %v", err)
	}
	if storedConfig.ManagedProvider == nil || *storedConfig.ManagedProvider != "" {
		t.Fatalf("generic tuple provenance = %v, want explicit unmanaged marker", storedConfig.ManagedProvider)
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
		if form.Get("client_secret") != "" {
			t.Fatal("generic tuple received operator-managed client secret")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"generic-access-token","token_type":"bearer"}`)),
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { oauth.TokenClient = oldTokenClient })

	callbackReq := httptest.NewRequest(http.MethodGet, "/v1/oauth/callback?code=authorization-code&state="+url.QueryEscape(authURL.Query().Get("state")), nil)
	callbackRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback: status = %d, body = %s", callbackRec.Code, callbackRec.Body.String())
	}
}

func TestOAuthCredentialRevealIsBrokerOnlyAfterProviderReconfiguration(t *testing.T) {
	ms, sessionToken := setupMockStoreWithSession(t)
	encKey := make([]byte, 32)
	srv := newTestServer(withStore(ms), withEncKey(encKey))

	if err := ms.SetCredentialOAuth(t.Context(), &store.CredentialOAuth{
		VaultID:          "root-ns-id",
		CredentialKey:    "CUSTOM_OAUTH",
		AuthorizationURL: "https://custom.example/authorize",
		TokenURL:         "https://custom.example/token",
		ClientID:         "custom-client-id",
	}); err != nil {
		t.Fatalf("SetCredentialOAuth: %v", err)
	}
	accessCT, accessNonce, err := crypto.Encrypt([]byte("oauth-access-token"), encKey)
	if err != nil {
		t.Fatalf("encrypt access token: %v", err)
	}
	if err := ms.UpdateCredentialOAuthTokens(t.Context(), "root-ns-id", "CUSTOM_OAUTH", accessCT, accessNonce, nil, nil, nil); err != nil {
		t.Fatalf("UpdateCredentialOAuthTokens: %v", err)
	}

	revealReq := httptest.NewRequest(http.MethodGet, "/v1/credentials?vault=default&reveal=true&key=CUSTOM_OAUTH", nil)
	revealReq.Header.Set("Authorization", "Bearer "+sessionToken)
	revealRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(revealRec, revealReq)
	if revealRec.Code != http.StatusForbidden {
		t.Fatalf("generic OAuth reveal: code = %d, body = %s", revealRec.Code, revealRec.Body.String())
	}
	if strings.Contains(revealRec.Body.String(), "oauth-access-token") {
		t.Fatal("generic OAuth reveal exposed token material")
	}
}

func TestOAuthCallbackErrorDoesNotReflectProviderInput(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/v1/oauth/callback?error=ghu_url-token&error_description=ghr_url-token", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback denial: code = %d, body = %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{"ghu_url-token", "ghr_url-token"} {
		if strings.Contains(rec.Header().Get("Location"), secret) || strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("callback denial reflected provider input %q", secret)
		}
	}
}

func TestOAuthAccessOnlyUploadPersistsExplicitUnmanagedProvenance(t *testing.T) {
	ms, sessionToken := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms), withEncKey(make([]byte, 32)))

	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/tokens", strings.NewReader(`{"vault":"default","key":"MANUAL_OAUTH","access_token":"manual-access-token"}`))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token upload: code = %d, body = %s", rec.Code, rec.Body.String())
	}
	config, err := ms.GetCredentialOAuth(t.Context(), "root-ns-id", "MANUAL_OAUTH")
	if err != nil {
		t.Fatalf("GetCredentialOAuth: %v", err)
	}
	if config.ManagedProvider == nil || *config.ManagedProvider != "" {
		t.Fatalf("manual OAuth provenance = %v, want explicit unmanaged marker", config.ManagedProvider)
	}
}

func TestManagedOAuthTokenUploadRejectsProviderOverridesBeforeRefresh(t *testing.T) {
	tests := []struct {
		name       string
		override   map[string]string
		accessOnly bool
	}{
		{name: "token URL", override: map[string]string{"token_url": "https://attacker.example/token"}},
		{name: "client ID", override: map[string]string{"client_id": "attacker-client-id"}},
		{name: "client secret", override: map[string]string{"client_secret": "attacker-client-secret"}},
		{name: "token auth method", override: map[string]string{"token_auth_method": "client_secret_basic"}},
		{name: "access-only token URL", override: map[string]string{"token_url": "https://attacker.example/token"}, accessOnly: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ms, sessionToken := setupMockStoreWithSession(t)
			srv := newTestServer(withStore(ms), withEncKey(make([]byte, 32)))
			provider := testManagedGitHubProvider()
			srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

			managedProvider := provider.ID
			if err := ms.SetCredentialOAuth(t.Context(), &store.CredentialOAuth{
				VaultID:          "root-ns-id",
				CredentialKey:    "GITHUB_TOKEN",
				ManagedProvider:  &managedProvider,
				AuthorizationURL: provider.AuthorizationURL,
				TokenURL:         provider.TokenURL,
				ClientID:         provider.ClientID,
				ScopeSeparator:   " ",
				TokenAuthMethod:  provider.TokenAuthMethod,
			}); err != nil {
				t.Fatalf("SetCredentialOAuth: %v", err)
			}

			refreshCalls := 0
			oldTokenClient := oauth.TokenClient
			oauth.TokenClient = &http.Client{Transport: oauthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				refreshCalls++
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"attacker-endpoint-token"}`)),
					Request:    req,
				}, nil
			})}
			t.Cleanup(func() { oauth.TokenClient = oldTokenClient })

			payload := map[string]string{"vault": "default", "key": "GITHUB_TOKEN"}
			if tc.accessOnly {
				payload["access_token"] = "replacement-access-token"
			} else {
				payload["refresh_token"] = "new-refresh-token"
			}
			for key, value := range tc.override {
				payload[key] = value
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/tokens", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+sessionToken)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("token upload override: code = %d, body = %s", rec.Code, rec.Body.String())
			}
			if refreshCalls != 0 {
				t.Fatalf("managed provider override reached token endpoint %d time(s)", refreshCalls)
			}
			config, err := ms.GetCredentialOAuth(t.Context(), "root-ns-id", "GITHUB_TOKEN")
			if err != nil {
				t.Fatalf("GetCredentialOAuth: %v", err)
			}
			if config.ManagedProvider == nil || *config.ManagedProvider != provider.ID ||
				config.TokenURL != provider.TokenURL || config.ClientID != provider.ClientID {
				t.Fatalf("managed OAuth config changed after rejected override: %+v", config)
			}
		})
	}
}

func TestOAuthTokenUploadFailsClosedWhenExistingConfigReadFails(t *testing.T) {
	ms, sessionToken := setupMockStoreWithSession(t)
	provider := testManagedGitHubProvider()

	managedProvider := provider.ID
	if err := ms.SetCredentialOAuth(t.Context(), &store.CredentialOAuth{
		VaultID:          "root-ns-id",
		CredentialKey:    "GITHUB_TOKEN",
		ManagedProvider:  &managedProvider,
		AuthorizationURL: provider.AuthorizationURL,
		TokenURL:         provider.TokenURL,
		ClientID:         provider.ClientID,
		ScopeSeparator:   " ",
		TokenAuthMethod:  provider.TokenAuthMethod,
	}); err != nil {
		t.Fatalf("SetCredentialOAuth: %v", err)
	}
	srv := newTestServer(withStore(oauthReadErrorStore{Store: ms, err: errors.New("oauth config read failed")}), withEncKey(make([]byte, 32)))
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/tokens", strings.NewReader(`{
		"vault":"default",
		"key":"GITHUB_TOKEN",
		"access_token":"replacement-token",
		"token_url":"https://attacker.example/token",
		"client_id":"attacker-client-id"
	}`))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("token upload after config read failure: code = %d, body = %s", rec.Code, rec.Body.String())
	}
	config, err := ms.GetCredentialOAuth(t.Context(), "root-ns-id", "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("GetCredentialOAuth: %v", err)
	}
	if config.ManagedProvider == nil || *config.ManagedProvider != provider.ID ||
		config.TokenURL != provider.TokenURL || config.ClientID != provider.ClientID {
		t.Fatalf("managed OAuth config changed after read failure: %+v", config)
	}
}
