package server

import (
	"net/url"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

func stringPointer(value string) *string { return &value }

func testManagedGoogleProvider() oauth.ManagedProvider {
	return oauth.ManagedProvider{
		ID:               "google",
		AuthorizationURL: "https://accounts.example.com/authorize",
		TokenURL:         "https://accounts.example.com/token",
		ClientID:         "managed-client-id",
		ClientSecret:     "managed-client-secret",
		TokenAuthMethod:  "client_secret_post",
		RequireScopes:    true,
	}
}

func testManagedGitHubProvider() oauth.ManagedProvider {
	return oauth.ManagedProvider{
		ID:               "github",
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		ClientID:         "managed-github-client-id",
		ClientSecret:     "managed-github-client-secret",
		TokenAuthMethod:  "client_secret_post",
		RequireScopes:    false,
		OmitScopes:       true,
	}
}

func TestApplyManagedOAuthProvider(t *testing.T) {
	srv := newTestServer()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{testManagedGoogleProvider()})

	req := oauthConnectRequest{
		Provider:         "google",
		AuthorizationURL: "https://attacker.example/authorize",
		TokenURL:         "https://attacker.example/token",
		ClientID:         "attacker-client-id",
		ClientSecret:     "attacker-client-secret",
		TokenAuthMethod:  "client_secret_basic",
		Scopes:           "openid email",
		DisablePKCE:      true,
	}
	if err := srv.applyManagedOAuthProvider(&req); err != nil {
		t.Fatalf("applyManagedOAuthProvider: %v", err)
	}

	provider := testManagedGoogleProvider()
	if req.AuthorizationURL != provider.AuthorizationURL {
		t.Errorf("AuthorizationURL = %q, want %q", req.AuthorizationURL, provider.AuthorizationURL)
	}
	if req.TokenURL != provider.TokenURL {
		t.Errorf("TokenURL = %q, want %q", req.TokenURL, provider.TokenURL)
	}
	if req.ClientID != provider.ClientID {
		t.Errorf("ClientID = %q, want %q", req.ClientID, provider.ClientID)
	}
	if req.ClientSecret != "" {
		t.Errorf("ClientSecret = %q, want empty so it is not persisted", req.ClientSecret)
	}
	if req.TokenAuthMethod != provider.TokenAuthMethod {
		t.Errorf("TokenAuthMethod = %q, want %q", req.TokenAuthMethod, provider.TokenAuthMethod)
	}
	if req.DisablePKCE {
		t.Error("DisablePKCE = true, want managed provider policy to require PKCE")
	}
}

func TestApplyManagedGitHubOAuthProviderDropsCallerScopes(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGitHubProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	req := oauthConnectRequest{
		Provider:         "github",
		AuthorizationURL: "https://attacker.example/authorize",
		TokenURL:         "https://attacker.example/token",
		ClientID:         "attacker-client-id",
		ClientSecret:     "attacker-client-secret",
		TokenAuthMethod:  "client_secret_basic",
		Scopes:           "repo workflow",
		DisablePKCE:      true,
	}
	if err := srv.applyManagedOAuthProvider(&req); err != nil {
		t.Fatalf("applyManagedOAuthProvider: %v", err)
	}

	if req.AuthorizationURL != provider.AuthorizationURL || req.TokenURL != provider.TokenURL {
		t.Fatalf("managed endpoints were not authoritative: authorization=%q token=%q", req.AuthorizationURL, req.TokenURL)
	}
	if req.ClientID != provider.ClientID || req.ClientSecret != "" || req.TokenAuthMethod != "client_secret_post" {
		t.Fatalf("managed client configuration was not authoritative: %+v", req)
	}
	if req.Scopes != "" {
		t.Fatalf("Scopes = %q, want empty for GitHub App user authorization", req.Scopes)
	}
	if req.DisablePKCE {
		t.Error("DisablePKCE = true, want managed GitHub to require PKCE")
	}

	authorizationURL := oauth.BuildAuthorizationURL(
		req.AuthorizationURL,
		req.ClientID,
		"https://vault.example/v1/oauth/callback",
		"state",
		"challenge",
		req.Scopes,
		" ",
		req.DisablePKCE,
	)
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if _, ok := parsed.Query()["scope"]; ok {
		t.Fatalf("authorization URL contains classic OAuth scope: %s", authorizationURL)
	}
}

func TestApplyManagedOAuthProviderRejectsMissingRequiredScopes(t *testing.T) {
	srv := newTestServer()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{testManagedGoogleProvider()})

	for _, scopes := range []string{"", " \t\n"} {
		req := oauthConnectRequest{Provider: "google", Scopes: scopes}
		err := srv.applyManagedOAuthProvider(&req)
		if err == nil {
			t.Fatalf("applyManagedOAuthProvider succeeded with scopes %q", scopes)
		}
		if got, want := err.Error(), `managed OAuth provider "google" requires at least one scope`; got != want {
			t.Fatalf("applyManagedOAuthProvider error = %q, want %q", got, want)
		}
	}
}

func TestApplyManagedOAuthProviderRejectsUnknownProvider(t *testing.T) {
	srv := newTestServer()
	req := oauthConnectRequest{Provider: "google"}

	if err := srv.applyManagedOAuthProvider(&req); err == nil {
		t.Fatal("applyManagedOAuthProvider succeeded for an unconfigured provider")
	}
}

func TestManagedOAuthProviderForConfig(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGoogleProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	config := &store.CredentialOAuth{
		AuthorizationURL: provider.AuthorizationURL,
		TokenURL:         provider.TokenURL,
		ClientID:         provider.ClientID,
		Scopes:           "openid email",
		ScopeSeparator:   " ",
		TokenAuthMethod:  provider.TokenAuthMethod,
	}
	got, managed, err := srv.managedOAuthProviderForConfig(config)
	if err != nil || !managed || got.ID != "google" {
		t.Fatalf("managedOAuthProviderForConfig = (%q, %v, %v), want google managed", got.ID, managed, err)
	}
	config.TokenURL = "https://attacker.example/token"
	got, managed, err = srv.managedOAuthProviderForConfig(config)
	if err != nil || managed || got.ID != "" {
		t.Fatalf("managedOAuthProviderForConfig mismatch = (%q, %v, %v), want unmanaged", got.ID, managed, err)
	}
}

func TestManagedOAuthProviderIDsSorted(t *testing.T) {
	srv := newTestServer()
	google := testManagedGoogleProvider()
	github := google
	github.ID = "github"
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{google, github})

	got := srv.managedOAuthProviderIDs()
	if len(got) != 2 || got[0] != "github" || got[1] != "google" {
		t.Fatalf("managedOAuthProviderIDs = %v, want [github google]", got)
	}
}

func TestOAuthClientSecretUsesCurrentManagedValue(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGoogleProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	config := &store.CredentialOAuth{
		ManagedProvider:  stringPointer("google"),
		AuthorizationURL: provider.AuthorizationURL,
		TokenURL:         provider.TokenURL,
		ClientID:         provider.ClientID,
		Scopes:           "openid email",
		ScopeSeparator:   " ",
		TokenAuthMethod:  provider.TokenAuthMethod,
	}

	got, err := srv.oauthClientSecret(config)
	if err != nil {
		t.Fatalf("oauthClientSecret: %v", err)
	}
	if got != provider.ClientSecret {
		t.Fatalf("oauthClientSecret = %q, want current managed secret", got)
	}
}

func TestOAuthClientSecretRejectsExplicitGenericTupleSpoof(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGitHubProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	got, err := srv.oauthClientSecret(&store.CredentialOAuth{
		ManagedProvider:  stringPointer(""),
		AuthorizationURL: provider.AuthorizationURL,
		TokenURL:         provider.TokenURL,
		ClientID:         provider.ClientID,
		ScopeSeparator:   " ",
		TokenAuthMethod:  provider.TokenAuthMethod,
	})
	if err != nil {
		t.Fatalf("oauthClientSecret: %v", err)
	}
	if got != "" {
		t.Fatalf("tuple spoof resolved operator secret")
	}
}

func TestOAuthClientSecretRejectsManagedPolicyMismatch(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGitHubProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	_, err := srv.oauthClientSecret(&store.CredentialOAuth{
		ManagedProvider:  stringPointer("github"),
		AuthorizationURL: provider.AuthorizationURL,
		TokenURL:         provider.TokenURL,
		ClientID:         provider.ClientID,
		ScopeSeparator:   " ",
		TokenAuthMethod:  provider.TokenAuthMethod,
		DisablePKCE:      true,
	})
	if err == nil {
		t.Fatal("oauthClientSecret accepted managed config with PKCE disabled")
	}
}

func TestOAuthClientSecretSupportsLegacyExactManagedConfig(t *testing.T) {
	srv := newTestServer()
	provider := testManagedGoogleProvider()
	srv.SetManagedOAuthProviders([]oauth.ManagedProvider{provider})

	got, err := srv.oauthClientSecret(&store.CredentialOAuth{
		AuthorizationURL: provider.AuthorizationURL,
		TokenURL:         provider.TokenURL,
		ClientID:         provider.ClientID,
		Scopes:           "openid email",
		ScopeSeparator:   " ",
		TokenAuthMethod:  provider.TokenAuthMethod,
	})
	if err != nil {
		t.Fatalf("oauthClientSecret: %v", err)
	}
	if got != provider.ClientSecret {
		t.Fatalf("oauthClientSecret = %q, want legacy managed secret", got)
	}
}

func TestOAuthClientSecretFallsBackToStoredValue(t *testing.T) {
	srv := newTestServer()
	secretCT, secretNonce, err := crypto.Encrypt([]byte("stored-secret"), srv.encKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	config := &store.CredentialOAuth{
		AuthorizationURL:  "https://custom.example.com/authorize",
		TokenURL:          "https://custom.example.com/token",
		ClientID:          "custom-client-id",
		ClientSecretCT:    secretCT,
		ClientSecretNonce: secretNonce,
	}

	got, err := srv.oauthClientSecret(config)
	if err != nil {
		t.Fatalf("oauthClientSecret: %v", err)
	}
	if got != "stored-secret" {
		t.Fatalf("oauthClientSecret = %q, want stored secret", got)
	}
}
