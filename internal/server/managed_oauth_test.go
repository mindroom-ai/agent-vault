package server

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

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

	if got := srv.managedOAuthProviderForConfig(provider.AuthorizationURL, provider.TokenURL, provider.ClientID); got != "google" {
		t.Errorf("managedOAuthProviderForConfig = %q, want google", got)
	}
	if got := srv.managedOAuthProviderForConfig(provider.AuthorizationURL, "https://attacker.example/token", provider.ClientID); got != "" {
		t.Errorf("managedOAuthProviderForConfig = %q for mismatched token URL, want empty", got)
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

	oldSecretCT, oldSecretNonce, err := crypto.Encrypt([]byte("old-managed-secret"), srv.encKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	config := &store.CredentialOAuth{
		AuthorizationURL:  provider.AuthorizationURL,
		TokenURL:          provider.TokenURL,
		ClientID:          provider.ClientID,
		ClientSecretCT:    oldSecretCT,
		ClientSecretNonce: oldSecretNonce,
	}

	got, err := srv.oauthClientSecret(config)
	if err != nil {
		t.Fatalf("oauthClientSecret: %v", err)
	}
	if got != provider.ClientSecret {
		t.Fatalf("oauthClientSecret = %q, want current managed secret", got)
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
