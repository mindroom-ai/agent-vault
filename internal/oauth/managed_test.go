package oauth

import (
	"os"
	"strings"
	"testing"
)

func clearManagedProviderEnv(t *testing.T) {
	t.Helper()
	t.Setenv(GoogleOAuthClientIDEnv, "")
	t.Setenv(GoogleOAuthClientSecretEnv, "")
	t.Setenv(GitHubOAuthClientIDEnv, "")
	t.Setenv(GitHubOAuthClientSecretEnv, "")
}

func TestLoadManagedProvidersFromEnvDisabled(t *testing.T) {
	clearManagedProviderEnv(t)

	providers, err := LoadManagedProvidersFromEnv()
	if err != nil {
		t.Fatalf("LoadManagedProvidersFromEnv: %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("providers = %d, want 0", len(providers))
	}
}

func TestLoadManagedProvidersFromEnvGoogle(t *testing.T) {
	clearManagedProviderEnv(t)
	t.Setenv(GoogleOAuthClientIDEnv, " google-client-id ")
	t.Setenv(GoogleOAuthClientSecretEnv, " google-client-secret ")

	providers, err := LoadManagedProvidersFromEnv()
	if err != nil {
		t.Fatalf("LoadManagedProvidersFromEnv: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}

	got := providers[0]
	if got.ID != "google" {
		t.Errorf("ID = %q, want google", got.ID)
	}
	if got.ClientID != "google-client-id" {
		t.Errorf("ClientID = %q, want trimmed client ID", got.ClientID)
	}
	if got.ClientSecret != "google-client-secret" {
		t.Errorf("ClientSecret = %q, want configured secret", got.ClientSecret)
	}
	if !got.RequireScopes {
		t.Error("RequireScopes = false, want true for Google")
	}
	if !strings.Contains(got.AuthorizationURL, "access_type=offline") || !strings.Contains(got.AuthorizationURL, "prompt=consent") {
		t.Errorf("AuthorizationURL = %q, want offline consent parameters", got.AuthorizationURL)
	}
	if _, ok := os.LookupEnv(GoogleOAuthClientSecretEnv); ok {
		t.Errorf("%s remained in environment", GoogleOAuthClientSecretEnv)
	}
}

func TestLoadManagedProvidersFromEnvRejectsPartialConfig(t *testing.T) {
	clearManagedProviderEnv(t)
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "missing secret", clientID: "google-client-id"},
		{name: "missing client ID", clientSecret: "google-client-secret"},
		{name: "whitespace secret", clientID: "google-client-id", clientSecret: " \t "},
		{name: "whitespace client ID", clientID: " \t ", clientSecret: "google-client-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(GoogleOAuthClientIDEnv, tt.clientID)
			t.Setenv(GoogleOAuthClientSecretEnv, tt.clientSecret)

			if _, err := LoadManagedProvidersFromEnv(); err == nil {
				t.Fatal("LoadManagedProvidersFromEnv succeeded with partial config")
			}
			if _, ok := os.LookupEnv(GoogleOAuthClientSecretEnv); ok {
				t.Fatalf("%s remained in environment after validation error", GoogleOAuthClientSecretEnv)
			}
		})
	}
}

func TestLoadManagedProvidersFromEnvGitHub(t *testing.T) {
	clearManagedProviderEnv(t)
	t.Setenv(GitHubOAuthClientIDEnv, " github-client-id ")
	t.Setenv(GitHubOAuthClientSecretEnv, " github-client-secret ")

	providers, err := LoadManagedProvidersFromEnv()
	if err != nil {
		t.Fatalf("LoadManagedProvidersFromEnv: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}

	got := providers[0]
	if got.ID != "github" {
		t.Errorf("ID = %q, want github", got.ID)
	}
	if got.AuthorizationURL != "https://github.com/login/oauth/authorize" {
		t.Errorf("AuthorizationURL = %q", got.AuthorizationURL)
	}
	if got.TokenURL != "https://github.com/login/oauth/access_token" {
		t.Errorf("TokenURL = %q", got.TokenURL)
	}
	if got.ClientID != "github-client-id" {
		t.Errorf("ClientID = %q, want trimmed client ID", got.ClientID)
	}
	if got.ClientSecret != "github-client-secret" {
		t.Errorf("ClientSecret = %q, want configured secret", got.ClientSecret)
	}
	if got.TokenAuthMethod != "client_secret_post" {
		t.Errorf("TokenAuthMethod = %q, want client_secret_post", got.TokenAuthMethod)
	}
	if got.RequireScopes {
		t.Error("RequireScopes = true, want false for GitHub App user authorization")
	}
	if _, ok := os.LookupEnv(GitHubOAuthClientSecretEnv); ok {
		t.Errorf("%s remained in environment", GitHubOAuthClientSecretEnv)
	}
}

func TestLoadManagedProvidersFromEnvRejectsPartialGitHubConfig(t *testing.T) {
	clearManagedProviderEnv(t)

	for _, tt := range []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "missing secret", clientID: "github-client-id"},
		{name: "missing client ID", clientSecret: "github-client-secret"},
		{name: "whitespace secret", clientID: "github-client-id", clientSecret: " \t "},
		{name: "whitespace client ID", clientID: " \t ", clientSecret: "github-client-secret"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(GitHubOAuthClientIDEnv, tt.clientID)
			t.Setenv(GitHubOAuthClientSecretEnv, tt.clientSecret)

			if _, err := LoadManagedProvidersFromEnv(); err == nil {
				t.Fatal("LoadManagedProvidersFromEnv succeeded with partial GitHub config")
			}
			if _, ok := os.LookupEnv(GitHubOAuthClientSecretEnv); ok {
				t.Fatalf("%s remained in environment after validation error", GitHubOAuthClientSecretEnv)
			}
		})
	}
}

func TestLoadManagedProvidersFromEnvGoogleAndGitHub(t *testing.T) {
	clearManagedProviderEnv(t)
	t.Setenv(GoogleOAuthClientIDEnv, "google-client-id")
	t.Setenv(GoogleOAuthClientSecretEnv, "google-client-secret")
	t.Setenv("AGENT_VAULT_OAUTH_GITHUB_CLIENT_ID", "github-client-id")
	t.Setenv("AGENT_VAULT_OAUTH_GITHUB_CLIENT_SECRET", "github-client-secret")

	providers, err := LoadManagedProvidersFromEnv()
	if err != nil {
		t.Fatalf("LoadManagedProvidersFromEnv: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(providers))
	}
	if providers[0].ID != "google" || providers[1].ID != "github" {
		t.Fatalf("provider IDs = [%q %q], want [google github]", providers[0].ID, providers[1].ID)
	}
}

func TestLoadManagedProvidersFromEnvClearsAllSecretsBeforeValidation(t *testing.T) {
	clearManagedProviderEnv(t)
	t.Setenv(GoogleOAuthClientIDEnv, "")
	t.Setenv(GoogleOAuthClientSecretEnv, "broken-google-secret")
	t.Setenv(GitHubOAuthClientIDEnv, "github-client-id")
	t.Setenv(GitHubOAuthClientSecretEnv, "github-client-secret")

	if _, err := LoadManagedProvidersFromEnv(); err == nil {
		t.Fatal("LoadManagedProvidersFromEnv succeeded with partial Google config")
	}
	for _, name := range []string{GoogleOAuthClientSecretEnv, GitHubOAuthClientSecretEnv} {
		if _, ok := os.LookupEnv(name); ok {
			t.Fatalf("%s remained in environment after validation error", name)
		}
	}
}
