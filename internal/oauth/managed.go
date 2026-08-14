package oauth

import (
	"fmt"
	"os"
	"strings"
)

const (
	// GoogleOAuthClientIDEnv and GoogleOAuthClientSecretEnv configure the
	// instance-managed Google OAuth application.
	GoogleOAuthClientIDEnv     = "AGENT_VAULT_OAUTH_GOOGLE_CLIENT_ID"
	GoogleOAuthClientSecretEnv = "AGENT_VAULT_OAUTH_GOOGLE_CLIENT_SECRET"

	// GitHubOAuthClientIDEnv and GitHubOAuthClientSecretEnv configure the
	// instance-managed GitHub App user authorization flow.
	GitHubOAuthClientIDEnv     = "AGENT_VAULT_OAUTH_GITHUB_CLIENT_ID"
	GitHubOAuthClientSecretEnv = "AGENT_VAULT_OAUTH_GITHUB_CLIENT_SECRET"
)

// ManagedProvider is an OAuth application configured by the instance operator.
// Vault users authorize their own accounts, but do not need to create or supply
// an OAuth client.
type ManagedProvider struct {
	ID               string
	AuthorizationURL string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	TokenAuthMethod  string
	RequireScopes    bool
	OmitScopes       bool
}

// LoadManagedProvidersFromEnv loads operator-managed OAuth applications.
// A partially configured provider fails closed instead of falling back to
// user-supplied client credentials unexpectedly.
func LoadManagedProvidersFromEnv() ([]ManagedProvider, error) {
	googleClientID := strings.TrimSpace(os.Getenv(GoogleOAuthClientIDEnv))
	googleClientSecret := strings.TrimSpace(os.Getenv(GoogleOAuthClientSecretEnv))
	githubClientID := strings.TrimSpace(os.Getenv(GitHubOAuthClientIDEnv))
	githubClientSecret := strings.TrimSpace(os.Getenv(GitHubOAuthClientSecretEnv))

	// Keep secrets in process memory after startup, not in the inherited
	// environment where child processes could read them. Clear both before
	// validation so fail-closed startup paths do not retain either secret.
	_ = os.Unsetenv(GoogleOAuthClientSecretEnv)
	_ = os.Unsetenv(GitHubOAuthClientSecretEnv)

	if (googleClientID == "") != (googleClientSecret == "") {
		return nil, fmt.Errorf("%s and %s must be set together", GoogleOAuthClientIDEnv, GoogleOAuthClientSecretEnv)
	}
	if (githubClientID == "") != (githubClientSecret == "") {
		return nil, fmt.Errorf("%s and %s must be set together", GitHubOAuthClientIDEnv, GitHubOAuthClientSecretEnv)
	}

	providers := make([]ManagedProvider, 0, 2)
	if googleClientID != "" {
		providers = append(providers, ManagedProvider{
			ID:               "google",
			AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent",
			TokenURL:         "https://oauth2.googleapis.com/token",
			ClientID:         googleClientID,
			ClientSecret:     googleClientSecret,
			TokenAuthMethod:  "client_secret_post",
			RequireScopes:    true,
		})
	}
	if githubClientID != "" {
		providers = append(providers, ManagedProvider{
			ID:               "github",
			AuthorizationURL: "https://github.com/login/oauth/authorize",
			TokenURL:         "https://github.com/login/oauth/access_token",
			ClientID:         githubClientID,
			ClientSecret:     githubClientSecret,
			TokenAuthMethod:  "client_secret_post",
			RequireScopes:    false,
			OmitScopes:       true,
		})
	}

	return providers, nil
}
