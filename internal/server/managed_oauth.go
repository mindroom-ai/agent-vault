package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

// SetManagedOAuthProviders configures OAuth applications supplied by the
// instance operator. It must be called before the server starts.
func (s *Server) SetManagedOAuthProviders(providers []oauth.ManagedProvider) {
	s.managedOAuthProviders = make(map[string]oauth.ManagedProvider, len(providers))
	for _, provider := range providers {
		if provider.ID == "" {
			continue
		}
		s.managedOAuthProviders[provider.ID] = provider
	}
}

func (s *Server) managedOAuthProviderIDs() []string {
	ids := make([]string, 0, len(s.managedOAuthProviders))
	for id := range s.managedOAuthProviders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Server) applyManagedOAuthProvider(req *oauthConnectRequest) error {
	if req.Provider == "" {
		return nil
	}

	provider, ok := s.managedOAuthProviders[req.Provider]
	if !ok {
		return fmt.Errorf("managed OAuth provider %q is not configured", req.Provider)
	}
	if provider.RequireScopes && strings.TrimSpace(req.Scopes) == "" {
		return fmt.Errorf("managed OAuth provider %q requires at least one scope", req.Provider)
	}

	req.AuthorizationURL = provider.AuthorizationURL
	req.TokenURL = provider.TokenURL
	req.ClientID = provider.ClientID
	// Never persist the shared secret in a vault credential. Callback and
	// refresh paths resolve the current operator-managed value at runtime.
	req.ClientSecret = ""
	req.TokenAuthMethod = provider.TokenAuthMethod
	return nil
}

func (s *Server) managedOAuthProviderForConfig(authorizationURL, tokenURL, clientID string) string {
	for _, id := range s.managedOAuthProviderIDs() {
		provider := s.managedOAuthProviders[id]
		if provider.AuthorizationURL == authorizationURL &&
			provider.TokenURL == tokenURL &&
			provider.ClientID == clientID {
			return id
		}
	}
	return ""
}

type managedOAuthClientSecretResolver struct{ server *Server }

func (r managedOAuthClientSecretResolver) ResolveOAuthClientSecret(config *store.CredentialOAuth) (string, bool) {
	if config == nil {
		return "", false
	}
	id := r.server.managedOAuthProviderForConfig(config.AuthorizationURL, config.TokenURL, config.ClientID)
	if id == "" {
		return "", false
	}
	provider, ok := r.server.managedOAuthProviders[id]
	if !ok {
		return "", false
	}
	return provider.ClientSecret, true
}

func (s *Server) oauthClientSecret(config *store.CredentialOAuth) (string, error) {
	if secret, ok := (managedOAuthClientSecretResolver{s}).ResolveOAuthClientSecret(config); ok {
		return secret, nil
	}
	if len(config.ClientSecretCT) == 0 {
		return "", nil
	}
	secret, err := crypto.Decrypt(config.ClientSecretCT, config.ClientSecretNonce, s.encKey)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}
