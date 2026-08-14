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
	if provider.OmitScopes {
		req.Scopes = ""
	}
	req.ScopeSeparator = " "
	req.DisablePKCE = false

	req.AuthorizationURL = provider.AuthorizationURL
	req.TokenURL = provider.TokenURL
	req.ClientID = provider.ClientID
	// Never persist the shared secret in a vault credential. Callback and
	// refresh paths resolve the current operator-managed value at runtime.
	req.ClientSecret = ""
	req.TokenAuthMethod = provider.TokenAuthMethod
	return nil
}

func (s *Server) legacyManagedOAuthProviderForConfig(config *store.CredentialOAuth) string {
	for _, id := range s.managedOAuthProviderIDs() {
		provider := s.managedOAuthProviders[id]
		if provider.AuthorizationURL == config.AuthorizationURL &&
			provider.TokenURL == config.TokenURL &&
			provider.ClientID == config.ClientID {
			return id
		}
	}
	return ""
}

func (s *Server) managedOAuthProviderForConfig(config *store.CredentialOAuth) (oauth.ManagedProvider, bool, error) {
	if config == nil {
		return oauth.ManagedProvider{}, false, nil
	}

	id := ""
	if config.ManagedProvider != nil {
		id = *config.ManagedProvider
		if id == "" {
			return oauth.ManagedProvider{}, false, nil
		}
	} else {
		// Rows created before managed-provider provenance was persisted remain
		// compatible only when their full stored policy is an exact match.
		id = s.legacyManagedOAuthProviderForConfig(config)
		if id == "" {
			return oauth.ManagedProvider{}, false, nil
		}
	}

	provider, ok := s.managedOAuthProviders[id]
	if !ok {
		return oauth.ManagedProvider{}, true, fmt.Errorf("managed OAuth provider %q is not configured", id)
	}
	if config.AuthorizationURL != provider.AuthorizationURL ||
		config.TokenURL != provider.TokenURL ||
		config.ClientID != provider.ClientID ||
		config.TokenAuthMethod != provider.TokenAuthMethod ||
		config.ScopeSeparator != " " || config.DisablePKCE ||
		len(config.ClientSecretCT) != 0 || len(config.ClientSecretNonce) != 0 {
		return oauth.ManagedProvider{}, true, fmt.Errorf("managed OAuth provider %q configuration does not match operator policy", id)
	}
	if provider.RequireScopes && strings.TrimSpace(config.Scopes) == "" {
		return oauth.ManagedProvider{}, true, fmt.Errorf("managed OAuth provider %q requires at least one scope", id)
	}
	if provider.OmitScopes && strings.TrimSpace(config.Scopes) != "" {
		return oauth.ManagedProvider{}, true, fmt.Errorf("managed OAuth provider %q does not accept caller scopes", id)
	}
	return provider, true, nil
}

type managedOAuthClientSecretResolver struct{ server *Server }

func (r managedOAuthClientSecretResolver) ResolveOAuthClientSecret(config *store.CredentialOAuth) (string, bool, error) {
	provider, managed, err := r.server.managedOAuthProviderForConfig(config)
	if err != nil || !managed {
		return "", managed, err
	}
	return provider.ClientSecret, true, nil
}

func (s *Server) oauthClientSecret(config *store.CredentialOAuth) (string, error) {
	secret, managed, err := (managedOAuthClientSecretResolver{s}).ResolveOAuthClientSecret(config)
	if err != nil {
		return "", err
	}
	if managed {
		return secret, nil
	}
	if len(config.ClientSecretCT) == 0 {
		return "", nil
	}
	secretBytes, err := crypto.Decrypt(config.ClientSecretCT, config.ClientSecretNonce, s.encKey)
	if err != nil {
		return "", err
	}
	return string(secretBytes), nil
}
