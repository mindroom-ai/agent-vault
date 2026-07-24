package brokercore

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

type staticOAuthClientSecretResolver struct {
	secret string
	ok     bool
}

func (r staticOAuthClientSecretResolver) ResolveOAuthClientSecret(_ *store.CredentialOAuth) (string, bool) {
	return r.secret, r.ok
}

func TestResolveOAuthClientSecretPrefersManagedValue(t *testing.T) {
	key := make32(0x42)
	storedCT, storedNonce, err := crypto.Encrypt([]byte("stored-secret"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	provider := &StoreCredentialProvider{
		EncKey:       key,
		OAuthSecrets: staticOAuthClientSecretResolver{secret: "current-managed-secret", ok: true},
	}

	got, err := provider.resolveOAuthClientSecret(&store.CredentialOAuth{
		ClientSecretCT:    storedCT,
		ClientSecretNonce: storedNonce,
	})
	if err != nil {
		t.Fatalf("resolveOAuthClientSecret: %v", err)
	}
	if got != "current-managed-secret" {
		t.Fatalf("resolveOAuthClientSecret = %q, want current managed secret", got)
	}
}

func TestResolveOAuthClientSecretFallsBackToStoredValue(t *testing.T) {
	key := make32(0x43)
	storedCT, storedNonce, err := crypto.Encrypt([]byte("stored-secret"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	provider := &StoreCredentialProvider{
		EncKey:       key,
		OAuthSecrets: staticOAuthClientSecretResolver{},
	}

	got, err := provider.resolveOAuthClientSecret(&store.CredentialOAuth{
		ClientSecretCT:    storedCT,
		ClientSecretNonce: storedNonce,
	})
	if err != nil {
		t.Fatalf("resolveOAuthClientSecret: %v", err)
	}
	if got != "stored-secret" {
		t.Fatalf("resolveOAuthClientSecret = %q, want stored secret", got)
	}
}
