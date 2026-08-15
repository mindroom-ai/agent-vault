package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func clearGitHubRepositoryEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		githubapp.EnvAppID,
		githubapp.EnvInstallationID,
		githubapp.EnvOrganization,
		githubapp.EnvOrganizationID,
		githubapp.EnvRepositoryPrefix,
		githubapp.EnvPrivateKeyFile,
		githubapp.EnvBrokerTokenFile,
	} {
		t.Setenv(name, "")
	}
}

func testRepositoryServer(t *testing.T) (*server.Server, *store.SQLStore) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "agent-vault.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return server.New("127.0.0.1:0", db, make([]byte, 32), nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler)), db
}

func TestAttachGitHubRepositoriesIfConfiguredDisabled(t *testing.T) {
	clearGitHubRepositoryEnv(t)
	srv, db := testRepositoryServer(t)
	if err := attachGitHubRepositoriesIfConfigured(srv, db); err != nil {
		t.Fatalf("attachGitHubRepositoriesIfConfigured: %v", err)
	}
	if _, ok := srv.CredentialProvider().(*brokercore.StoreCredentialProvider); !ok {
		t.Fatalf("provider type = %T, want unchanged store provider", srv.CredentialProvider())
	}
}

func TestAttachGitHubRepositoriesIfConfiguredChainsRepositoryProvider(t *testing.T) {
	clearGitHubRepositoryEnv(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "private-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	tokenPath := filepath.Join(t.TempDir(), "broker-token")
	if err := os.WriteFile(tokenPath, []byte("broker-control-plane-token-at-least-32-bytes"), 0o600); err != nil {
		t.Fatalf("write broker token: %v", err)
	}
	t.Setenv(githubapp.EnvAppID, "101")
	t.Setenv(githubapp.EnvInstallationID, "202")
	t.Setenv(githubapp.EnvOrganization, "example-org")
	t.Setenv(githubapp.EnvOrganizationID, "303")
	t.Setenv(githubapp.EnvRepositoryPrefix, "MindRoom-")
	t.Setenv(githubapp.EnvPrivateKeyFile, keyPath)
	t.Setenv(githubapp.EnvBrokerTokenFile, tokenPath)

	srv, db := testRepositoryServer(t)
	if err := attachGitHubRepositoriesIfConfigured(srv, db); err != nil {
		t.Fatalf("attachGitHubRepositoriesIfConfigured: %v", err)
	}
	if _, ok := srv.CredentialProvider().(*githubapp.RepositoryCredentialProvider); !ok {
		t.Fatalf("provider type = %T, want repository provider", srv.CredentialProvider())
	}
}

func TestAttachGitHubRepositoriesIfConfiguredRejectsPartialIdentity(t *testing.T) {
	clearGitHubRepositoryEnv(t)
	t.Setenv(githubapp.EnvAppID, "101")
	srv, db := testRepositoryServer(t)
	if err := attachGitHubRepositoriesIfConfigured(srv, db); err == nil {
		t.Fatal("attachGitHubRepositoriesIfConfigured succeeded, want partial config error")
	}
}
