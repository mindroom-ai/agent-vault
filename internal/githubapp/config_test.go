package githubapp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var machineConfigEnv = []string{
	"AGENT_VAULT_MINDROOM_GITHUB_APP_ID",
	"AGENT_VAULT_MINDROOM_GITHUB_APP_INSTALLATION_ID",
	"AGENT_VAULT_MINDROOM_GITHUB_ORGANIZATION",
	"AGENT_VAULT_MINDROOM_GITHUB_APP_ORGANIZATION_ID",
	"AGENT_VAULT_MINDROOM_GITHUB_REPOSITORY_PREFIX",
	"AGENT_VAULT_MINDROOM_GITHUB_APP_PRIVATE_KEY_FILE",
	"AGENT_VAULT_MINDROOM_REPOSITORY_BROKER_TOKEN_FILE",
}

func clearMachineConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range machineConfigEnv {
		t.Setenv(key, "")
	}
}

func writeConfigSecret(t *testing.T, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", name, err)
	}
	return path
}

func rsaPEM(t *testing.T, pkcs8 bool) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func setValidMachineConfigEnv(t *testing.T, pkcs8 bool) string {
	t.Helper()
	clearMachineConfigEnv(t)
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_ID", "101")
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_INSTALLATION_ID", "202")
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_ORGANIZATION", "example-org")
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_ORGANIZATION_ID", "303")
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_REPOSITORY_PREFIX", "MindRoom-")
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_PRIVATE_KEY_FILE", writeConfigSecret(t, "private-key.pem", rsaPEM(t, pkcs8)))
	token := "repository-broker-token-with-at-least-32-bytes"
	t.Setenv("AGENT_VAULT_MINDROOM_REPOSITORY_BROKER_TOKEN_FILE", writeConfigSecret(t, "token", []byte("\n"+token+"\n")))
	return token
}

func TestLoadConfigFromEnvDisabledWhenAllVariablesAbsent(t *testing.T) {
	clearMachineConfigEnv(t)
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}
	if cfg != nil {
		t.Fatalf("config = %+v, want nil", cfg)
	}
}

func TestLoadConfigFromEnvRejectsPartialConfiguration(t *testing.T) {
	clearMachineConfigEnv(t)
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_ID", "101")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("LoadConfigFromEnv succeeded, want partial-config error")
	}
}

func TestLoadConfigFromEnvAcceptsPKCS1AndPKCS8RSAKeys(t *testing.T) {
	for _, pkcs8 := range []bool{false, true} {
		t.Run(map[bool]string{false: "PKCS1", true: "PKCS8"}[pkcs8], func(t *testing.T) {
			token := setValidMachineConfigEnv(t, pkcs8)
			cfg, err := LoadConfigFromEnv()
			if err != nil {
				t.Fatalf("LoadConfigFromEnv: %v", err)
			}
			if cfg.AppID != 101 || cfg.InstallationID != 202 || cfg.OrganizationID != 303 {
				t.Fatalf("numeric identity = (%d, %d, %d), want (101, 202, 303)", cfg.AppID, cfg.InstallationID, cfg.OrganizationID)
			}
			if cfg.Organization != "example-org" || cfg.RepositoryPrefix != "MindRoom-" {
				t.Fatalf("policy = (%q, %q), want (example-org, MindRoom-)", cfg.Organization, cfg.RepositoryPrefix)
			}
			if cfg.PrivateKey == nil {
				t.Fatal("PrivateKey is nil")
			}
			if !cfg.AuthenticateBrokerToken(token) {
				t.Fatal("AuthenticateBrokerToken rejected configured token")
			}
			if cfg.AuthenticateBrokerToken(token + "-wrong") {
				t.Fatal("AuthenticateBrokerToken accepted wrong token")
			}
		})
	}
}

func TestRepositoryMarkerIsDeterministicAndScopedWithoutDisclosingInputs(t *testing.T) {
	setValidMachineConfigEnv(t, false)
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}

	workerHash := HashWorkerKey("worker-redwood")
	marker := cfg.repositoryMarker("vault-redwood", workerHash, "example-org", "MindRoom-redwood")
	if marker != cfg.repositoryMarker("vault-redwood", workerHash, "example-org", "MindRoom-redwood") {
		t.Fatal("RepositoryMarker is not deterministic")
	}
	if !strings.HasPrefix(marker, "agent-vault-mindroom-v1:") {
		t.Fatalf("marker = %q, want versioned prefix", marker)
	}
	for _, raw := range []string{"vault-redwood", workerHash, "example-org", "MindRoom-redwood"} {
		if strings.Contains(marker, raw) {
			t.Fatalf("marker disclosed scoped input %q", raw)
		}
	}
	for _, changed := range []string{
		cfg.repositoryMarker("vault-other", workerHash, "example-org", "MindRoom-redwood"),
		cfg.repositoryMarker("vault-redwood", HashWorkerKey("worker-other"), "example-org", "MindRoom-redwood"),
		cfg.repositoryMarker("vault-redwood", workerHash, "other", "MindRoom-redwood"),
		cfg.repositoryMarker("vault-redwood", workerHash, "example-org", "MindRoom-other"),
	} {
		if changed == marker {
			t.Fatal("RepositoryMarker did not change with scoped input")
		}
	}
}

func TestLoadConfigFromEnvRejectsShortBrokerTokenWithoutDisclosingIt(t *testing.T) {
	setValidMachineConfigEnv(t, false)
	secret := "too-short-secret"
	t.Setenv("AGENT_VAULT_MINDROOM_REPOSITORY_BROKER_TOKEN_FILE", writeConfigSecret(t, "short-token", []byte(secret)))
	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("LoadConfigFromEnv succeeded, want short-token error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed broker token: %v", err)
	}
}

func TestLoadConfigFromEnvRejectsInvalidPrivateKeyWithoutDisclosingIt(t *testing.T) {
	setValidMachineConfigEnv(t, false)
	secret := "not-a-private-key-sensitive-value"
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_PRIVATE_KEY_FILE", writeConfigSecret(t, "bad-private-key.pem", []byte(secret)))
	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("LoadConfigFromEnv succeeded, want private-key error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed private key bytes: %v", err)
	}
}

func TestLoadConfigFromEnvRejectsLegacyEncryptedPEM(t *testing.T) {
	setValidMachineConfigEnv(t, false)
	encrypted := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("encrypted-private-key-bytes"),
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC,00000000000000000000000000000000",
		},
	})
	t.Setenv("AGENT_VAULT_MINDROOM_GITHUB_APP_PRIVATE_KEY_FILE", writeConfigSecret(t, "encrypted-private-key.pem", encrypted))
	_, err := LoadConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "unencrypted PEM") {
		t.Fatalf("LoadConfigFromEnv error = %v, want unencrypted-PEM rejection", err)
	}
}
