// Package githubapp implements the operator-owned GitHub App machine identity
// used for MindRoom repository provisioning and repository-scoped proxy auth.
package githubapp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	EnvAppID            = "AGENT_VAULT_MINDROOM_GITHUB_APP_ID"
	EnvInstallationID   = "AGENT_VAULT_MINDROOM_GITHUB_APP_INSTALLATION_ID"
	EnvOrganization     = "AGENT_VAULT_MINDROOM_GITHUB_ORGANIZATION"
	EnvOrganizationID   = "AGENT_VAULT_MINDROOM_GITHUB_APP_ORGANIZATION_ID"
	EnvRepositoryPrefix = "AGENT_VAULT_MINDROOM_GITHUB_REPOSITORY_PREFIX"
	EnvPrivateKeyFile   = "AGENT_VAULT_MINDROOM_GITHUB_APP_PRIVATE_KEY_FILE"
	EnvBrokerTokenFile  = "AGENT_VAULT_MINDROOM_REPOSITORY_BROKER_TOKEN_FILE"
)

var configEnvNames = []string{
	EnvAppID,
	EnvInstallationID,
	EnvOrganization,
	EnvOrganizationID,
	EnvRepositoryPrefix,
	EnvPrivateKeyFile,
	EnvBrokerTokenFile,
}

// Config contains non-secret identity metadata, a parsed private key, and a
// one-way hash of the control-plane broker token. Raw file bytes are discarded.
type Config struct {
	AppID             int64
	InstallationID    int64
	Organization      string
	OrganizationID    int64
	RepositoryPrefix  string
	PrivateKey        *rsa.PrivateKey
	brokerTokenSHA256 [sha256.Size]byte
}

// LoadConfigFromEnv returns nil when the feature is fully absent. Partial
// configuration fails closed so a deployment cannot appear enabled while
// silently omitting one security boundary.
func LoadConfigFromEnv() (*Config, error) {
	present := 0
	values := make(map[string]string, len(configEnvNames))
	for _, name := range configEnvNames {
		values[name] = strings.TrimSpace(os.Getenv(name))
		if values[name] != "" {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	if present != len(configEnvNames) {
		return nil, fmt.Errorf("MindRoom GitHub App configuration is incomplete: all %d variables are required", len(configEnvNames))
	}

	appID, err := parsePositiveID(values[EnvAppID], EnvAppID)
	if err != nil {
		return nil, err
	}
	installationID, err := parsePositiveID(values[EnvInstallationID], EnvInstallationID)
	if err != nil {
		return nil, err
	}
	organizationID, err := parsePositiveID(values[EnvOrganizationID], EnvOrganizationID)
	if err != nil {
		return nil, err
	}
	if values[EnvOrganization] == "" {
		return nil, fmt.Errorf("%s must not be empty", EnvOrganization)
	}
	if values[EnvRepositoryPrefix] == "" {
		return nil, fmt.Errorf("%s must not be empty", EnvRepositoryPrefix)
	}

	privateKey, err := readRSAPrivateKey(values[EnvPrivateKeyFile])
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", EnvPrivateKeyFile, err)
	}
	tokenHash, err := readBrokerTokenHash(values[EnvBrokerTokenFile])
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", EnvBrokerTokenFile, err)
	}

	return &Config{
		AppID:             appID,
		InstallationID:    installationID,
		Organization:      values[EnvOrganization],
		OrganizationID:    organizationID,
		RepositoryPrefix:  values[EnvRepositoryPrefix],
		PrivateKey:        privateKey,
		brokerTokenSHA256: tokenHash,
	}, nil
}

func parsePositiveID(value, name string) (int64, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%s must be a positive decimal integer", name)
	}
	return id, nil
}

func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	defer wipe(raw)

	block, _ := pem.Decode(raw)
	if block == nil || block.Headers["DEK-Info"] != "" || strings.Contains(strings.ToUpper(block.Headers["Proc-Type"]), "ENCRYPTED") {
		return nil, fmt.Errorf("private key must be an unencrypted PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key must contain PKCS#1 or PKCS#8 RSA material")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}
	return key, nil
}

func readBrokerTokenHash(path string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read broker token file: %w", err)
	}
	defer wipe(raw)
	token := bytes.TrimSpace(raw)
	if len(token) < 32 {
		return zero, fmt.Errorf("broker token must contain at least 32 bytes")
	}
	return sha256.Sum256(token), nil
}

// AuthenticateBrokerToken compares a presented token with the configured
// one-way hash in constant time. The configured plaintext is never retained.
func (c *Config) AuthenticateBrokerToken(token string) bool {
	if c == nil || token == "" {
		return false
	}
	presented := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(presented[:], c.brokerTokenSHA256[:]) == 1
}

// repositoryMarker produces a deterministic, non-secret ownership marker for
// recovering an exact repository after an ambiguous GitHub create response.
// Length-prefixing makes the scoped input tuple unambiguous.
func (c *Config) repositoryMarker(vaultID, workerHash, organization, repositoryName string) string {
	mac := hmac.New(sha256.New, c.brokerTokenSHA256[:])
	for _, value := range []string{vaultID, workerHash, organization, repositoryName} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(value))
	}
	return "agent-vault-mindroom-v1:" + hex.EncodeToString(mac.Sum(nil))
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
