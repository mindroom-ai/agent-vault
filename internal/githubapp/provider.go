package githubapp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"path"
	"strings"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

type RepositoryCredentialSource interface {
	Binding(context.Context, string) (*store.GitHubRepositoryBinding, error)
	RepositoryToken(context.Context, string) (string, error)
}

type RepositoryCredentialProvider struct {
	source   RepositoryCredentialSource
	fallback brokercore.CredentialProvider
}

func NewRepositoryCredentialProvider(source RepositoryCredentialSource, fallback brokercore.CredentialProvider) *RepositoryCredentialProvider {
	return &RepositoryCredentialProvider{source: source, fallback: fallback}
}

func (p *RepositoryCredentialProvider) Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*brokercore.InjectResult, error) {
	host := targetHost
	if parsedHost, _, err := net.SplitHostPort(targetHost); err == nil {
		host = parsedHost
	}
	if targetPort != 443 || (host != "github.com" && host != "api.github.com") {
		return p.fallback.Inject(ctx, vaultID, targetHost, targetPort, targetPath)
	}

	binding, err := p.source.Binding(ctx, vaultID)
	if errors.Is(err, sql.ErrNoRows) {
		return p.fallback.Inject(ctx, vaultID, targetHost, targetPort, targetPath)
	}
	if err != nil || !validRuntimeBinding(binding, vaultID) {
		return nil, brokercore.ErrServiceNotFound
	}
	if !matchesBoundRepositoryPath(host, targetPath, binding.Organization, binding.RepositoryName) {
		return p.fallback.Inject(ctx, vaultID, targetHost, targetPort, targetPath)
	}

	token, err := p.source.RepositoryToken(ctx, binding.RepositoryID)
	if err != nil {
		return nil, brokercore.ErrCredentialMissing
	}
	authorization := "Bearer " + token
	if host == "github.com" {
		authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	}
	return &brokercore.InjectResult{
		Headers:     map[string]string{"Authorization": authorization},
		MatchedName: "mindroom-github-repository",
		MatchedHost: host,
		MatchedPath: boundRepositoryBasePath(host, binding.Organization, binding.RepositoryName),
	}, nil
}

func validRuntimeBinding(binding *store.GitHubRepositoryBinding, vaultID string) bool {
	return binding != nil && binding.VaultID == vaultID && binding.RepositoryID != "" &&
		binding.Organization != "" && binding.RepositoryName != "" &&
		binding.PermissionsJSON == contentsWritePermissionsJSON
}

func matchesBoundRepositoryPath(host, targetPath, organization, repositoryName string) bool {
	if targetPath == "" || path.Clean(targetPath) != targetPath || strings.Contains(targetPath, "//") {
		return false
	}
	base := boundRepositoryBasePath(host, organization, repositoryName)
	return targetPath == base || strings.HasPrefix(targetPath, base+"/")
}

func boundRepositoryBasePath(host, organization, repositoryName string) string {
	base := "/" + organization + "/" + repositoryName
	if host == "api.github.com" {
		return "/repos" + base
	}
	return base + ".git"
}
