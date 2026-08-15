package githubapp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

type fakeRepositoryCredentialSource struct {
	binding    *store.GitHubRepositoryBinding
	bindingErr error
	token      string
	tokenErr   error
	tokenIDs   []string
}

func (s *fakeRepositoryCredentialSource) Binding(context.Context, string) (*store.GitHubRepositoryBinding, error) {
	return s.binding, s.bindingErr
}

func (s *fakeRepositoryCredentialSource) RepositoryToken(_ context.Context, repositoryID string) (string, error) {
	s.tokenIDs = append(s.tokenIDs, repositoryID)
	return s.token, s.tokenErr
}

type fakeFallbackProvider struct {
	calls  int
	result *brokercore.InjectResult
	err    error
}

func (p *fakeFallbackProvider) Inject(context.Context, string, string, int, string) (*brokercore.InjectResult, error) {
	p.calls++
	return p.result, p.err
}

func boundCredentialSource() *fakeRepositoryCredentialSource {
	return &fakeRepositoryCredentialSource{
		binding: &store.GitHubRepositoryBinding{
			VaultID:         "vault-redwood",
			RepositoryID:    "123456789",
			Organization:    "example-org",
			RepositoryName:  "MindRoom-redwood",
			PermissionsJSON: `{"contents":"write"}`,
		},
		token: "runtime-installation-secret",
	}
}

func TestRepositoryCredentialProviderInjectsRepoScopedTokenForExactGitAndAPIPaths(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		path       string
		wantHeader string
	}{
		{
			name:       "Git smart HTTP",
			host:       "github.com",
			path:       "/example-org/MindRoom-redwood.git/git-receive-pack",
			wantHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:runtime-installation-secret")),
		},
		{
			name:       "repository API",
			host:       "api.github.com",
			path:       "/repos/example-org/MindRoom-redwood/contents/README.md",
			wantHeader: "Bearer runtime-installation-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := boundCredentialSource()
			fallback := &fakeFallbackProvider{result: &brokercore.InjectResult{Passthrough: true}}
			provider := NewRepositoryCredentialProvider(source, fallback)
			result, err := provider.Inject(t.Context(), "vault-redwood", tt.host, 443, tt.path)
			if err != nil {
				t.Fatalf("Inject: %v", err)
			}
			if result.Headers["Authorization"] != tt.wantHeader {
				t.Fatalf("Authorization = %q", result.Headers["Authorization"])
			}
			if result.MatchedName != "mindroom-github-repository" || fallback.calls != 0 {
				t.Fatalf("matched name/fallback calls = %q/%d", result.MatchedName, fallback.calls)
			}
			if len(source.tokenIDs) != 1 || source.tokenIDs[0] != "123456789" {
				t.Fatalf("token repository IDs = %v", source.tokenIDs)
			}
		})
	}
}

func TestRepositoryCredentialProviderDoesNotApplyMachineIdentityOutsideExactBinding(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		path string
	}{
		{name: "other GitHub repository", host: "github.com", port: 443, path: "/example-org/other.git/git-receive-pack"},
		{name: "prefix confusion", host: "github.com", port: 443, path: "/example-org/MindRoom-redwood.git-evil/git-receive-pack"},
		{name: "other repository API", host: "api.github.com", port: 443, path: "/repos/example-org/other/contents/file"},
		{name: "organization confusion", host: "api.github.com", port: 443, path: "/repos/example-org-evil/MindRoom-redwood/contents/file"},
		{name: "wrong port", host: "github.com", port: 8443, path: "/example-org/MindRoom-redwood.git/git-receive-pack"},
		{name: "host suffix", host: "github.com.evil.example", port: 443, path: "/example-org/MindRoom-redwood.git/git-receive-pack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := boundCredentialSource()
			fallbackResult := &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer existing-user-oauth"}, MatchedName: "existing-github"}
			fallback := &fakeFallbackProvider{result: fallbackResult}
			provider := NewRepositoryCredentialProvider(source, fallback)
			result, err := provider.Inject(t.Context(), "vault-redwood", tt.host, tt.port, tt.path)
			if err != nil {
				t.Fatalf("Inject: %v", err)
			}
			if result != fallbackResult || fallback.calls != 1 {
				t.Fatalf("result/fallback calls = %#v/%d; want existing OAuth provider", result, fallback.calls)
			}
			if len(source.tokenIDs) != 0 {
				t.Fatalf("machine token minted for unbound target: %v", source.tokenIDs)
			}
		})
	}
}

func TestRepositoryCredentialProviderPreservesFallbackWhenVaultHasNoBinding(t *testing.T) {
	source := &fakeRepositoryCredentialSource{bindingErr: sql.ErrNoRows}
	fallbackResult := &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer existing-user-oauth"}}
	fallback := &fakeFallbackProvider{result: fallbackResult}
	provider := NewRepositoryCredentialProvider(source, fallback)
	result, err := provider.Inject(t.Context(), "unbound-vault", "api.github.com", 443, "/user")
	if err != nil || result != fallbackResult || fallback.calls != 1 {
		t.Fatalf("Inject = %#v, %v; fallback calls = %d", result, err, fallback.calls)
	}
}

func TestRepositoryCredentialProviderFailsClosedOnInvalidBindingOrStoreFailure(t *testing.T) {
	broaderPermissions := boundCredentialSource()
	broaderPermissions.binding.VaultID = "vault"
	broaderPermissions.binding.PermissionsJSON = `{"contents":"write","issues":"write"}`
	tests := []struct {
		name   string
		source *fakeRepositoryCredentialSource
	}{
		{name: "store failure", source: &fakeRepositoryCredentialSource{bindingErr: errors.New("database unavailable")}},
		{name: "broader permissions", source: broaderPermissions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fallback := &fakeFallbackProvider{result: &brokercore.InjectResult{Passthrough: true}}
			provider := NewRepositoryCredentialProvider(tt.source, fallback)
			_, err := provider.Inject(t.Context(), "vault", "api.github.com", 443, "/repos/example-org/MindRoom-redwood/contents/file")
			if err == nil {
				t.Fatal("Inject succeeded, want fail-closed error")
			}
			if fallback.calls != 0 || len(tt.source.tokenIDs) != 0 {
				t.Fatalf("fallback/token calls = %d/%v, want 0/none", fallback.calls, tt.source.tokenIDs)
			}
		})
	}
}
