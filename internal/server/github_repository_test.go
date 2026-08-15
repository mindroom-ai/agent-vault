package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/store"
)

type fakeGitHubRepositoryManager struct {
	authToken string
	request   githubapp.EnsureRequest
	vaultID   string
	lease     githubapp.RepositoryLease
	created   bool
	err       error
	calls     int
	binding   *store.GitHubRepositoryBinding
	token     string
	tokenIDs  []string
}

func (m *fakeGitHubRepositoryManager) AuthenticateBrokerToken(token string) bool {
	return token == m.authToken
}

func (m *fakeGitHubRepositoryManager) EnsureRepository(_ context.Context, vaultID string, request githubapp.EnsureRequest) (githubapp.RepositoryLease, bool, error) {
	m.calls++
	m.vaultID = vaultID
	m.request = request
	return m.lease, m.created, m.err
}

func (m *fakeGitHubRepositoryManager) Binding(context.Context, string) (*store.GitHubRepositoryBinding, error) {
	if m.binding == nil {
		return nil, sql.ErrNoRows
	}
	return m.binding, nil
}

func (m *fakeGitHubRepositoryManager) RepositoryToken(_ context.Context, repositoryID string) (string, error) {
	m.tokenIDs = append(m.tokenIDs, repositoryID)
	return m.token, nil
}

func repositoryEnsureRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mindroom/repositories/ensure", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer broker-control-plane-token")
	req.Header.Set("X-Vault", "default")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestMindRoomRepositoryEnsureUsesDedicatedAuthAndReturnsNoCredential(t *testing.T) {
	manager := &fakeGitHubRepositoryManager{
		authToken: "broker-control-plane-token",
		created:   true,
		lease: githubapp.RepositoryLease{
			RepositoryID:   "123456789",
			Organization:   "example-org",
			RepositoryName: "MindRoom-redwood",
			CloneURL:       "https://github.com/example-org/MindRoom-redwood.git",
		},
	}
	srv := newTestServer()
	srv.AttachGitHubRepositoryManager(manager)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, repositoryEnsureRequest(`{"worker_key":"worker-redwood","organization":"example-org","repository_name":"MindRoom-redwood"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if manager.calls != 1 || manager.vaultID != "root-ns-id" || manager.request.WorkerKey != "worker-redwood" {
		t.Fatalf("manager call = %d vault=%q request=%+v", manager.calls, manager.vaultID, manager.request)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	wantKeys := map[string]bool{"repository_id": true, "organization": true, "repository_name": true, "clone_url": true}
	if len(response) != len(wantKeys) {
		t.Fatalf("response fields = %#v, want credential-free lease", response)
	}
	for key := range response {
		if !wantKeys[key] {
			t.Fatalf("unexpected response field %q", key)
		}
	}
	if strings.Contains(rec.Body.String(), "token") || strings.Contains(rec.Body.String(), "credential") || strings.Contains(rec.Body.String(), "worker-redwood") {
		t.Fatalf("response disclosed sensitive input or credential field: %s", rec.Body.String())
	}
}

func TestMindRoomRepositoryEnsureRejectsOrdinaryAgentSessionToken(t *testing.T) {
	ms, ordinaryToken := setupMockStoreWithSession(t)
	manager := &fakeGitHubRepositoryManager{authToken: "broker-control-plane-token"}
	srv := newTestServer(withStore(ms))
	srv.AttachGitHubRepositoryManager(manager)
	req := repositoryEnsureRequest(`{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`)
	req.Header.Set("Authorization", "Bearer "+ordinaryToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || manager.calls != 0 {
		t.Fatalf("status/calls = %d/%d, want 401/0", rec.Code, manager.calls)
	}
}

func TestMindRoomRepositoryEnsureValidatesBoundaryAndMapsConflicts(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*http.Request, *fakeGitHubRepositoryManager)
		body       string
		wantStatus int
	}{
		{name: "feature disabled", configure: func(_ *http.Request, _ *fakeGitHubRepositoryManager) {}, body: `{}`, wantStatus: http.StatusServiceUnavailable},
		{name: "missing vault", configure: func(r *http.Request, _ *fakeGitHubRepositoryManager) { r.Header.Del("X-Vault") }, body: `{}`, wantStatus: http.StatusBadRequest},
		{name: "unknown vault", configure: func(r *http.Request, _ *fakeGitHubRepositoryManager) { r.Header.Set("X-Vault", "unknown") }, body: `{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`, wantStatus: http.StatusNotFound},
		{name: "unknown request field", body: `{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent","permissions":{"administration":"write"}}`, wantStatus: http.StatusBadRequest},
		{name: "immutable conflict", configure: func(_ *http.Request, m *fakeGitHubRepositoryManager) { m.err = githubapp.ErrBindingConflict }, body: `{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`, wantStatus: http.StatusConflict},
		{name: "GitHub collision", configure: func(_ *http.Request, m *fakeGitHubRepositoryManager) { m.err = githubapp.ErrRepositoryCollision }, body: `{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`, wantStatus: http.StatusConflict},
		{name: "GitHub validation rejection", configure: func(_ *http.Request, m *fakeGitHubRepositoryManager) { m.err = githubapp.ErrRepositoryCreateRejected }, body: `{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`, wantStatus: http.StatusBadGateway},
		{name: "upstream failure", configure: func(_ *http.Request, m *fakeGitHubRepositoryManager) { m.err = errors.New("github unavailable") }, body: `{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`, wantStatus: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &fakeGitHubRepositoryManager{authToken: "broker-control-plane-token"}
			srv := newTestServer()
			req := repositoryEnsureRequest(tt.body)
			if tt.name != "feature disabled" {
				srv.AttachGitHubRepositoryManager(manager)
			}
			if tt.configure != nil {
				tt.configure(req, manager)
			}
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestMindRoomRepositoryEnsureReturnsNotFoundForMissingSQLVault(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "agent-vault.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	manager := &fakeGitHubRepositoryManager{authToken: "broker-control-plane-token"}
	srv := New("127.0.0.1:0", db, make([]byte, 32), nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))
	srv.AttachGitHubRepositoryManager(manager)
	req := repositoryEnsureRequest(`{"worker_key":"worker","organization":"example-org","repository_name":"MindRoom-agent"}`)
	req.Header.Set("X-Vault", "does-not-exist")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || manager.calls != 0 {
		t.Fatalf("status/calls = %d/%d, want 404/0; body=%s", rec.Code, manager.calls, rec.Body.String())
	}
}

func TestCredentialProviderChainsRepositoryBindingAheadOfExistingOAuthProvider(t *testing.T) {
	manager := &fakeGitHubRepositoryManager{
		binding: &store.GitHubRepositoryBinding{
			VaultID:         "root-ns-id",
			RepositoryID:    "123456789",
			Organization:    "example-org",
			RepositoryName:  "MindRoom-redwood",
			PermissionsJSON: `{"contents":"write"}`,
		},
		token: "runtime-installation-token",
	}
	srv := newTestServer()
	srv.AttachGitHubRepositoryManager(manager)
	provider := srv.CredentialProvider()
	result, err := provider.Inject(t.Context(), "root-ns-id", "api.github.com", 443, "/repos/example-org/MindRoom-redwood/contents/README.md")
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if result.Headers["Authorization"] != "Bearer runtime-installation-token" || len(manager.tokenIDs) != 1 || manager.tokenIDs[0] != "123456789" {
		t.Fatalf("result/token IDs = %#v/%v", result, manager.tokenIDs)
	}
	if _, ok := provider.(*githubapp.RepositoryCredentialProvider); !ok {
		t.Fatalf("provider type = %T, want repository provider chaining existing provider", provider)
	}
}
