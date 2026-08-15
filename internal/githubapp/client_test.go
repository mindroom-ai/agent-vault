package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClientConfig(t *testing.T) *Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &Config{
		AppID:            101,
		InstallationID:   202,
		Organization:     "example-org",
		OrganizationID:   303,
		RepositoryPrefix: "MindRoom-",
		PrivateKey:       key,
	}
}

func decodeJWTPart(t *testing.T, token string, part int, dst any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[part])
	if err != nil {
		t.Fatalf("DecodeString JWT part %d: %v", part, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("Unmarshal JWT part %d: %v", part, err)
	}
}

func TestClientVerifyInstallationRequiresSelectedAndExactIdentity(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		response   string
		wantErr    bool
		checkToken bool
	}{
		{
			name: "selected exact installation",
			response: `{"id":202,"app_id":101,"account":{"login":"example-org","id":303},` +
				`"repository_selection":"selected","permissions":{"administration":"write","contents":"write"}}`,
			checkToken: true,
		},
		{
			name: "all repositories rejected",
			response: `{"id":202,"app_id":101,"account":{"login":"example-org","id":303},` +
				`"repository_selection":"all","permissions":{"administration":"write","contents":"write"}}`,
			wantErr: true,
		},
		{
			name: "wrong organization ID",
			response: `{"id":202,"app_id":101,"account":{"login":"example-org","id":999},` +
				`"repository_selection":"selected","permissions":{"administration":"write","contents":"write"}}`,
			wantErr: true,
		},
		{
			name: "missing administration write",
			response: `{"id":202,"app_id":101,"account":{"login":"example-org","id":303},` +
				`"repository_selection":"selected","permissions":{"administration":"read","contents":"write"}}`,
			wantErr: true,
		},
		{
			name: "missing contents write",
			response: `{"id":202,"app_id":101,"account":{"login":"example-org","id":303},` +
				`"repository_selection":"selected","permissions":{"administration":"write","contents":"read"}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authorization string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/app/installations/202" {
					t.Errorf("request = %s %s, want GET /app/installations/202", r.Method, r.URL.Path)
				}
				authorization = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := NewClient(testClientConfig(t))
			client.baseURL = server.URL
			client.httpClient = server.Client()
			client.now = func() time.Time { return now }
			err := client.VerifyInstallation(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyInstallation error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkToken {
				if !strings.HasPrefix(authorization, "Bearer ") {
					t.Fatalf("Authorization = %q, want Bearer JWT", authorization)
				}
				jwt := strings.TrimPrefix(authorization, "Bearer ")
				var header map[string]any
				decodeJWTPart(t, jwt, 0, &header)
				if header["alg"] != "RS256" || header["typ"] != "JWT" {
					t.Fatalf("JWT header = %#v", header)
				}
				var claims struct {
					IssuedAt  int64  `json:"iat"`
					ExpiresAt int64  `json:"exp"`
					Issuer    string `json:"iss"`
				}
				decodeJWTPart(t, jwt, 1, &claims)
				if claims.Issuer != "101" || claims.IssuedAt != now.Add(-60*time.Second).Unix() || claims.ExpiresAt != now.Add(9*time.Minute).Unix() {
					t.Fatalf("JWT claims = %+v", claims)
				}
			}
		})
	}
}

func TestClientCreateRepositoryUsesPrivateExactPayloadAndValidatesResponse(t *testing.T) {
	const marker = "agent-vault-mindroom-v1:test-marker"
	tests := []struct {
		name     string
		status   int
		response string
		wantErr  error
	}{
		{
			name:     "created",
			status:   http.StatusCreated,
			response: `{"id":123456789,"name":"MindRoom-redwood","private":true,"description":"agent-vault-mindroom-v1:test-marker","clone_url":"https://github.com/example-org/MindRoom-redwood.git","owner":{"login":"example-org","id":303}}`,
		},
		{
			name:     "unprocessable create is not assumed to be a collision",
			status:   http.StatusUnprocessableEntity,
			response: `{"message":"name already exists"}`,
			wantErr:  ErrRepositoryCreateRejected,
		},
		{
			name:     "public response rejected",
			status:   http.StatusCreated,
			response: `{"id":123456789,"name":"MindRoom-redwood","private":false,"description":"agent-vault-mindroom-v1:test-marker","clone_url":"https://github.com/example-org/MindRoom-redwood.git","owner":{"login":"example-org","id":303}}`,
			wantErr:  ErrUnexpectedGitHubResponse,
		},
		{
			name:     "wrong marker rejected",
			status:   http.StatusCreated,
			response: `{"id":123456789,"name":"MindRoom-redwood","private":true,"description":"other","clone_url":"https://github.com/example-org/MindRoom-redwood.git","owner":{"login":"example-org","id":303}}`,
			wantErr:  ErrUnexpectedGitHubResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/orgs/example-org/repos" {
					t.Errorf("request = %s %s, want POST /orgs/example-org/repos", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer internal-admin-token" {
					t.Errorf("Authorization = %q, want internal provisioning token", got)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("Decode body: %v", err)
				}
				if len(body) != 3 || body["name"] != "MindRoom-redwood" || body["private"] != true || body["description"] != marker {
					t.Errorf("create body = %#v, want exact name/private/marker fields", body)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := NewClient(testClientConfig(t))
			client.baseURL = server.URL
			client.httpClient = server.Client()
			repository, err := client.CreateRepository(context.Background(), "internal-admin-token", "MindRoom-redwood", marker)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("CreateRepository error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateRepository: %v", err)
			}
			if repository.ID != "123456789" || repository.Organization != "example-org" || repository.Name != "MindRoom-redwood" || repository.CloneURL != "https://github.com/example-org/MindRoom-redwood.git" {
				t.Fatalf("repository = %+v", repository)
			}
		})
	}
}

func TestClientGetRepositoryAdoptsOnlyExactPrivateMarkedRepository(t *testing.T) {
	const marker = "agent-vault-mindroom-v1:test-marker"
	tests := []struct {
		name     string
		status   int
		response string
		wantErr  error
	}{
		{
			name:     "exact marked repository",
			status:   http.StatusOK,
			response: `{"id":123456789,"name":"MindRoom-redwood","private":true,"description":"agent-vault-mindroom-v1:test-marker","clone_url":"https://github.com/example-org/MindRoom-redwood.git","owner":{"login":"example-org","id":303}}`,
		},
		{
			name:     "unmarked collision rejected",
			status:   http.StatusOK,
			response: `{"id":123456789,"name":"MindRoom-redwood","private":true,"description":"human repository","clone_url":"https://github.com/example-org/MindRoom-redwood.git","owner":{"login":"example-org","id":303}}`,
			wantErr:  ErrUnexpectedGitHubResponse,
		},
		{
			name:    "missing repository",
			status:  http.StatusNotFound,
			wantErr: ErrRepositoryNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/repos/example-org/MindRoom-redwood" {
					t.Errorf("request = %s %s, want exact repository GET", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer provisioning-secret" {
					t.Errorf("Authorization = %q", got)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := NewClient(testClientConfig(t))
			client.baseURL = server.URL
			client.httpClient = server.Client()
			repository, err := client.GetRepository(context.Background(), "provisioning-secret", "MindRoom-redwood", marker)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetRepository error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && (repository == nil || repository.ID != "123456789") {
				t.Fatalf("repository = %+v, want exact marked repository", repository)
			}
		})
	}
}

func TestClientMintInstallationTokenSendsExactNarrowing(t *testing.T) {
	expiresAt := time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/202/access_tokens" {
			t.Errorf("request = %s %s, want installation token endpoint", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("Authorization = %q, want App JWT", r.Header.Get("Authorization"))
		}
		var body struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Decode body: %v", err)
		}
		if len(body.RepositoryIDs) != 1 || body.RepositoryIDs[0] != 123456789 {
			t.Errorf("repository_ids = %v, want [123456789]", body.RepositoryIDs)
		}
		if len(body.Permissions) != 1 || body.Permissions["contents"] != "write" {
			t.Errorf("permissions = %#v, want contents:write only", body.Permissions)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"installation-secret","expires_at":"` + expiresAt.Format(time.RFC3339) + `"}`))
	}))
	defer server.Close()

	client := NewClient(testClientConfig(t))
	client.baseURL = server.URL
	client.httpClient = server.Client()
	token, err := client.MintInstallationToken(context.Background(), []int64{123456789}, map[string]string{"contents": "write"})
	if err != nil {
		t.Fatalf("MintInstallationToken: %v", err)
	}
	if token.Value != "installation-secret" || !token.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("token = %+v", token)
	}
}

func TestClientErrorsDoNotIncludeGitHubResponseSecrets(t *testing.T) {
	secret := "ghs_must-never-escape"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"` + secret + `"}`))
	}))
	defer server.Close()

	client := NewClient(testClientConfig(t))
	client.baseURL = server.URL
	client.httpClient = server.Client()
	_, err := client.MintInstallationToken(context.Background(), []int64{123456789}, map[string]string{"contents": "write"})
	if err == nil {
		t.Fatal("MintInstallationToken succeeded, want upstream error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed GitHub response secret: %v", err)
	}
}
