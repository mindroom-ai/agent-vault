package githubapp

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

type fakeBindingStore struct {
	lockMu         sync.Mutex
	locks          map[string]*sync.Mutex
	dataMu         sync.Mutex
	byVault        map[string]store.GitHubRepositoryBinding
	byWorker       map[string]store.GitHubRepositoryBinding
	createErr      error
	lockCalls      int
	commitErr      error
	commitPersists bool
	lockContextErr error
}

func (s *fakeBindingStore) WithGitHubRepositoryBindingLock(ctx context.Context, fn func(store.GitHubRepositoryBindingStore) error) error {
	s.lockMu.Lock()
	lock := s.locks["github-repository-provisioning"]
	if lock == nil {
		lock = &sync.Mutex{}
		s.locks["github-repository-provisioning"] = lock
	}
	s.lockCalls++
	s.lockMu.Unlock()
	lock.Lock()
	defer lock.Unlock()
	s.dataMu.Lock()
	beforeVault := make(map[string]store.GitHubRepositoryBinding, len(s.byVault))
	for key, binding := range s.byVault {
		beforeVault[key] = binding
	}
	beforeWorker := make(map[string]store.GitHubRepositoryBinding, len(s.byWorker))
	for key, binding := range s.byWorker {
		beforeWorker[key] = binding
	}
	s.dataMu.Unlock()
	if err := fn(s); err != nil {
		s.lockMu.Lock()
		s.lockContextErr = ctx.Err()
		s.lockMu.Unlock()
		return err
	}
	s.lockMu.Lock()
	s.lockContextErr = ctx.Err()
	s.lockMu.Unlock()
	s.lockMu.Lock()
	commitErr, persists := s.commitErr, s.commitPersists
	s.commitErr = nil
	s.lockMu.Unlock()
	if commitErr != nil {
		if !persists {
			s.dataMu.Lock()
			s.byVault, s.byWorker = beforeVault, beforeWorker
			s.dataMu.Unlock()
		}
		return commitErr
	}
	return nil
}

func newFakeBindingStore() *fakeBindingStore {
	return &fakeBindingStore{
		locks:    make(map[string]*sync.Mutex),
		byVault:  make(map[string]store.GitHubRepositoryBinding),
		byWorker: make(map[string]store.GitHubRepositoryBinding),
	}
}

func (s *fakeBindingStore) LockVault(_ context.Context, key string) (func(), error) {
	s.lockMu.Lock()
	lock := s.locks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		s.locks[key] = lock
	}
	s.lockMu.Unlock()
	lock.Lock()
	return lock.Unlock, nil
}

func (s *fakeBindingStore) CreateGitHubRepositoryBinding(_ context.Context, binding store.GitHubRepositoryBinding) error {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	if s.createErr != nil {
		return s.createErr
	}
	if _, ok := s.byVault[binding.VaultID]; ok {
		return errors.New("duplicate vault")
	}
	if _, ok := s.byWorker[binding.WorkerKeyHash]; ok {
		return errors.New("duplicate worker")
	}
	s.byVault[binding.VaultID] = binding
	s.byWorker[binding.WorkerKeyHash] = binding
	return nil
}

func (s *fakeBindingStore) GetGitHubRepositoryBinding(_ context.Context, vaultID string) (*store.GitHubRepositoryBinding, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	binding, ok := s.byVault[vaultID]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return &binding, nil
}

func (s *fakeBindingStore) GetGitHubRepositoryBindingByWorkerHash(_ context.Context, hash string) (*store.GitHubRepositoryBinding, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	binding, ok := s.byWorker[hash]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return &binding, nil
}

type fakeRepositoryClient struct {
	mu            sync.Mutex
	mintCalls     int
	verifyCalls   int
	createCalls   int
	getCalls      int
	createErr     error
	getErr        error
	mintErrAt     map[int]error
	createHook    func()
	repository    *Repository
	getRepository *Repository
	createMarkers []string
	getMarkers    []string
	createTokens  []string
	getTokens     []string
	mintedTokens  []*InstallationToken
	mintIDs       [][]int64
	mintPerms     []map[string]string
}

func (c *fakeRepositoryClient) VerifyInstallation(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifyCalls++
	return nil
}

func (c *fakeRepositoryClient) MintInstallationToken(_ context.Context, ids []int64, permissions map[string]string) (*InstallationToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mintCalls++
	c.mintIDs = append(c.mintIDs, append([]int64(nil), ids...))
	c.mintPerms = append(c.mintPerms, clonePermissions(permissions))
	if err := c.mintErrAt[c.mintCalls]; err != nil {
		return nil, err
	}
	token := &InstallationToken{Value: "minted-" + strconv.Itoa(c.mintCalls), ExpiresAt: time.Now().Add(time.Hour)}
	c.mintedTokens = append(c.mintedTokens, token)
	return token, nil
}

func (c *fakeRepositoryClient) CreateRepository(_ context.Context, token, name, marker string) (*Repository, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.createCalls++
	c.createMarkers = append(c.createMarkers, marker)
	c.createTokens = append(c.createTokens, token)
	if !strings.HasPrefix(token, "minted-") {
		return nil, errors.New("wrong provisioning token")
	}
	if c.createHook != nil {
		c.createHook()
	}
	if c.createErr != nil {
		return nil, c.createErr
	}
	if c.repository != nil {
		copy := *c.repository
		return &copy, nil
	}
	return &Repository{ID: "123456789", Organization: "example-org", Name: name, CloneURL: "https://github.com/example-org/" + name + ".git"}, nil
}

func (c *fakeRepositoryClient) GetRepository(_ context.Context, token, name, marker string) (*Repository, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCalls++
	c.getMarkers = append(c.getMarkers, marker)
	c.getTokens = append(c.getTokens, token)
	if !strings.HasPrefix(token, "minted-") || name == "" || marker == "" {
		return nil, errors.New("wrong repository recovery capability")
	}
	if c.getErr != nil {
		return nil, c.getErr
	}
	if c.getRepository == nil {
		return nil, ErrRepositoryNotFound
	}
	copy := *c.getRepository
	return &copy, nil
}

func newTestManager(t *testing.T) (*Manager, *fakeBindingStore, *fakeRepositoryClient) {
	t.Helper()
	config := testClientConfig(t)
	bindingStore := newFakeBindingStore()
	client := &fakeRepositoryClient{}
	return NewManager(config, bindingStore, client, NewTokenManager(client, time.Now)), bindingStore, client
}

func assertMintedTokensWiped(t *testing.T, client *fakeRepositoryClient) {
	t.Helper()
	for i, token := range client.mintedTokens {
		if token.Value != "" {
			t.Fatalf("minted token %d retained after ensure", i+1)
		}
	}
}

func TestManagerEnsureCreatesPrivateBindingWithoutPersistingSecrets(t *testing.T) {
	manager, bindingStore, client := newTestManager(t)
	lease, created, err := manager.EnsureRepository(t.Context(), "vault-redwood", EnsureRequest{
		WorkerKey:      "worker-redwood",
		Organization:   "example-org",
		RepositoryName: "MindRoom-redwood",
	})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	if !created {
		t.Fatal("created = false, want true")
	}
	if lease.RepositoryID != "123456789" || lease.Organization != "example-org" || lease.RepositoryName != "MindRoom-redwood" || lease.CloneURL != "https://github.com/example-org/MindRoom-redwood.git" {
		t.Fatalf("lease = %+v", lease)
	}
	if client.verifyCalls != 1 || client.mintCalls != 2 || len(client.mintIDs[0]) != 0 || len(client.mintPerms[0]) != 1 || client.mintPerms[0]["administration"] != "write" {
		t.Fatalf("provisioning mints = ids %v permissions %#v", client.mintIDs, client.mintPerms)
	}
	if len(client.mintIDs[1]) != 1 || client.mintIDs[1][0] != 123456789 || len(client.mintPerms[1]) != 1 || client.mintPerms[1]["contents"] != "write" {
		t.Fatalf("scoped access probe = ids %v permissions %#v", client.mintIDs[1], client.mintPerms[1])
	}
	assertMintedTokensWiped(t, client)
	binding := bindingStore.byVault["vault-redwood"]
	if binding.WorkerKeyHash != HashWorkerKey("worker-redwood") || binding.PermissionsJSON != `{"contents":"write"}` {
		t.Fatalf("binding = %+v", binding)
	}
	if binding.WorkerKeyHash == "worker-redwood" {
		t.Fatal("raw worker key persisted")
	}
}

func TestManagerEnsureReturnsExactExistingBindingWithoutMint(t *testing.T) {
	manager, _, client := newTestManager(t)
	request := EnsureRequest{WorkerKey: "worker-redwood", Organization: "example-org", RepositoryName: "MindRoom-redwood"}
	first, _, err := manager.EnsureRepository(t.Context(), "vault-redwood", request)
	if err != nil {
		t.Fatalf("first EnsureRepository: %v", err)
	}
	second, created, err := manager.EnsureRepository(t.Context(), "vault-redwood", request)
	if err != nil {
		t.Fatalf("second EnsureRepository: %v", err)
	}
	if created || second != first {
		t.Fatalf("second = %+v, created = %v; want exact existing %+v", second, created, first)
	}
	if client.mintCalls != 2 || client.createCalls != 1 {
		t.Fatalf("mint/create calls = %d/%d, want 2/1", client.mintCalls, client.createCalls)
	}
}

func TestManagerEnsureRejectsPolicyAndBindingConflictsBeforeGitHub(t *testing.T) {
	tests := []struct {
		name      string
		vaultID   string
		first     *EnsureRequest
		request   EnsureRequest
		wantError error
	}{
		{name: "wrong organization", vaultID: "vault", request: EnsureRequest{WorkerKey: "worker", Organization: "other", RepositoryName: "MindRoom-agent"}, wantError: ErrInvalidEnsureRequest},
		{name: "prefix only", vaultID: "vault", request: EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-"}, wantError: ErrInvalidEnsureRequest},
		{name: "invalid repository name", vaultID: "vault", request: EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent/other"}, wantError: ErrInvalidEnsureRequest},
		{name: "vault rebound", vaultID: "vault", first: &EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"}, request: EnsureRequest{WorkerKey: "worker-2", Organization: "example-org", RepositoryName: "MindRoom-agent-2"}, wantError: ErrBindingConflict},
		{name: "worker rebound", vaultID: "vault-2", first: &EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"}, request: EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"}, wantError: ErrBindingConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, _, client := newTestManager(t)
			if tt.first != nil {
				firstVault := tt.vaultID
				if tt.name == "worker rebound" {
					firstVault = "vault-1"
				}
				if _, _, err := manager.EnsureRepository(t.Context(), firstVault, *tt.first); err != nil {
					t.Fatalf("seed EnsureRepository: %v", err)
				}
			}
			before := client.createCalls
			_, _, err := manager.EnsureRepository(t.Context(), tt.vaultID, tt.request)
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("EnsureRepository error = %v, want %v", err, tt.wantError)
			}
			if client.createCalls != before {
				t.Fatalf("create calls changed from %d to %d", before, client.createCalls)
			}
		})
	}
}

func TestManagerEnsureFailsClosedOnGitHubCollisionAndStoreFailure(t *testing.T) {
	for _, tt := range []struct {
		name      string
		createErr error
		storeErr  error
		mintErrAt int
		wantMints int
		want      error
	}{
		{name: "GitHub 422 without repository", createErr: ErrRepositoryCreateRejected, wantMints: 2, want: ErrRepositoryCreateRejected},
		{name: "scoped access probe failure leaves marked repository for retry", mintErrAt: 2, wantMints: 2, want: ErrRepositoryCapability},
		{name: "binding write failure leaves marked repository for retry", storeErr: errors.New("database unavailable"), wantMints: 2, want: ErrBindingPersistence},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager, bindingStore, client := newTestManager(t)
			client.createErr = tt.createErr
			if tt.mintErrAt != 0 {
				client.mintErrAt = map[int]error{tt.mintErrAt: errors.New("mint unavailable")}
			}
			bindingStore.createErr = tt.storeErr
			_, _, err := manager.EnsureRepository(t.Context(), "vault", EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"})
			if !errors.Is(err, tt.want) {
				t.Fatalf("EnsureRepository error = %v, want %v", err, tt.want)
			}
			if len(bindingStore.byVault) != 0 {
				t.Fatalf("binding persisted after failure: %#v", bindingStore.byVault)
			}
			if client.mintCalls != tt.wantMints {
				t.Fatalf("mint calls = %d, want %d", client.mintCalls, tt.wantMints)
			}
			assertMintedTokensWiped(t, client)
		})
	}
}

func TestManagerEnsureRecoversMarkedRepositoryAfterPostCreateFailure(t *testing.T) {
	for _, tt := range []struct {
		name      string
		firstErr  error
		configure func(*fakeBindingStore, *fakeRepositoryClient)
	}{
		{
			name:     "binding write failure",
			firstErr: ErrBindingPersistence,
			configure: func(bindingStore *fakeBindingStore, _ *fakeRepositoryClient) {
				bindingStore.createErr = errors.New("database unavailable")
			},
		},
		{
			name:     "scoped access probe failure",
			firstErr: ErrRepositoryCapability,
			configure: func(_ *fakeBindingStore, client *fakeRepositoryClient) {
				client.mintErrAt = map[int]error{2: errors.New("repository not selected yet")}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager, bindingStore, client := newTestManager(t)
			tt.configure(bindingStore, client)
			request := EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"}

			if _, _, err := manager.EnsureRepository(t.Context(), "vault", request); !errors.Is(err, tt.firstErr) {
				t.Fatalf("first EnsureRepository error = %v, want %v", err, tt.firstErr)
			}

			bindingStore.createErr = nil
			client.mintErrAt = nil
			client.createErr = ErrRepositoryCreateRejected
			client.getRepository = &Repository{ID: "123456789", Organization: "example-org", Name: "MindRoom-agent", CloneURL: "https://github.com/example-org/MindRoom-agent.git"}
			lease, created, err := manager.EnsureRepository(t.Context(), "vault", request)
			if err != nil {
				t.Fatalf("retry EnsureRepository: %v", err)
			}
			if !created || lease.RepositoryID != "123456789" || client.getCalls != 1 || client.mintCalls != 5 {
				t.Fatalf("retry lease/created/get/mints = %+v/%v/%d/%d", lease, created, client.getCalls, client.mintCalls)
			}
			assertMintedTokensWiped(t, client)
		})
	}
}

func TestManagerEnsureRecoversOnlyItsExactMarkedRepositoryAfterAmbiguousCreate(t *testing.T) {
	for _, tt := range []struct {
		name      string
		createErr error
	}{
		{name: "lost create response", createErr: errors.New("connection reset after request")},
		{name: "retry sees rejected create", createErr: ErrRepositoryCreateRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager, bindingStore, client := newTestManager(t)
			client.createErr = tt.createErr
			client.getRepository = &Repository{ID: "987654321", Organization: "example-org", Name: "MindRoom-agent", CloneURL: "https://github.com/example-org/MindRoom-agent.git"}

			lease, created, err := manager.EnsureRepository(t.Context(), "vault", EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"})
			if err != nil {
				t.Fatalf("EnsureRepository: %v", err)
			}
			if !created || lease.RepositoryID != "987654321" {
				t.Fatalf("lease/created = %+v/%v, want recovered repository", lease, created)
			}
			if client.getCalls != 1 {
				t.Fatalf("get calls = %d, want 1", client.getCalls)
			}
			if client.mintCalls != 3 || client.createTokens[0] == client.getTokens[0] {
				t.Fatalf("mint calls/create/get tokens = %d/%#v/%#v, want fresh recovery token and scoped probe", client.mintCalls, client.createTokens, client.getTokens)
			}
			if len(client.mintIDs[2]) != 1 || client.mintIDs[2][0] != 987654321 || client.mintPerms[2]["contents"] != "write" {
				t.Fatalf("recovered scoped access probe = ids %v permissions %#v", client.mintIDs[2], client.mintPerms[2])
			}
			assertMintedTokensWiped(t, client)
			if len(client.createMarkers) != 1 || len(client.getMarkers) != 1 || client.createMarkers[0] == "" || client.createMarkers[0] != client.getMarkers[0] {
				t.Fatalf("create/get markers = %#v/%#v, want same non-empty marker", client.createMarkers, client.getMarkers)
			}
			if got := bindingStore.byVault["vault"].RepositoryID; got != "987654321" {
				t.Fatalf("bound repository ID = %q, want recovered ID", got)
			}
		})
	}
}

func TestManagerEnsureDoesNotAdoptOrDeleteUnmarkedCollision(t *testing.T) {
	manager, bindingStore, client := newTestManager(t)
	client.createErr = ErrRepositoryCreateRejected
	client.getErr = ErrUnexpectedGitHubResponse

	_, _, err := manager.EnsureRepository(t.Context(), "vault", EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"})
	if !errors.Is(err, ErrRepositoryCollision) {
		t.Fatalf("EnsureRepository error = %v, want original collision", err)
	}
	if client.getCalls != 1 {
		t.Fatalf("get calls = %d, want 1", client.getCalls)
	}
	if client.mintCalls != 2 || client.createTokens[0] == client.getTokens[0] {
		t.Fatalf("mint calls/create/get tokens = %d/%#v/%#v, want fresh recovery token", client.mintCalls, client.createTokens, client.getTokens)
	}
	assertMintedTokensWiped(t, client)
	if len(bindingStore.byVault) != 0 {
		t.Fatalf("binding persisted for unmarked collision: %#v", bindingStore.byVault)
	}
}

func TestManagerEnsureDeduplicatesConcurrentCreation(t *testing.T) {
	manager, _, client := newTestManager(t)
	request := EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"}
	const callers = 12
	errCh := make(chan error, callers)
	for range callers {
		go func() {
			_, _, err := manager.EnsureRepository(context.Background(), "vault", request)
			errCh <- err
		}()
	}
	for range callers {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if client.createCalls != 1 || client.mintCalls != 2 {
		t.Fatalf("create/mint calls = %d/%d, want 1/2", client.createCalls, client.mintCalls)
	}
	if manager.store.(*fakeBindingStore).lockCalls != callers {
		t.Fatalf("binding lock callbacks = %d, want %d", manager.store.(*fakeBindingStore).lockCalls, callers)
	}
}

func TestManagerEnsureReconcilesAmbiguousBindingCommit(t *testing.T) {
	for _, tt := range []struct {
		name           string
		commitPersists bool
		wantErr        error
		wantMints      int
	}{
		{name: "commit reached database", commitPersists: true, wantMints: 2},
		{name: "transaction rolled back", wantErr: ErrBindingPersistence, wantMints: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager, bindingStore, client := newTestManager(t)
			bindingStore.commitErr = errors.New("ambiguous commit result")
			bindingStore.commitPersists = tt.commitPersists
			lease, created, err := manager.EnsureRepository(t.Context(), "vault", EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("EnsureRepository error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && (!created || lease.RepositoryID != "123456789") {
				t.Fatalf("lease/created = %+v/%v, want reconciled created repository", lease, created)
			}
			if client.mintCalls != tt.wantMints {
				t.Fatalf("mint calls = %d, want %d", client.mintCalls, tt.wantMints)
			}
			assertMintedTokensWiped(t, client)
			if bindingStore.lockCalls != 2 {
				t.Fatalf("binding lock callbacks = %d, want initial plus reconciliation", bindingStore.lockCalls)
			}
		})
	}
}

func TestManagerEnsureKeepsBindingLockAliveAfterRequestCancellation(t *testing.T) {
	manager, bindingStore, client := newTestManager(t)
	requestCtx, cancel := context.WithCancel(context.Background())
	client.createHook = cancel

	lease, created, err := manager.EnsureRepository(requestCtx, "vault", EnsureRequest{WorkerKey: "worker", Organization: "example-org", RepositoryName: "MindRoom-agent"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	if !created || lease.RepositoryID != "123456789" {
		t.Fatalf("lease/created = %+v/%v", lease, created)
	}
	if bindingStore.lockContextErr != nil {
		t.Fatalf("binding lock context released after irreversible create: %v", bindingStore.lockContextErr)
	}
	assertMintedTokensWiped(t, client)
}
