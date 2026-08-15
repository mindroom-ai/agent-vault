package githubapp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

const contentsWritePermissionsJSON = `{"contents":"write"}`

var (
	ErrInvalidEnsureRequest = errors.New("invalid repository ensure request")
	ErrBindingConflict      = errors.New("repository binding conflicts with immutable existing binding")
	ErrBindingPersistence   = errors.New("repository was created but its binding could not be persisted")
	ErrRepositoryCapability = errors.New("repository was created but scoped access could not be verified")
	validRepositoryName     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

const repositoryEnsureTimeout = 5 * time.Minute

type EnsureRequest struct {
	WorkerKey      string `json:"worker_key"`
	Organization   string `json:"organization"`
	RepositoryName string `json:"repository_name"`
}

type RepositoryLease struct {
	RepositoryID   string `json:"repository_id"`
	Organization   string `json:"organization"`
	RepositoryName string `json:"repository_name"`
	CloneURL       string `json:"clone_url"`
}

type BindingStore interface {
	GetGitHubRepositoryBinding(context.Context, string) (*store.GitHubRepositoryBinding, error)
	WithGitHubRepositoryBindingLock(context.Context, func(store.GitHubRepositoryBindingStore) error) error
}

type RepositoryClient interface {
	InstallationTokenMinter
	VerifyInstallation(context.Context) error
	CreateRepository(context.Context, string, string, string) (*Repository, error)
	GetRepository(context.Context, string, string, string) (*Repository, error)
}

type Manager struct {
	config *Config
	store  BindingStore
	client RepositoryClient
	tokens *TokenManager
}

func NewManager(config *Config, bindingStore BindingStore, client RepositoryClient, tokens *TokenManager) *Manager {
	return &Manager{config: config, store: bindingStore, client: client, tokens: tokens}
}

func HashWorkerKey(workerKey string) string {
	digest := sha256.Sum256([]byte(workerKey))
	return hex.EncodeToString(digest[:])
}

func (m *Manager) AuthenticateBrokerToken(token string) bool {
	return m != nil && m.config.AuthenticateBrokerToken(token)
}

func (m *Manager) EnsureRepository(ctx context.Context, vaultID string, request EnsureRequest) (RepositoryLease, bool, error) {
	if err := m.validateEnsureRequest(vaultID, request); err != nil {
		return RepositoryLease{}, false, err
	}
	if err := m.client.VerifyInstallation(ctx); err != nil {
		return RepositoryLease{}, false, fmt.Errorf("verify GitHub App installation: %w", err)
	}
	// Once repository creation can begin, keep the cluster-wide lock and the
	// full create-and-bind transition alive independently of client disconnects.
	// A bounded context prevents abandoned requests from running forever.
	operationCtx, cancelOperation := context.WithTimeout(context.WithoutCancel(ctx), repositoryEnsureTimeout)
	defer cancelOperation()
	ctx = operationCtx
	workerHash := HashWorkerKey(request.WorkerKey)

	var lease RepositoryLease
	var created bool
	var createdRepository *Repository
	var expectedBinding *store.GitHubRepositoryBinding
	var bindingCallbackSucceeded bool
	err := m.store.WithGitHubRepositoryBindingLock(ctx, func(bindings store.GitHubRepositoryBindingStore) error {
		existing, err := bindings.GetGitHubRepositoryBinding(ctx, vaultID)
		if err == nil {
			if !bindingMatches(existing, vaultID, workerHash, request.Organization, request.RepositoryName) {
				return ErrBindingConflict
			}
			lease = leaseFromBinding(existing)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read repository binding: %w", err)
		}

		_, err = bindings.GetGitHubRepositoryBindingByWorkerHash(ctx, workerHash)
		if err == nil {
			return ErrBindingConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read repository worker binding: %w", err)
		}

		creationToken, err := m.client.MintInstallationToken(ctx, nil, map[string]string{"administration": "write"})
		if err != nil {
			return fmt.Errorf("mint repository provisioning capability: %w", err)
		}
		marker := m.config.repositoryMarker(vaultID, workerHash, request.Organization, request.RepositoryName)
		createdRepository, err = m.client.CreateRepository(ctx, creationToken.Value, request.RepositoryName, marker)
		creationToken.Value = ""
		if err != nil {
			createErr := err
			recoveryToken, mintErr := m.client.MintInstallationToken(ctx, nil, map[string]string{"administration": "write"})
			if mintErr != nil {
				createdRepository = nil
				return createErr
			}
			createdRepository, err = m.client.GetRepository(ctx, recoveryToken.Value, request.RepositoryName, marker)
			recoveryToken.Value = ""
			if err != nil {
				createdRepository = nil
				if errors.Is(err, ErrUnexpectedGitHubResponse) {
					return ErrRepositoryCollision
				}
				return createErr
			}
		}
		repositoryID, err := strconv.ParseInt(createdRepository.ID, 10, 64)
		if err != nil || repositoryID <= 0 {
			return ErrRepositoryCapability
		}
		accessToken, err := m.client.MintInstallationToken(ctx, []int64{repositoryID}, map[string]string{"contents": "write"})
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRepositoryCapability, err)
		}
		accessToken.Value = ""
		binding := store.GitHubRepositoryBinding{
			VaultID:         vaultID,
			WorkerKeyHash:   workerHash,
			RepositoryID:    createdRepository.ID,
			Organization:    createdRepository.Organization,
			RepositoryName:  createdRepository.Name,
			PermissionsJSON: contentsWritePermissionsJSON,
		}
		expectedBinding = &binding
		if err := bindings.CreateGitHubRepositoryBinding(ctx, binding); err != nil {
			return fmt.Errorf("%w: %v", ErrBindingPersistence, err)
		}
		lease = leaseFromBinding(&binding)
		created = true
		bindingCallbackSucceeded = true
		return nil
	})
	if err != nil && createdRepository != nil && bindingCallbackSucceeded {
		reconciledLease, reconcileErr := m.reconcileAmbiguousBinding(ctx, *expectedBinding)
		if reconcileErr != nil {
			return RepositoryLease{}, false, reconcileErr
		}
		return reconciledLease, true, nil
	}
	if err != nil {
		return RepositoryLease{}, false, err
	}
	return lease, created, nil
}

func (m *Manager) reconcileAmbiguousBinding(ctx context.Context, expected store.GitHubRepositoryBinding) (RepositoryLease, error) {
	var lease RepositoryLease
	err := m.store.WithGitHubRepositoryBindingLock(ctx, func(bindings store.GitHubRepositoryBindingStore) error {
		existing, err := bindings.GetGitHubRepositoryBinding(ctx, expected.VaultID)
		if err == nil {
			if !sameBinding(existing, &expected) {
				return ErrBindingPersistence
			}
			lease = leaseFromBinding(existing)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrBindingPersistence
		}
		return ErrBindingPersistence
	})
	if err != nil {
		if errors.Is(err, ErrBindingPersistence) {
			return RepositoryLease{}, err
		}
		return RepositoryLease{}, ErrBindingPersistence
	}
	return lease, nil
}

func (m *Manager) Binding(ctx context.Context, vaultID string) (*store.GitHubRepositoryBinding, error) {
	return m.store.GetGitHubRepositoryBinding(ctx, vaultID)
}

func (m *Manager) RepositoryToken(ctx context.Context, repositoryID string) (string, error) {
	return m.tokens.Token(ctx, repositoryID)
}

func (m *Manager) validateEnsureRequest(vaultID string, request EnsureRequest) error {
	if vaultID == "" || request.WorkerKey == "" || len(request.WorkerKey) > 4096 {
		return ErrInvalidEnsureRequest
	}
	if request.Organization != m.config.Organization ||
		!strings.HasPrefix(request.RepositoryName, m.config.RepositoryPrefix) ||
		len(request.RepositoryName) <= len(m.config.RepositoryPrefix) ||
		len(request.RepositoryName) > 100 ||
		!validRepositoryName.MatchString(request.RepositoryName) {
		return ErrInvalidEnsureRequest
	}
	return nil
}

func bindingMatches(binding *store.GitHubRepositoryBinding, vaultID, workerHash, organization, repositoryName string) bool {
	return binding != nil && binding.VaultID == vaultID && binding.WorkerKeyHash == workerHash &&
		binding.Organization == organization && binding.RepositoryName == repositoryName &&
		binding.PermissionsJSON == contentsWritePermissionsJSON
}

func sameBinding(a, b *store.GitHubRepositoryBinding) bool {
	return a != nil && b != nil && a.VaultID == b.VaultID && a.WorkerKeyHash == b.WorkerKeyHash &&
		a.RepositoryID == b.RepositoryID && a.Organization == b.Organization &&
		a.RepositoryName == b.RepositoryName && a.PermissionsJSON == b.PermissionsJSON
}

func leaseFromBinding(binding *store.GitHubRepositoryBinding) RepositoryLease {
	return RepositoryLease{
		RepositoryID:   binding.RepositoryID,
		Organization:   binding.Organization,
		RepositoryName: binding.RepositoryName,
		CloneURL:       fmt.Sprintf("https://github.com/%s/%s.git", binding.Organization, binding.RepositoryName),
	}
}
