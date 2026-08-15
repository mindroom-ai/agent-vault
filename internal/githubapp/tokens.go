package githubapp

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	tokenRefreshBuffer = 5 * time.Minute
	tokenMintTimeout   = 30 * time.Second
)

type InstallationTokenMinter interface {
	MintInstallationToken(context.Context, []int64, map[string]string) (*InstallationToken, error)
}

type TokenManager struct {
	minter InstallationTokenMinter
	now    func() time.Time

	mu      sync.RWMutex
	cache   map[string]*InstallationToken
	minting singleflight.Group
}

func NewTokenManager(minter InstallationTokenMinter, now func() time.Time) *TokenManager {
	if now == nil {
		now = time.Now
	}
	return &TokenManager{minter: minter, now: now, cache: make(map[string]*InstallationToken)}
}

func (m *TokenManager) Token(ctx context.Context, repositoryID string) (string, error) {
	id, err := strconv.ParseInt(repositoryID, 10, 64)
	if err != nil || id <= 0 {
		return "", fmt.Errorf("repository ID must be a positive decimal integer")
	}
	if token := m.cached(repositoryID); token != "" {
		return token, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	result := m.minting.DoChan(repositoryID, func() (any, error) {
		if token := m.cached(repositoryID); token != "" {
			return token, nil
		}
		mintCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenMintTimeout)
		defer cancel()
		minted, err := m.minter.MintInstallationToken(mintCtx, []int64{id}, map[string]string{"contents": "write"})
		if err != nil {
			return "", err
		}
		if minted == nil || minted.Value == "" || !minted.ExpiresAt.After(m.now().Add(tokenRefreshBuffer)) {
			return "", fmt.Errorf("GitHub installation token has no safe usable lifetime")
		}
		m.mu.Lock()
		m.cache[repositoryID] = minted
		m.mu.Unlock()
		return minted.Value, nil
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case outcome := <-result:
		if outcome.Err != nil {
			return "", outcome.Err
		}
		return outcome.Val.(string), nil
	}
}

func (m *TokenManager) cached(repositoryID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := m.cache[repositoryID]
	if token == nil {
		return ""
	}
	if !token.ExpiresAt.After(m.now().Add(tokenRefreshBuffer)) {
		delete(m.cache, repositoryID)
		return ""
	}
	return token.Value
}

func clonePermissions(permissions map[string]string) map[string]string {
	cloned := make(map[string]string, len(permissions))
	for name, level := range permissions {
		cloned[name] = level
	}
	return cloned
}
