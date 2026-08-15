package githubapp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeInstallationTokenMinter struct {
	mu             sync.Mutex
	calls          int
	now            func() time.Time
	started        chan struct{}
	release        chan struct{}
	requests       []tokenMintRequest
	err            error
	respectContext bool
}

type tokenMintRequest struct {
	repositoryIDs []int64
	permissions   map[string]string
}

func (f *fakeInstallationTokenMinter) MintInstallationToken(ctx context.Context, repositoryIDs []int64, permissions map[string]string) (*InstallationToken, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.requests = append(f.requests, tokenMintRequest{
		repositoryIDs: append([]int64(nil), repositoryIDs...),
		permissions:   clonePermissions(permissions),
	})
	started, release, mintErr, respectContext := f.started, f.release, f.err, f.respectContext
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if respectContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if mintErr != nil {
		return nil, mintErr
	}
	return &InstallationToken{
		Value:     fmt.Sprintf("installation-token-%d", call),
		ExpiresAt: f.now().Add(time.Hour),
	}, nil
}

func (f *fakeInstallationTokenMinter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestTokenManagerNarrowsEveryMintToOneRepositoryAndContentsWrite(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	minter := &fakeInstallationTokenMinter{now: func() time.Time { return now }}
	manager := NewTokenManager(minter, func() time.Time { return now })

	token, err := manager.Token(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != "installation-token-1" {
		t.Fatalf("token = %q", token)
	}
	request := minter.requests[0]
	if len(request.repositoryIDs) != 1 || request.repositoryIDs[0] != 123456789 {
		t.Fatalf("repository IDs = %v, want exact repository", request.repositoryIDs)
	}
	if len(request.permissions) != 1 || request.permissions["contents"] != "write" {
		t.Fatalf("permissions = %#v, want contents:write only", request.permissions)
	}
}

func TestTokenManagerRefreshesAtSafePreExpiryAndNotBefore(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	minter := &fakeInstallationTokenMinter{now: func() time.Time { return now }}
	manager := NewTokenManager(minter, func() time.Time { return now })

	first, err := manager.Token(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	now = now.Add(54 * time.Minute)
	cached, err := manager.Token(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("cached Token: %v", err)
	}
	if cached != first || minter.callCount() != 1 {
		t.Fatalf("cached token = %q, calls = %d; want first token and one mint", cached, minter.callCount())
	}
	now = now.Add(time.Minute)
	refreshed, err := manager.Token(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("refreshed Token: %v", err)
	}
	if refreshed == first || minter.callCount() != 2 {
		t.Fatalf("refreshed token = %q, calls = %d; want new token and two mints", refreshed, minter.callCount())
	}
}

func TestTokenManagerEvictsUnsafeTokenEvenWhenRefreshFails(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	minter := &fakeInstallationTokenMinter{now: func() time.Time { return now }}
	manager := NewTokenManager(minter, func() time.Time { return now })
	if _, err := manager.Token(context.Background(), "123456789"); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	now = now.Add(55 * time.Minute)
	minter.err = fmt.Errorf("GitHub unavailable")
	if _, err := manager.Token(context.Background(), "123456789"); err == nil {
		t.Fatal("refresh Token succeeded, want error")
	}
	manager.mu.RLock()
	_, retained := manager.cache["123456789"]
	manager.mu.RUnlock()
	if retained {
		t.Fatal("unsafe installation token remained cached after refresh failure")
	}
}

func TestTokenManagerDeduplicatesConcurrentMint(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	minter := &fakeInstallationTokenMinter{
		now:     func() time.Time { return now },
		started: started,
		release: release,
	}
	manager := NewTokenManager(minter, func() time.Time { return now })

	const callers = 20
	errCh := make(chan error, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			token, err := manager.Token(context.Background(), "123456789")
			if err == nil && token != "installation-token-1" {
				err = fmt.Errorf("token = %q", token)
			}
			errCh <- err
		}()
	}
	close(start)
	<-started
	time.Sleep(10 * time.Millisecond)
	if calls := minter.callCount(); calls != 1 {
		t.Fatalf("mint calls while concurrent request blocked = %d, want 1", calls)
	}
	close(release)
	for range callers {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if calls := minter.callCount(); calls != 1 {
		t.Fatalf("mint calls = %d, want 1", calls)
	}
}

func TestTokenManagerLeaderCancellationDoesNotCancelSharedMint(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	minter := &fakeInstallationTokenMinter{
		now:            func() time.Time { return now },
		started:        started,
		release:        release,
		respectContext: true,
	}
	manager := NewTokenManager(minter, func() time.Time { return now })

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := manager.Token(leaderCtx, "123456789")
		leaderErr <- err
	}()
	<-started

	followerStarted := make(chan struct{})
	followerResult := make(chan struct {
		token string
		err   error
	}, 1)
	go func() {
		close(followerStarted)
		token, err := manager.Token(context.Background(), "123456789")
		followerResult <- struct {
			token string
			err   error
		}{token: token, err: err}
	}()
	<-followerStarted
	time.Sleep(10 * time.Millisecond)
	cancelLeader()
	if err := <-leaderErr; err != context.Canceled {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	close(release)

	follower := <-followerResult
	if follower.err != nil || follower.token != "installation-token-1" {
		t.Fatalf("follower result = %q, %v; want shared mint success", follower.token, follower.err)
	}
	if calls := minter.callCount(); calls != 1 {
		t.Fatalf("mint calls = %d, want one shared operation", calls)
	}
}

func TestTokenManagerRejectsInvalidRepositoryIDBeforeMint(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	minter := &fakeInstallationTokenMinter{now: func() time.Time { return now }}
	manager := NewTokenManager(minter, func() time.Time { return now })
	if _, err := manager.Token(context.Background(), "not-a-repository-id"); err == nil {
		t.Fatal("Token succeeded, want invalid repository ID error")
	}
	if calls := minter.callCount(); calls != 0 {
		t.Fatalf("mint calls = %d, want 0", calls)
	}
}
