package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

const defaultServicesFixture = `[
  {"name":"google-workspace-apis","host":"*.googleapis.com","auth":{"type":"bearer","token":"GOOGLE"}},
  {"name":"google-workspace-www-apis","host":"www.googleapis.com","auth":{"type":"bearer","token":"GOOGLE"}},
  {"name":"github","host":"api.github.com","auth":{"type":"bearer","token":"GITHUB_TOKEN"}},
  {"name":"github-git","host":"github.com","auth":{"type":"basic","username":"GITHUB_TOKEN","password":"GITHUB_TOKEN"}}
]`

func TestVaultCreateSeedsConfiguredDefaultServices(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEFAULT_SERVICES_JSON", defaultServicesFixture)
	ms, token := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))

	req := httptest.NewRequest(http.MethodPost, "/v1/vaults", strings.NewReader(`{"name":"project-vault"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	config := ms.brokerConfigs["ns-project-vault"]
	if config == nil {
		t.Fatal("new vault has no broker config with default services")
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	if len(services) != 4 {
		t.Fatalf("expected 4 default services, got %d: %s", len(services), config.ServicesJSON)
	}
	if services[0].Name != "google-workspace-apis" || services[1].Name != "google-workspace-www-apis" ||
		services[2].Name != "github" || services[3].Name != "github-git" {
		t.Fatalf("unexpected default services: %s", config.ServicesJSON)
	}
}

func TestDefaultServiceSeedPreservesExistingNamedServices(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEFAULT_SERVICES_JSON", defaultServicesFixture)
	ms := newMockStore()
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID: "root-ns-id",
		ServicesJSON: `[
          {"name":"github","host":"api.github.com","auth":{"type":"bearer","token":"CUSTOM_GITHUB_TOKEN"}},
          {"name":"custom","host":"api.example.com","auth":{"type":"bearer","token":"CUSTOM_TOKEN"}}
        ]`,
	}
	srv := newTestServer(withStore(ms))

	if err := srv.seedDefaultServices(context.Background(), ms.vaults["default"]); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}

	config := ms.brokerConfigs["root-ns-id"]
	var services []broker.Service
	if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	if len(services) != 5 {
		t.Fatalf("expected two existing services plus three missing defaults, got %d: %s", len(services), config.ServicesJSON)
	}
	byName := make(map[string]broker.Service, len(services))
	for _, service := range services {
		byName[service.Name] = service
	}
	if got := byName["github"].Auth.Token; got != "CUSTOM_GITHUB_TOKEN" {
		t.Fatalf("existing github service was overwritten: token key = %q", got)
	}
	if _, ok := byName["custom"]; !ok {
		t.Fatal("custom service was removed")
	}
	if _, ok := byName["github-git"]; !ok {
		t.Fatal("missing default github-git service was not added")
	}
}

func TestDefaultServiceSeedPersistsBackfilledNamesWithoutAddingService(t *testing.T) {
	t.Setenv(
		"AGENT_VAULT_DEFAULT_SERVICES_JSON",
		`[{"name":"api-github-com","host":"api.github.com","auth":{"type":"bearer","token":"GITHUB_TOKEN"}}]`,
	)
	ms := newMockStore()
	ms.brokerConfigs["root-ns-id"] = &store.BrokerConfig{
		VaultID:      "root-ns-id",
		ServicesJSON: `[{"host":"api.github.com","auth":{"type":"bearer","token":"GITHUB_TOKEN"}}]`,
	}
	srv := newTestServer(withStore(ms))

	if err := srv.seedDefaultServices(context.Background(), ms.vaults["default"]); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(ms.brokerConfigs["root-ns-id"].ServicesJSON), &services); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	if len(services) != 1 || services[0].Name != "api-github-com" {
		t.Fatalf("expected backfilled name to be persisted, got %s", ms.brokerConfigs["root-ns-id"].ServicesJSON)
	}
}

func TestConfiguredDefaultServicesBackfillExistingVaults(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEFAULT_SERVICES_JSON", defaultServicesFixture)
	ms := newMockStore()
	other, err := ms.CreateVault(context.Background(), "other-vault")
	if err != nil {
		t.Fatalf("create existing vault: %v", err)
	}
	srv := newTestServer(withStore(ms))

	reconciler, ok := any(srv).(interface {
		reconcileDefaultServices(context.Context) error
	})
	if !ok {
		t.Fatal("server does not support default-service reconciliation")
	}
	if err := reconciler.reconcileDefaultServices(context.Background()); err != nil {
		t.Fatalf("reconcile defaults: %v", err)
	}

	for _, vaultID := range []string{"root-ns-id", other.ID} {
		config := ms.brokerConfigs[vaultID]
		if config == nil {
			t.Fatalf("vault %s was not backfilled", vaultID)
		}
		var services []broker.Service
		if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
			t.Fatalf("decode services for %s: %v", vaultID, err)
		}
		if len(services) != 4 {
			t.Fatalf("vault %s: expected 4 services, got %d", vaultID, len(services))
		}
	}
}

func TestStartFailsToBindBeforeDefaultServiceReconciliation(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEFAULT_SERVICES_JSON", defaultServicesFixture)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close()

	ms := newMockStore()
	srv := newTestServer(withStore(ms))
	srv.httpServer.Addr = occupied.Addr().String()

	err = srv.Start()
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("expected listen error, got %v", err)
	}
	if config := ms.brokerConfigs["root-ns-id"]; config != nil {
		t.Fatalf("failed startup mutated vault services: %s", config.ServicesJSON)
	}
}

func TestStartClosesListenerWhenDefaultServiceReconciliationFails(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate address: %v", err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}

	t.Setenv("AGENT_VAULT_DEFAULT_SERVICES_JSON", "not-json")
	srv := newTestServer()
	srv.httpServer.Addr = addr

	err = srv.Start()
	if err == nil || !strings.Contains(err.Error(), "reconcile default services") {
		t.Fatalf("expected reconciliation error, got %v", err)
	}
	rebound, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listener leaked after reconciliation failure: %v", err)
	}
	defer rebound.Close()
}

func TestConfiguredDefaultServicesRejectInvalidServiceBeforeBackfill(t *testing.T) {
	t.Setenv(
		"AGENT_VAULT_DEFAULT_SERVICES_JSON",
		`[{"name":"github","host":"api.github.com","auth":{"type":"bearer"}}]`,
	)
	ms := newMockStore()
	srv := newTestServer(withStore(ms))

	err := srv.reconcileDefaultServices(context.Background())
	if err == nil {
		t.Fatal("expected invalid default service configuration to fail")
	}
	if !strings.Contains(err.Error(), "AGENT_VAULT_DEFAULT_SERVICES_JSON") {
		t.Fatalf("error should identify configuration source, got %v", err)
	}
	if config := ms.brokerConfigs["root-ns-id"]; config != nil {
		t.Fatalf("invalid defaults mutated existing vault: %s", config.ServicesJSON)
	}
}

func TestConfiguredDefaultServicesRejectNull(t *testing.T) {
	t.Setenv("AGENT_VAULT_DEFAULT_SERVICES_JSON", "null")
	srv := newTestServer()

	err := srv.reconcileDefaultServices(context.Background())
	if err == nil {
		t.Fatal("expected null default services configuration to fail")
	}
	if !strings.Contains(err.Error(), "JSON array") {
		t.Fatalf("error should require a JSON array, got %v", err)
	}
}
