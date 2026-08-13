package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

const defaultServicesEnv = "AGENT_VAULT_DEFAULT_SERVICES_JSON"

// ValidateDefaultServicesEnv validates hosted default-service configuration
// before command startup performs any persistent store initialization.
func ValidateDefaultServicesEnv() error {
	_, err := loadDefaultServicesFromEnv()
	return err
}

func loadDefaultServicesFromEnv() ([]broker.Service, error) {
	raw := os.Getenv(defaultServicesEnv)
	if raw == "" {
		return nil, nil
	}

	var services []broker.Service
	if err := json.Unmarshal([]byte(raw), &services); err != nil {
		return nil, fmt.Errorf("decode %s: %w", defaultServicesEnv, err)
	}
	if services == nil {
		return nil, fmt.Errorf("decode %s: expected a JSON array", defaultServicesEnv)
	}
	services = splitInlineHosts(services)
	if err := broker.Validate(&broker.Config{Vault: "defaults", Services: services}); err != nil {
		return nil, fmt.Errorf("validate %s: %w", defaultServicesEnv, err)
	}
	return services, nil
}

func (s *Server) initialServicesJSON() (string, error) {
	if s.defaultServicesErr != nil {
		return "", s.defaultServicesErr
	}
	if len(s.defaultServices) == 0 {
		return "[]", nil
	}
	servicesJSON, err := json.Marshal(s.defaultServices)
	if err != nil {
		return "", fmt.Errorf("marshal default services: %w", err)
	}
	return string(servicesJSON), nil
}

func (s *Server) seedDefaultServices(ctx context.Context, vault *store.Vault) error {
	if s.defaultServicesErr != nil {
		return s.defaultServicesErr
	}
	if len(s.defaultServices) == 0 {
		return nil
	}

	unlock, err := s.lockVaultServices(ctx, vault.ID)
	if err != nil {
		return fmt.Errorf("lock vault services: %w", err)
	}
	defer unlock()

	existing, namesBackfilled, err := s.loadServicesWithBackfill(ctx, vault.ID)
	if err != nil {
		return fmt.Errorf("load vault services: %w", err)
	}
	byName := make(map[string]bool, len(existing))
	for _, service := range existing {
		byName[service.Name] = true
	}
	changed := namesBackfilled
	for _, service := range s.defaultServices {
		if !byName[service.Name] {
			existing = append(existing, service)
			byName[service.Name] = true
			changed = true
		}
	}
	if !changed {
		return nil
	}

	servicesJSON, err := json.Marshal(existing)
	if err != nil {
		return fmt.Errorf("marshal vault services: %w", err)
	}
	if _, err := s.store.SetBrokerConfig(ctx, vault.ID, string(servicesJSON)); err != nil {
		return fmt.Errorf("set vault services: %w", err)
	}
	return nil
}

func (s *Server) reconcileDefaultServices(ctx context.Context) error {
	if s.defaultServicesErr != nil {
		return s.defaultServicesErr
	}
	if len(s.defaultServices) == 0 {
		return nil
	}

	vaults, err := s.store.ListVaults(ctx)
	if err != nil {
		return fmt.Errorf("list vaults: %w", err)
	}
	for i := range vaults {
		if err := s.seedDefaultServices(ctx, &vaults[i]); err != nil {
			return fmt.Errorf("seed vault %q: %w", vaults[i].Name, err)
		}
	}
	return nil
}
