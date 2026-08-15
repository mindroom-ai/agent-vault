package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/githubapp"
)

func (s *Server) handleMindRoomRepositoryEnsure(w http.ResponseWriter, r *http.Request) {
	manager := s.githubRepositories
	if manager == nil {
		jsonError(w, http.StatusServiceUnavailable, "MindRoom repository broker is not configured")
		return
	}
	authorization := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || token == "" || !manager.AuthenticateBrokerToken(token) {
		jsonError(w, http.StatusUnauthorized, "Invalid repository broker credentials")
		return
	}
	vaultName := r.Header.Get("X-Vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "X-Vault is required")
		return
	}
	vault, err := s.store.GetVault(r.Context(), vaultName)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Logical vault not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadGateway, "Failed to resolve logical vault")
		return
	}
	if vault == nil {
		jsonError(w, http.StatusNotFound, "Logical vault not found")
		return
	}

	var request githubapp.EnsureRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid repository ensure request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "Invalid repository ensure request")
		return
	}

	lease, created, err := manager.EnsureRepository(r.Context(), vault.ID, request)
	if err != nil {
		switch {
		case errors.Is(err, githubapp.ErrInvalidEnsureRequest):
			jsonError(w, http.StatusBadRequest, "Invalid repository ensure request")
		case errors.Is(err, githubapp.ErrBindingConflict), errors.Is(err, githubapp.ErrRepositoryCollision):
			jsonError(w, http.StatusConflict, "Repository binding conflicts with existing state")
		default:
			jsonError(w, http.StatusBadGateway, "Repository provisioning failed")
		}
		return
	}
	if created {
		jsonCreated(w, lease)
		return
	}
	jsonOK(w, lease)
}
