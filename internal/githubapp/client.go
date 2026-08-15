package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	githubAPIBaseURL = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
	maxResponseBytes = 1 << 20
)

var (
	ErrRepositoryCollision      = errors.New("GitHub repository name already exists")
	ErrRepositoryCreateRejected = errors.New("GitHub rejected repository creation")
	ErrRepositoryNotFound       = errors.New("GitHub repository not found")
	ErrUnexpectedGitHubResponse = errors.New("GitHub returned an unexpected repository")
)

type Repository struct {
	ID           string
	Organization string
	Name         string
	CloneURL     string
}

type repositoryResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Private     bool   `json:"private"`
	Description string `json:"description"`
	CloneURL    string `json:"clone_url"`
	Owner       struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"owner"`
}

type InstallationToken struct {
	Value     string
	ExpiresAt time.Time
}

type Client struct {
	config     *Config
	baseURL    string
	httpClient *http.Client
	now        func() time.Time
}

func NewClient(config *Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{
		config:  config,
		baseURL: githubAPIBaseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		now: time.Now,
	}
}

func (c *Client) VerifyInstallation(ctx context.Context) error {
	jwt, err := c.appJWT()
	if err != nil {
		return err
	}
	var installation struct {
		ID                  int64  `json:"id"`
		AppID               int64  `json:"app_id"`
		RepositorySelection string `json:"repository_selection"`
		Account             struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		} `json:"account"`
		Permissions map[string]string `json:"permissions"`
	}
	status, err := c.doJSON(ctx, http.MethodGet,
		fmt.Sprintf("/app/installations/%d", c.config.InstallationID), jwt, nil, &installation)
	if err != nil {
		return fmt.Errorf("verify GitHub App installation: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("verify GitHub App installation: GitHub returned HTTP %d", status)
	}
	if installation.ID != c.config.InstallationID || installation.AppID != c.config.AppID ||
		installation.Account.ID != c.config.OrganizationID ||
		!strings.EqualFold(installation.Account.Login, c.config.Organization) {
		return fmt.Errorf("GitHub App installation identity does not match configured organization")
	}
	if installation.RepositorySelection != "selected" {
		return fmt.Errorf("GitHub App installation must use selected repositories")
	}
	if installation.Permissions["administration"] != "write" || installation.Permissions["contents"] != "write" {
		return fmt.Errorf("GitHub App installation must grant Administration write and Contents write")
	}
	return nil
}

func (c *Client) CreateRepository(ctx context.Context, token, name, marker string) (*Repository, error) {
	payload := struct {
		Name        string `json:"name"`
		Private     bool   `json:"private"`
		Description string `json:"description"`
	}{Name: name, Private: true, Description: marker}
	var response repositoryResponse
	path := "/orgs/" + url.PathEscape(c.config.Organization) + "/repos"
	status, err := c.doJSON(ctx, http.MethodPost, path, token, payload, &response)
	if err != nil {
		return nil, fmt.Errorf("create GitHub repository: %w", err)
	}
	if status == http.StatusUnprocessableEntity {
		return nil, fmt.Errorf("%w: HTTP %d", ErrRepositoryCreateRejected, status)
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("create GitHub repository: GitHub returned HTTP %d", status)
	}
	return c.validateRepository(response, name, marker)
}

// GetRepository returns a repository only when its immutable identity, private
// visibility, and provisioning marker exactly match this broker request.
func (c *Client) GetRepository(ctx context.Context, token, name, marker string) (*Repository, error) {
	var response repositoryResponse
	path := "/repos/" + url.PathEscape(c.config.Organization) + "/" + url.PathEscape(name)
	status, err := c.doJSON(ctx, http.MethodGet, path, token, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("get GitHub repository: %w", err)
	}
	if status == http.StatusNotFound {
		return nil, ErrRepositoryNotFound
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get GitHub repository: GitHub returned HTTP %d", status)
	}
	return c.validateRepository(response, name, marker)
}

func (c *Client) validateRepository(response repositoryResponse, name, marker string) (*Repository, error) {
	wantCloneURL := fmt.Sprintf("https://github.com/%s/%s.git", c.config.Organization, name)
	if response.ID <= 0 || response.Name != name || !response.Private || response.Description != marker ||
		response.Owner.ID != c.config.OrganizationID ||
		!strings.EqualFold(response.Owner.Login, c.config.Organization) ||
		response.CloneURL != wantCloneURL {
		return nil, ErrUnexpectedGitHubResponse
	}
	return &Repository{
		ID:           strconv.FormatInt(response.ID, 10),
		Organization: c.config.Organization,
		Name:         response.Name,
		CloneURL:     response.CloneURL,
	}, nil
}

func (c *Client) MintInstallationToken(ctx context.Context, repositoryIDs []int64, permissions map[string]string) (*InstallationToken, error) {
	jwt, err := c.appJWT()
	if err != nil {
		return nil, err
	}
	payload := struct {
		RepositoryIDs []int64           `json:"repository_ids,omitempty"`
		Permissions   map[string]string `json:"permissions"`
	}{RepositoryIDs: repositoryIDs, Permissions: permissions}
	var response struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	status, err := c.doJSON(ctx, http.MethodPost,
		fmt.Sprintf("/app/installations/%d/access_tokens", c.config.InstallationID), jwt, payload, &response)
	if err != nil {
		return nil, fmt.Errorf("mint GitHub App installation token: %w", err)
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("mint GitHub App installation token: GitHub returned HTTP %d", status)
	}
	if response.Token == "" || response.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("mint GitHub App installation token: GitHub returned an incomplete response")
	}
	return &InstallationToken{Value: response.Token, ExpiresAt: response.ExpiresAt}, nil
}

func (c *Client) appJWT() (string, error) {
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: "RS256", Type: "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal GitHub App JWT header: %w", err)
	}
	now := c.now().UTC()
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(9 * time.Minute).Unix(), Issuer: strconv.FormatInt(c.config.AppID, 10)})
	if err != nil {
		return "", fmt.Errorf("marshal GitHub App JWT claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.config.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *Client) doJSON(ctx context.Context, method, path, token string, input, output any) (int, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return 0, fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if output == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(output); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return resp.StatusCode, nil
}
