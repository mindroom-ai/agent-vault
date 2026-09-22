package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeUIBasePath(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"":              "/",
		"   ":           "/",
		"/":             "/",
		"vault":         "/vault",
		"/vault":        "/vault",
		" /vault/ ":     "/vault",
		"teams/primary": "/teams/primary",
		"/~ops/ui-v2":   "/~ops/ui-v2",
	}
	for input, want := range valid {
		input, want := input, want
		t.Run("valid_"+input, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeUIBasePath(input)
			if err != nil {
				t.Fatalf("NormalizeUIBasePath(%q): %v", input, err)
			}
			if got != want {
				t.Fatalf("NormalizeUIBasePath(%q) = %q, want %q", input, got, want)
			}
		})
	}

	invalid := []string{
		"https://example.com/vault",
		"//example.com/vault",
		"/v1",
		"/v1/dashboard",
		"/health",
		"/discover",
		"/vault?mode=admin",
		"/vault#settings",
		"/vault//nested",
		"/vault/../admin",
		"/vault/./admin",
		"/vault/%2e%2e/admin",
		`/vault\admin`,
		"/vault\x00/admin",
		"/vault/%2Fadmin",
		"/vault/space here",
	}
	for _, input := range invalid {
		input := input
		t.Run("invalid_"+input, func(t *testing.T) {
			t.Parallel()
			if got, err := NormalizeUIBasePath(input); err == nil {
				t.Fatalf("NormalizeUIBasePath(%q) = %q, want error", input, got)
			}
		})
	}
}

func TestServerRoutesUnderUIBasePath(t *testing.T) {
	srv := New(
		"127.0.0.1:0",
		newMockStore(),
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)

	if got := srv.UIBasePath(); got != "/vault" {
		t.Fatalf("UIBasePath() = %q, want /vault", got)
	}
	if got := srv.UIURL("/invite/token"); got != "https://vault.example.com/vault/invite/token" {
		t.Fatalf("UIURL() = %q", got)
	}

	for _, path := range []string{"/v1/status", "/vault/v1/status"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, body = %s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"initialized":true`) {
			t.Fatalf("GET %s: unexpected body %s", path, rec.Body.String())
		}
	}
}

func TestUIBasePathHandler(t *testing.T) {
	t.Parallel()

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	})
	handler := mountUIBasePath(app, "/vault")

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
		wantHeader string
	}{
		{path: "/vault", wantStatus: http.StatusPermanentRedirect, wantHeader: "/vault/"},
		{path: "/vault?token=example", wantStatus: http.StatusPermanentRedirect, wantHeader: "/vault/?token=example"},
		{path: "/vault/", wantStatus: http.StatusOK, wantBody: "/"},
		{path: "/vault/assets/app.js", wantStatus: http.StatusOK, wantBody: "/assets/app.js"},
		{path: "/vault/v1/status", wantStatus: http.StatusOK, wantBody: "/v1/status"},
		{path: "/vault/vaults/example/services", wantStatus: http.StatusOK, wantBody: "/vaults/example/services"},
		{path: "/v1/status", wantStatus: http.StatusOK, wantBody: "/v1/status"},
		{path: "/vaulted", wantStatus: http.StatusOK, wantBody: "/vaulted"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Body.String(); tt.wantStatus == http.StatusOK && got != tt.wantBody {
				t.Fatalf("body = %q, want %q", got, tt.wantBody)
			}
			if got := rec.Header().Get("Location"); got != tt.wantHeader {
				t.Fatalf("Location = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestUIBasePathCanonicalRedirectsStayMounted(t *testing.T) {
	srv := New(
		"127.0.0.1:0",
		newMockStore(),
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)

	tests := []struct {
		path        string
		fragment    string
		rawFragment string
		want        string
	}{
		{path: "/vault/vaults?next=%2Fdemo%2Fone", fragment: "section/one", rawFragment: "section%2Fone", want: "/vault/vaults/?next=%2Fdemo%2Fone#section%2Fone"},
		{path: "/vault/account", want: "/vault/account/"},
		{path: "/vault/manage", want: "/vault/manage/"},
		{path: "/vault/assets", want: "/vault/assets/"},
		{path: "/vault/vaults//demo/services?next=%2Fone", want: "/vault/vaults/demo/services?next=%2Fone"},
		{path: "/vault/vaults//demo/a%2Fb", want: "/vault/vaults/demo/a%2Fb"},
		{path: "/vault/vaults/../../v1/status?next=%2Fone", want: "/vault/v1/status?next=%2Fone"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.URL.Fragment = tt.fragment
			req.URL.RawFragment = tt.rawFragment
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusTemporaryRedirect)
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Fatalf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUIBasePathMountNameOverlapRedirects(t *testing.T) {
	for _, basePath := range []string{"/vaults", "/account", "/manage", "/assets", "/fonts"} {
		t.Run(basePath, func(t *testing.T) {
			srv := New(
				"127.0.0.1:0",
				newMockStore(),
				make([]byte, 32),
				nil,
				true,
				"https://vault.example.com",
				basePath,
				slog.New(slog.DiscardHandler),
			)

			requestPath := basePath + basePath + "?next=%2Fone"
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, requestPath, nil)
			srv.httpServer.Handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusTemporaryRedirect)
			}
			want := basePath + basePath + "/?next=%2Fone"
			if got := rec.Header().Get("Location"); got != want {
				t.Fatalf("Location = %q, want %q", got, want)
			}
		})
	}
}

func TestRenderSPAIndex(t *testing.T) {
	t.Parallel()

	template := []byte(`<base href="__AGENT_VAULT_UI_BASE_HREF__"><meta name="agent-vault-ui-base-path" content="__AGENT_VAULT_UI_BASE_PATH__">`)
	tests := []struct {
		basePath string
		wantBase string
		wantMeta string
	}{
		{basePath: "/", wantBase: `href="/"`, wantMeta: `content="/"`},
		{basePath: "/vault", wantBase: `href="/vault/"`, wantMeta: `content="/vault"`},
	}
	for _, tt := range tests {
		got, err := renderSPAIndex(template, tt.basePath)
		if err != nil {
			t.Fatalf("renderSPAIndex(%q): %v", tt.basePath, err)
		}
		body := string(got)
		if !strings.Contains(body, tt.wantBase) || !strings.Contains(body, tt.wantMeta) {
			t.Fatalf("rendered body %q does not contain %q and %q", body, tt.wantBase, tt.wantMeta)
		}
		if strings.Contains(body, "__AGENT_VAULT_UI_BASE_") {
			t.Fatalf("rendered body retains placeholder: %q", body)
		}
	}
}

func TestUIBasePathScopesOAuthRedirectsAndCookies(t *testing.T) {
	srv := New(
		"127.0.0.1:0",
		newMockStore(),
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)
	if got := srv.oauthCallbackURL(); got != "https://vault.example.com/vault/v1/oauth/callback" {
		t.Fatalf("oauthCallbackURL() = %q", got)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vault/v1/oauth/callback", nil)
	srv.redirectOAuthComplete(rec, req, "demo", "TOKEN", "success", "")
	if got := rec.Header().Get("Location"); got != "https://vault.example.com/vault/oauth/complete?status=success&vault=demo&key=TOKEN" {
		t.Fatalf("OAuth completion Location = %q", got)
	}

	cookie := sessionCookie(req, srv.baseURL, srv.uiBasePath, "session-token", 3600)
	if cookie.Path != "/vault" {
		t.Fatalf("cookie Path = %q, want /vault", cookie.Path)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie security flags changed: %#v", cookie)
	}

	rootCookie := sessionCookie(req, srv.baseURL, "/", "session-token", 3600)
	if rootCookie.Path != "/" {
		t.Fatalf("root cookie Path = %q, want /", rootCookie.Path)
	}
}

func TestUIBasePathMigrationLogoutClearsOnlyCurrentBrowserSessions(t *testing.T) {
	ms := newMockStore()
	root := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		false,
		"https://vault.example.com",
		"/",
		slog.New(slog.DiscardHandler),
	)

	request := func(jar http.CookieJar, srv *Server, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		u, err := url.Parse("https://vault.example.com" + path)
		if err != nil {
			t.Fatalf("parse request URL: %v", err)
		}
		req := httptest.NewRequest(method, u.String(), strings.NewReader(body))
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		jar.SetCookies(u, rec.Result().Cookies())
		return rec
	}

	firstBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create first cookie jar: %v", err)
	}
	secondBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create second cookie jar: %v", err)
	}
	credentials := `{"email":"owner@example.test","password":"owner-password-843"}`
	if rec := request(firstBrowser, root, http.MethodPost, "/v1/auth/register", credentials); rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := request(secondBrowser, root, http.MethodPost, "/v1/auth/login", credentials); rec.Code != http.StatusOK {
		t.Fatalf("second browser login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	mounted := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)
	if rec := request(firstBrowser, mounted, http.MethodPost, "/vault/v1/auth/login", credentials); rec.Code != http.StatusOK {
		t.Fatalf("prefixed login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	prefixedURL, err := url.Parse("https://vault.example.com/vault/v1/auth/me")
	if err != nil {
		t.Fatalf("parse prefixed URL: %v", err)
	}
	firstBrowserCookies := firstBrowser.Cookies(prefixedURL)
	if got := len(firstBrowserCookies); got != 2 {
		t.Fatalf("first browser cookies after mount migration = %d, want 2", got)
	}

	if rec := request(firstBrowser, mounted, http.MethodPost, "/vault/v1/auth/logout", ""); rec.Code != http.StatusOK {
		t.Fatalf("logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := len(firstBrowser.Cookies(prefixedURL)); got != 0 {
		t.Fatalf("first browser cookies after logout = %d, want 0", got)
	}
	for _, cookie := range firstBrowserCookies {
		if _, ok := ms.sessions[cookie.Value]; ok {
			t.Fatal("a first-browser session survives logout")
		}
	}
	if rec := request(firstBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first browser reauthenticated after logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := request(secondBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("second browser session was revoked: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestUIBasePathSelfRevokeClearsOnlyCurrentBrowserSessions(t *testing.T) {
	ms := newMockStore()
	root := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		false,
		"https://vault.example.com",
		"/",
		slog.New(slog.DiscardHandler),
	)

	request := func(jar http.CookieJar, srv *Server, method, requestPath, body string) *httptest.ResponseRecorder {
		t.Helper()
		u, err := url.Parse("https://vault.example.com" + requestPath)
		if err != nil {
			t.Fatalf("parse request URL: %v", err)
		}
		req := httptest.NewRequest(method, u.String(), strings.NewReader(body))
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		jar.SetCookies(u, rec.Result().Cookies())
		return rec
	}

	firstBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create first cookie jar: %v", err)
	}
	secondBrowser, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create second cookie jar: %v", err)
	}
	credentials := `{"email":"owner@example.test","password":"owner-password-843"}`
	register := request(firstBrowser, root, http.MethodPost, "/v1/auth/register", credentials)
	if register.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, body = %s", register.Code, register.Body.String())
	}
	var rootLogin loginResponse
	if err := json.NewDecoder(register.Body).Decode(&rootLogin); err != nil {
		t.Fatalf("decode root registration: %v", err)
	}
	secondLogin := request(secondBrowser, root, http.MethodPost, "/v1/auth/login", credentials)
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("second browser login: status = %d, body = %s", secondLogin.Code, secondLogin.Body.String())
	}
	var secondBrowserLogin loginResponse
	if err := json.NewDecoder(secondLogin.Body).Decode(&secondBrowserLogin); err != nil {
		t.Fatalf("decode second browser login: %v", err)
	}

	mounted := New(
		"127.0.0.1:0",
		ms,
		make([]byte, 32),
		nil,
		true,
		"https://vault.example.com",
		"/vault",
		slog.New(slog.DiscardHandler),
	)
	prefixedLogin := request(firstBrowser, mounted, http.MethodPost, "/vault/v1/auth/login", credentials)
	if prefixedLogin.Code != http.StatusOK {
		t.Fatalf("prefixed login: status = %d, body = %s", prefixedLogin.Code, prefixedLogin.Body.String())
	}
	var mountedSession loginResponse
	if err := json.NewDecoder(prefixedLogin.Body).Decode(&mountedSession); err != nil {
		t.Fatalf("decode prefixed login: %v", err)
	}
	prefixedURL, err := url.Parse("https://vault.example.com/vault/v1/auth/me")
	if err != nil {
		t.Fatalf("parse prefixed URL: %v", err)
	}
	if got := len(firstBrowser.Cookies(prefixedURL)); got != 2 {
		t.Fatalf("first browser cookies after mount migration = %d, want 2", got)
	}
	current := ms.sessions[mountedSession.Token]
	if current == nil {
		t.Fatal("prefixed session was not stored")
	}

	revokePath := "/vault/v1/auth/sessions/" + current.PublicID
	if rec := request(firstBrowser, mounted, http.MethodDelete, revokePath, ""); rec.Code != http.StatusOK {
		t.Fatalf("self-revoke: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := len(firstBrowser.Cookies(prefixedURL)); got != 0 {
		t.Fatalf("first browser cookies after self-revoke = %d, want 0", got)
	}
	for _, token := range []string{rootLogin.Token, mountedSession.Token} {
		if _, ok := ms.sessions[token]; ok {
			t.Fatalf("first-browser session %q survives self-revoke", token)
		}
	}
	if _, ok := ms.sessions[secondBrowserLogin.Token]; !ok {
		t.Fatal("second browser session was revoked")
	}
	if rec := request(firstBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first browser reauthenticated after self-revoke: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := request(secondBrowser, mounted, http.MethodGet, "/vault/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("second browser session stopped authenticating: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestLogoutBearerDoesNotRevokeCookieSession(t *testing.T) {
	ms := setupMockStoreWithUser(t, "owner@example.test", "owner-password-843")
	srv := newTestServer(withStore(ms))
	login := func() string {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/auth/login",
			strings.NewReader(`{"email":"owner@example.test","password":"owner-password-843"}`),
		)
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("login cookies = %d, want 1", len(cookies))
		}
		return cookies[0].Value
	}

	bearerToken := login()
	cookieToken := login()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.AddCookie(&http.Cookie{Name: "av_session", Value: cookieToken})
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, ok := ms.sessions[bearerToken]; ok {
		t.Fatal("Bearer session survives logout")
	}
	if _, ok := ms.sessions[cookieToken]; !ok {
		t.Fatal("cookie session was revoked by Bearer logout")
	}
}
