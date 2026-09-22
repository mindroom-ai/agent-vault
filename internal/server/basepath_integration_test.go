//go:build integration

package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestBuiltUIRootAndNestedBasePaths(t *testing.T) {
	assetPattern := regexp.MustCompile(`(?:src|href)="\./(assets/[^"]+)"`)
	stylesheetPattern := regexp.MustCompile(`href="\./(assets/[^"]+\.css)"`)
	fontPattern := regexp.MustCompile(`url\(\.\./(fonts/[^)]+\.woff2)\)`)

	for _, basePath := range []string{"", "/vault"} {
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
			prefix := ""
			if basePath != "" {
				prefix = basePath
			}

			deepLink := requestBuiltUI(t, srv, prefix+"/vaults/demo/services")
			if deepLink.Code != http.StatusOK {
				t.Fatalf("deep link status = %d, body = %s", deepLink.Code, deepLink.Body.String())
			}
			body := deepLink.Body.String()
			baseHref := "/"
			if prefix != "" {
				baseHref = prefix + "/"
			}
			if !strings.Contains(body, `<base href="`+baseHref+`" />`) {
				t.Fatalf("deep link has wrong runtime base configuration: %s", body)
			}

			match := assetPattern.FindStringSubmatch(body)
			if len(match) != 2 {
				t.Fatalf("built index has no relative asset URL: %s", body)
			}
			asset := requestBuiltUI(t, srv, prefix+"/"+match[1])
			if asset.Code != http.StatusOK || asset.Body.Len() == 0 {
				t.Fatalf("asset status = %d, bytes = %d", asset.Code, asset.Body.Len())
			}

			stylesheetMatch := stylesheetPattern.FindStringSubmatch(body)
			if len(stylesheetMatch) != 2 {
				t.Fatalf("built index has no relative stylesheet URL: %s", body)
			}
			stylesheet := requestBuiltUI(t, srv, prefix+"/"+stylesheetMatch[1])
			if stylesheet.Code != http.StatusOK {
				t.Fatalf("stylesheet status = %d, body = %s", stylesheet.Code, stylesheet.Body.String())
			}
			fontMatch := fontPattern.FindStringSubmatch(stylesheet.Body.String())
			if len(fontMatch) != 2 {
				t.Fatalf("built stylesheet has no relative font URL")
			}
			font := requestBuiltUI(t, srv, prefix+"/"+fontMatch[1])
			if font.Code != http.StatusOK || font.Body.Len() == 0 {
				t.Fatalf("font status = %d, bytes = %d", font.Code, font.Body.Len())
			}
			for _, favicon := range []string{"/favicon.svg", "/favicon.png"} {
				icon := requestBuiltUI(t, srv, prefix+favicon)
				if icon.Code != http.StatusOK || icon.Body.Len() == 0 {
					t.Fatalf("GET %s: status = %d, bytes = %d", prefix+favicon, icon.Code, icon.Body.Len())
				}
			}

			for _, path := range []string{prefix + "/login", prefix + "/v1/status"} {
				resp := requestBuiltUI(t, srv, path)
				if resp.Code != http.StatusOK {
					t.Fatalf("GET %s: status = %d, body = %s", path, resp.Code, resp.Body.String())
				}
			}
		})
	}
}

func requestBuiltUI(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}
