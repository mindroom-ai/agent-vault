package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
)

const (
	uiBaseHrefPlaceholder = "__AGENT_VAULT_UI_BASE_HREF__"
	uiBasePathPlaceholder = "__AGENT_VAULT_UI_BASE_PATH__"
)

// NormalizeUIBasePath validates and canonicalizes the path where the browser
// UI is served. The root path is represented as "/"; nested paths have one
// leading slash and no trailing slash.
func NormalizeUIBasePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" || path == "/" {
		return "/", nil
	}
	if strings.HasPrefix(path, "//") || strings.ContainsAny(path, "%?#\\") {
		return "", fmt.Errorf("must be a local URL path without encoding, query, or fragment")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	if strings.Contains(path, "//") {
		return "", fmt.Errorf("must not contain repeated separators")
	}
	if path == "/health" || path == "/discover" || path == "/v1" || strings.HasPrefix(path, "/v1/") {
		return "", fmt.Errorf("must not overlap a root control API path")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("must not contain traversal segments")
		}
		if segment == "" {
			return "", fmt.Errorf("must not contain empty segments")
		}
		for _, ch := range segment {
			if !isSafeUIPathCharacter(ch) {
				return "", fmt.Errorf("contains unsupported character %q", ch)
			}
		}
	}
	return path, nil
}

func isSafeUIPathCharacter(ch rune) bool {
	return ch >= 'a' && ch <= 'z' ||
		ch >= 'A' && ch <= 'Z' ||
		ch >= '0' && ch <= '9' ||
		strings.ContainsRune("-._~", ch)
}

func mountUIBasePath(app http.Handler, basePath string) http.Handler {
	if basePath == "/" {
		return app
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == basePath {
			redirectURL := *r.URL
			redirectURL.Path = basePath + "/"
			redirectURL.RawPath = ""
			http.Redirect(w, r, redirectURL.String(), http.StatusPermanentRedirect)
			return
		}
		if strings.HasPrefix(r.URL.Path, basePath+"/") {
			if location, ok := canonicalUIRequestLocation(r.URL, basePath); ok {
				http.Redirect(w, r, location, http.StatusTemporaryRedirect)
				return
			}
			clone := r.Clone(r.Context())
			urlCopy := *r.URL
			urlCopy.Path = strings.TrimPrefix(r.URL.Path, basePath)
			if urlCopy.RawPath != "" {
				urlCopy.RawPath = strings.TrimPrefix(r.URL.RawPath, basePath)
			}
			clone.URL = &urlCopy
			app.ServeHTTP(&uiBasePathResponseWriter{
				ResponseWriter: w,
				basePath:       basePath,
				requestURL:     r.URL,
			}, clone)
			return
		}
		app.ServeHTTP(w, r)
	})
}

type uiBasePathResponseWriter struct {
	http.ResponseWriter
	basePath   string
	requestURL *url.URL
}

func (w *uiBasePathResponseWriter) WriteHeader(status int) {
	if status >= http.StatusMultipleChoices && status < http.StatusBadRequest {
		location := w.Header().Get("Location")
		if location != "" {
			w.Header().Set("Location", rebaseUIRedirectLocation(location, w.basePath, w.requestURL))
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *uiBasePathResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func canonicalUIRequestLocation(requestURL *url.URL, basePath string) (string, bool) {
	escapedPath := requestURL.EscapedPath()
	escapedSuffix := strings.TrimPrefix(escapedPath, basePath)
	if escapedSuffix == escapedPath {
		return "", false
	}
	cleanedPath := basePath + cleanUIRequestPath(escapedSuffix)
	if cleanedPath == escapedPath {
		return "", false
	}
	decodedPath, err := url.PathUnescape(cleanedPath)
	if err != nil {
		return "", false
	}
	redirectURL := *requestURL
	redirectURL.Path = decodedPath
	redirectURL.RawPath = cleanedPath
	return redirectURL.String(), true
}

func cleanUIRequestPath(path string) string {
	if path == "" {
		return "/"
	}
	cleaned := pathpkg.Clean(path)
	if strings.HasSuffix(path, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func rebaseUIRedirectLocation(location, basePath string, requestURL *url.URL) string {
	redirectURL, err := url.Parse(location)
	if err != nil || redirectURL.IsAbs() || redirectURL.Host != "" || !strings.HasPrefix(redirectURL.Path, "/") {
		return location
	}
	// Requests reaching this writer have already had basePath stripped, so a
	// root-relative Location belongs to the application namespace. Redirects
	// intentionally targeting a public URL must use an absolute URL from UIURL.
	redirectURL.Path = basePath + redirectURL.Path
	if redirectURL.RawPath != "" {
		redirectURL.RawPath = basePath + redirectURL.RawPath
	}
	if redirectURL.Fragment == "" && requestURL.Fragment != "" {
		redirectURL.Fragment = requestURL.Fragment
		redirectURL.RawFragment = requestURL.RawFragment
	}
	return redirectURL.String()
}

func renderSPAIndex(template []byte, basePath string) ([]byte, error) {
	if !bytes.Contains(template, []byte(uiBaseHrefPlaceholder)) ||
		!bytes.Contains(template, []byte(uiBasePathPlaceholder)) {
		return nil, fmt.Errorf("frontend index is missing UI base path placeholders")
	}
	baseHref := basePath
	if baseHref != "/" {
		baseHref += "/"
	}
	rendered := bytes.ReplaceAll(template, []byte(uiBaseHrefPlaceholder), []byte(baseHref))
	rendered = bytes.ReplaceAll(rendered, []byte(uiBasePathPlaceholder), []byte(basePath))
	return rendered, nil
}
