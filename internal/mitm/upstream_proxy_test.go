package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestUpstreamProxyFromEnvironmentUnsetReturnsNil(t *testing.T) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		t.Setenv(v, "")
	}
	if fn := upstreamProxyFromEnvironment(); fn != nil {
		t.Fatal("upstreamProxyFromEnvironment() with no proxy env should be nil so the direct path stays unchanged")
	}
}

func TestUpstreamProxyFromEnvironmentHonorsEnv(t *testing.T) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		t.Setenv(v, "")
	}
	t.Setenv("HTTPS_PROXY", "http://egress.internal:3128")
	t.Setenv("NO_PROXY", "bypassed.example")

	fn := upstreamProxyFromEnvironment()
	if fn == nil {
		t.Fatal("upstreamProxyFromEnvironment() = nil with HTTPS_PROXY set")
	}

	proxied, err := fn(httptest.NewRequest(http.MethodGet, "https://api.example.com/v1", nil))
	if err != nil {
		t.Fatalf("proxy func: %v", err)
	}
	if proxied == nil || proxied.Host != "egress.internal:3128" {
		t.Fatalf("proxy for api.example.com = %v, want egress.internal:3128", proxied)
	}

	bypassed, err := fn(httptest.NewRequest(http.MethodGet, "https://bypassed.example/v1", nil))
	if err != nil {
		t.Fatalf("proxy func: %v", err)
	}
	if bypassed != nil {
		t.Fatalf("proxy for NO_PROXY host = %v, want direct", bypassed)
	}
}

// connectRecorder collects the CONNECT targets a test egress proxy saw.
type connectRecorder struct {
	mu      sync.Mutex
	targets []string
}

func (c *connectRecorder) record(target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targets = append(c.targets, target)
}

func (c *connectRecorder) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.targets...)
}

// startConnectProxy runs a minimal recording CONNECT proxy, standing in for
// a corporate/cluster egress proxy. deny=true refuses every tunnel with
// 403, mimicking an allowlist rejection.
func startConnectProxy(t *testing.T, deny bool) (*url.URL, *connectRecorder) {
	t.Helper()
	rec := &connectRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "only CONNECT", http.StatusMethodNotAllowed)
			return
		}
		rec.record(r.Host)
		if deny {
			http.Error(w, "forbidden by allowlist", http.StatusForbidden)
			return
		}
		dst, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = dst.Close()
			http.Error(w, "cannot hijack", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			_ = dst.Close()
			return
		}
		_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = bufrw.Flush()
		go func() {
			_, _ = io.Copy(dst, conn)
			_ = dst.Close()
		}()
		_, _ = io.Copy(conn, dst)
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return u, rec
}

// trustUpstream points the MITM transport's TLS config at the httptest
// upstream's certificate, as the other e2e tests do.
func trustUpstream(p *Proxy, upstream *httptest.Server) {
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
}

func TestMITMChainsHTTPSThroughEgressProxy(t *testing.T) {
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "chained-body")
	}))
	defer upstream.Close()

	upstreamAuthority := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)

	egressURL, rec := startConnectProxy(t, false)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"},
		}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	trustUpstream(p, upstream)
	// Injected the same way upstreamProxyFromEnvironment wires it; the env
	// path itself is covered above (httpproxy bypasses loopback hosts, so
	// an env-driven e2e against 127.0.0.1 would silently go direct).
	p.upstream.Proxy = http.ProxyURL(egressURL)

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "chained-body" {
		t.Fatalf("body = %q, want chained-body", body)
	}
	if sawAuth != "Bearer injected-secret" {
		t.Fatalf("upstream saw Authorization %q; injection must survive chaining", sawAuth)
	}
	targets := rec.recorded()
	if len(targets) != 1 || targets[0] != upstreamAuthority {
		t.Fatalf("egress proxy saw CONNECT targets %v, want exactly [%s]", targets, upstreamAuthority)
	}
}

func TestMITMSurfacesEgressProxyDenial(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must not be reached when the egress proxy denies CONNECT")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamHost, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	egressURL, rec := startConnectProxy(t, true)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	// The host IS injectable, so the request clears agent-vault's own host
	// policy and reaches the dial — where the egress proxy refuses CONNECT.
	// This isolates "egress proxy said no" from "agent-vault said no".
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	trustUpstream(p, upstream)
	p.upstream.Proxy = http.ProxyURL(egressURL)

	client := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots)
	resp, err := client.Get(upstream.URL + "/ping")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 500 {
			t.Fatalf("status = %d, want a transport error or 5xx when the egress proxy refuses the tunnel", resp.StatusCode)
		}
	}
	// The decisive assertion: the request was handed to the egress proxy
	// (not dialed directly), and never reached the upstream (t.Error above).
	if got := rec.recorded(); len(got) != 1 {
		t.Fatalf("egress proxy saw CONNECT targets %v, want exactly one (the denied tunnel)", got)
	}
}

func TestMITMWebSocketChainsThroughEgressProxy(t *testing.T) {
	serverDone := make(chan error, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			serverDone <- fmt.Errorf("upstream response writer cannot hijack")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		key := r.Header.Get("Sec-Websocket-Key")
		_, _ = io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: "+websocketAccept(key)+"\r\n\r\n")

		text, err := readWebSocketTextFrame(rw.Reader)
		if err != nil {
			serverDone <- err
			return
		}
		if text != "ping" {
			serverDone <- fmt.Errorf("upstream frame = %q, want ping", text)
			return
		}
		serverDone <- writeWebSocketTextFrame(conn, "pong", false)
	}))
	defer upstream.Close()

	upstreamTarget := strings.TrimPrefix(upstream.URL, "https://")
	upstreamHost, _, _ := net.SplitHostPort(upstreamTarget)

	egressURL, rec := startConnectProxy(t, false)

	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		upstreamHost: {result: &brokercore.InjectResult{}},
	}}

	proxyURL, clientRoots, p := setupProxy(t, sr, cp)
	trustUpstream(p, upstream)
	p.upstream.Proxy = http.ProxyURL(egressURL)

	conn := openMITMTunnel(t, proxyURL, clientRoots, upstreamTarget, "av_sess_ok")
	defer func() { _ = conn.Close() }()

	tlsConn := tls.Client(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    clientRoots,
		ServerName: "127.0.0.1",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake through MITM: %v", err)
	}

	if _, err := io.WriteString(tlsConn,
		"GET / HTTP/1.1\r\n"+
			"Host: "+upstreamTarget+"\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	respBuf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for !strings.Contains(string(respBuf), "\r\n\r\n") {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			t.Fatalf("read upgrade response: %v (got %q)", err, respBuf)
		}
		respBuf = append(respBuf, tmp[:n]...)
	}
	if !strings.Contains(string(respBuf), "101 Switching Protocols") {
		t.Fatalf("upgrade response = %q, want 101", respBuf)
	}

	if _, err := tlsConn.Write(maskedTextFrame(t, "ping")); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}
	if got := readFrameText(t, tlsConn); got != "pong" {
		t.Fatalf("ws reply = %q, want pong", got)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("upstream handler: %v", err)
	}

	targets := rec.recorded()
	if len(targets) != 1 || targets[0] != upstreamTarget {
		t.Fatalf("egress proxy saw CONNECT targets %v, want exactly [%s]", targets, upstreamTarget)
	}
}
