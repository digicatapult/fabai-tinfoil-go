package tinfoil

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const (
	fabaiModel   = "fabai-chat"
	fabaiReplica = "protected.fabai.internal"
	fabaiPrompt  = "validate the canary"
)

// fabaiGateway is a TLS gateway, trusted only through its own client, that
// serves a catalog of one FabAI model and answers sealed requests as a
// replica holding identity would.
type fabaiGateway struct {
	server   *httptest.Server
	identity *ehbpidentity.Identity

	mu      sync.Mutex
	headers []http.Header
	bodies  []string
}

func newFabAIGateway(t *testing.T) *fabaiGateway {
	t.Helper()
	identity, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	g := &fabaiGateway{identity: identity}
	replica := identity.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		g.headers = append(g.headers, r.Header.Clone())
		g.bodies = append(g.bodies, string(body))
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	g.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/catalog" {
			io.WriteString(w, `{
				"`+fabaiModel+`": {"repo": "digicatapult/fabai-demo", "hosts": ["`+fabaiReplica+`"]},
				"tinfoil-chat": {"repo": "tinfoilsh/confidential-chat", "hosts": ["chat.tinfoil.sh"]}
			}`)
			return
		}
		replica.ServeHTTP(w, r)
	}))
	t.Cleanup(g.server.Close)
	return g
}

// options returns FabAI's gateway options for g, with check as the SealCheck.
func (g *fabaiGateway) options(check SealCheck) *GatewayOptions {
	return &GatewayOptions{
		URL:             g.server.URL + "/v1/",
		RepositoryOwner: "digicatapult",
		SealCheck:       check,
		Transport:       g.server.Client().Transport,
		OmitCachePrefix: true,
	}
}

func (g *fabaiGateway) send(t *testing.T, client *GatewayHTTPClient) (*http.Response, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"model": fabaiModel, "messages": []map[string]string{{"role": "user", "content": fabaiPrompt}}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, client.BaseURL()+"chat/completions", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	return client.Do(req)
}

func TestFabAIGatewayChecksBeforeEverySend(t *testing.T) {
	g := newFabAIGateway(t)
	var checks atomic.Int32
	relay := strings.TrimPrefix(g.server.URL, "https://")
	client, err := NewGatewayHTTPClient(t.Context(), g.options(func(_ context.Context, gotRelay, host string) ([]byte, error) {
		checks.Add(1)
		assert.Equal(t, relay, gotRelay)
		assert.Equal(t, fabaiReplica, host)
		return g.identity.MarshalPublicKey(), nil
	}))
	require.NoError(t, err, "the catalog is fetched over the scoped transport")

	models, err := client.Models(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{fabaiModel}, models)

	const sequential, concurrent = 3, 8
	for range sequential {
		resp, err := g.send(t, client)
		require.NoError(t, err)
		out, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		require.JSONEq(t, `{"ok":true}`, string(out), "the response is opened with the checked key")
	}
	var wg sync.WaitGroup
	for range concurrent {
		wg.Go(func() {
			resp, err := g.send(t, client)
			if assert.NoError(t, err) {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}
	wg.Wait()

	require.GreaterOrEqual(t, int(checks.Load()), sequential+concurrent, "every send has a check of its own")
	g.mu.Lock()
	defer g.mu.Unlock()
	require.Len(t, g.bodies, sequential+concurrent)
	for i, h := range g.headers {
		require.Empty(t, h.Get("X-Tinfoil-Cache-Prefix"), "nothing derived from the prompt reaches the gateway")
		require.Equal(t, fabaiReplica, h.Get("X-Tinfoil-Seal"))
		require.Contains(t, g.bodies[i], fabaiPrompt, "the replica opens the sealed body")
	}

	reported := client.Current()
	require.Len(t, reported, 1)
	require.Empty(t, reported[0].Verification.CodeTag(), "a seal check's verification has no code facts")
}

func TestFabAIGatewaySendsNothingToARefusedReplica(t *testing.T) {
	g := newFabAIGateway(t)
	refused := errors.New("software tick failed")
	client, err := NewGatewayHTTPClient(t.Context(), g.options(func(context.Context, string, string) ([]byte, error) {
		return nil, refused
	}))
	require.NoError(t, err)
	_, err = g.send(t, client)
	require.ErrorIs(t, err, refused)
	require.ErrorIs(t, err, errs.ErrAttestation)
	g.mu.Lock()
	defer g.mu.Unlock()
	require.Empty(t, g.bodies, "no request reaches a replica the check refused")
}

func TestFabAIGatewayNeedsTheScopedTransport(t *testing.T) {
	g := newFabAIGateway(t)
	opts := g.options(func(context.Context, string, string) ([]byte, error) { return g.identity.MarshalPublicKey(), nil })
	opts.Transport = nil
	_, err := NewGatewayHTTPClient(t.Context(), opts)
	require.ErrorIs(t, err, errs.ErrNetwork, "http.DefaultTransport doesn't trust the gateway's CA")
}

func TestFabAIGatewayOptionsRefused(t *testing.T) {
	check := func(context.Context, string, string) ([]byte, error) { return nil, nil }
	verifier, err := verify.NewVerifier()
	require.NoError(t, err)
	for name, opts := range map[string]*GatewayOptions{
		"seal check with a verifier":     {SealCheck: check, Verifier: verifier},
		"seal check with a pin verifier": {SealCheck: check, ModelPins: map[string]ModelPin{fabaiModel: {Repo: "digicatapult/fabai-demo", Verifier: verifier}}},
		"seal check with a check":        {SealCheck: check, VerificationCheck: func(*verify.Verification) error { return nil }},
		"owner with a slash":             {RepositoryOwner: "digicatapult/"},
		"owner with a path":              {RepositoryOwner: "digicatapult/fabai-demo"},
		"owner with a leading hyphen":    {RepositoryOwner: "-digicatapult"},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Catalog = func() Catalog { return Catalog{} }
			_, err := NewGatewayHTTPClient(t.Context(), opts)
			require.ErrorIs(t, err, errs.ErrConfiguration)
		})
	}
}
