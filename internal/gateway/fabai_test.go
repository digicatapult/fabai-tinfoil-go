package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

func TestRepositoryOwnerReplacesTinfoilsh(t *testing.T) {
	catalog := Catalog{
		"fabai-chat":   {Repo: "digicatapult/fabai-demo", Hosts: []string{"protected.fabai.internal"}},
		"tinfoil-chat": {Repo: "tinfoilsh/confidential-chat", Hosts: []string{"chat.tinfoil.sh"}},
	}
	fabai, err := NewTransport(Config{Catalog: func() Catalog { return catalog }, RepositoryOwner: "digicatapult/"})
	require.NoError(t, err)
	models, err := fabai.Models(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"fabai-chat"}, models, "only the owner's repositories are served")

	upstream, err := NewTransport(Config{Catalog: func() Catalog { return catalog }})
	require.NoError(t, err)
	models, err = upstream.Models(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"tinfoil-chat"}, models, "unset, the owner is tinfoilsh/")
}

func TestRepositoryOwnerAppliesToModelPins(t *testing.T) {
	_, err := NewTransport(Config{RepositoryOwner: "digicatapult/", ModelPins: map[string]ModelPin{"fabai-chat": {Repo: "digicatapult/fabai-demo"}}})
	require.NoError(t, err)

	_, err = NewTransport(Config{RepositoryOwner: "digicatapult/", ModelPins: map[string]ModelPin{"chat": {Repo: "tinfoilsh/confidential-chat"}}})
	require.ErrorIs(t, err, errs.ErrConfiguration)
	require.ErrorContains(t, err, "must belong to digicatapult/")
}

func TestRepositoryOwnerFiltersTheFetchedCatalog(t *testing.T) {
	catalog, err := readCatalogFor(strings.NewReader(`{
		"fabai-chat": {"repo": "digicatapult/fabai-demo", "hosts": ["protected.fabai.internal"]},
		"tagged": {"repo": "digicatapult/fabai-demo@v1", "hosts": ["protected.fabai.internal"]},
		"tinfoil-chat": {"repo": "tinfoilsh/confidential-chat", "hosts": ["chat.tinfoil.sh"]}
	}`), "digicatapult/")
	require.NoError(t, err)
	require.Equal(t, Catalog{"fabai-chat": {Repo: "digicatapult/fabai-demo", Hosts: []string{"protected.fabai.internal"}}}, catalog)
}

// sentCachePrefix sends a chat request, with the cache-prefix header set by
// the caller when callerPrefix isn't empty, and returns the header the
// replica received.
func sentCachePrefix(t *testing.T, omit bool, callerPrefix string) string {
	t.Helper()
	var got string
	seal := sealTestTransport(func(string) (http.RoundTripper, error) {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			got = req.Header.Get(cachePrefixHeader)
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	seal.secret = "client-secret"
	seal.omitCachePrefix = omit
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions",
		strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"the canary sings"}]}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if callerPrefix != "" {
		req.Header.Set(cachePrefixHeader, callerPrefix)
	}
	resp, err := seal.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	return got
}

func TestOmitCachePrefix(t *testing.T) {
	require.NotEmpty(t, sentCachePrefix(t, false, ""), "unset, upstream's prefix is sent")
	require.Empty(t, sentCachePrefix(t, true, ""))
	require.Empty(t, sentCachePrefix(t, true, "set-by-caller"), "nothing the caller sets gets through either")
}
