package transport

import (
	"context"
	"crypto/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const keyHeader = "X-Test-Key"

// newSingleUseTransport returns a Transport for an enclave whose SealCheck
// returns a new random key on each call, which it counts, and whose requests
// answer with the key they were sent under.
func newSingleUseTransport(t *testing.T, checks *atomic.Int32) *Transport {
	t.Helper()
	e, err := enclave.New(enclave.Config{Host: "protected.fabai.internal", SealCheck: func(context.Context, string, string) ([]byte, error) {
		checks.Add(1)
		key := make([]byte, 32)
		rand.Read(key)
		return key, nil
	}})
	require.NoError(t, err)
	return &Transport{enclave: e, mode: testMode(func(v *verify.Verification) (http.RoundTripper, error) {
		key, _ := v.HPKEPublicKey()
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody}
			resp.Header.Set(keyHeader, key)
			return resp, nil
		}), nil
	})}
}

// sendForKey sends a request through tr and returns the key it was sent
// under. It reports failures with assert, so it can run on any goroutine.
func sendForKey(t *testing.T, tr *Transport) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", http.NoBody)
	if !assert.NoError(t, err) {
		return ""
	}
	resp, err := tr.RoundTrip(req)
	if !assert.NoError(t, err) {
		return ""
	}
	return resp.Header.Get(keyHeader)
}

func TestSingleUseSendClaimsTheCheckBeforeIt(t *testing.T) {
	var checks atomic.Int32
	tr := newSingleUseTransport(t, &checks)

	// The gateway checks a replica before sending to it; the send then claims
	// that check rather than making another.
	verified, err := tr.EnsureVerified(context.Background())
	require.NoError(t, err)
	checked, _ := verified.HPKEPublicKey()
	require.Equal(t, checked, sendForKey(t, tr))
	require.EqualValues(t, 1, checks.Load())

	second := sendForKey(t, tr)
	require.NotEqual(t, checked, second, "a second send can't reuse the first's check")
	require.EqualValues(t, 2, checks.Load())
}

func TestSingleUseConcurrentSendsNeverShareACheck(t *testing.T) {
	const sends = 32
	var checks atomic.Int32
	tr := newSingleUseTransport(t, &checks)

	keys := make([]string, sends)
	var wg sync.WaitGroup
	for i := range sends {
		wg.Go(func() { keys[i] = sendForKey(t, tr) })
	}
	wg.Wait()

	seen := map[string]bool{}
	for _, key := range keys {
		require.NotEmpty(t, key)
		require.False(t, seen[key], "two sends were sealed under one check")
		seen[key] = true
	}
	require.GreaterOrEqual(t, int(checks.Load()), sends)
}

func TestReusableTransportStillSharesAVerification(t *testing.T) {
	var fetches atomic.Int32
	tr := newTestTransport(t, nil, func() (*verify.Verification, error) {
		fetches.Add(1)
		return verifytest.New(verifytest.Fields{FreshnessExpiresAt: time.Now().Add(time.Hour)}), nil
	}, testMode(func(*verify.Verification) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody}, nil
		}), nil
	}))
	sendForKey(t, tr)
	sendForKey(t, tr)
	require.EqualValues(t, 1, fetches.Load(), "without a SealCheck, upstream's reuse is unchanged")
}
