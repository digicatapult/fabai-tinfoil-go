package enclave

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

func sealCheckKey(b byte) []byte {
	key := make([]byte, hpkeKeySize)
	for i := range key {
		key[i] = b
	}
	return key
}

func TestSealCheckReplacesVerify(t *testing.T) {
	var gotRelay, gotHost string
	e, err := New(Config{Host: "protected.fabai.internal", Relay: "gateway.fabai.internal", SealCheck: func(_ context.Context, relay, host string) ([]byte, error) {
		gotRelay, gotHost = relay, host
		return sealCheckKey(7), nil
	}})
	require.NoError(t, err, "no pin or verifier is needed")
	require.True(t, e.SingleUse())
	require.Nil(t, e.Verifier(), "verify isn't used")

	before := time.Now()
	v, err := e.Verify()
	require.NoError(t, err)
	require.Equal(t, "gateway.fabai.internal", gotRelay)
	require.Equal(t, "protected.fabai.internal", gotHost)

	key, ok := v.HPKEPublicKey()
	require.True(t, ok)
	require.Equal(t, hex.EncodeToString(sealCheckKey(7)), key)
	_, ok = v.TLSPublicKeyFP()
	require.False(t, ok, "the seal check attests one key")
	require.Empty(t, v.CodeTag(), "verify appraised nothing")
	require.Empty(t, v.ConfigRepo())
	require.Equal(t, sealCheckVerifier, v.Metadata().Verifier.Name)
	require.WithinDuration(t, before.Add(sealCheckLifetime), v.FreshnessExpiresAt(), time.Second)
}

func TestSealCheckRefusalIsNotRetried(t *testing.T) {
	refused := errors.New("software tick failed")
	for name, check := range map[string]SealCheck{
		"refused":   func(context.Context, string, string) ([]byte, error) { return nil, refused },
		"short key": func(context.Context, string, string) ([]byte, error) { return sealCheckKey(1)[:31], nil },
		"no key":    func(context.Context, string, string) ([]byte, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			var calls int
			e, err := New(Config{Host: "modified.fabai.internal", SealCheck: func(ctx context.Context, relay, host string) ([]byte, error) {
				calls++
				return check(ctx, relay, host)
			}})
			require.NoError(t, err)
			_, err = e.Verify()
			require.ErrorIs(t, err, errs.ErrAttestation)
			require.ErrorContains(t, err, "modified.fabai.internal")
			require.Equal(t, 1, calls, "a refusal is a decision about the replica")
		})
	}
}

func TestSealCheckNeedsAHost(t *testing.T) {
	_, err := New(Config{SealCheck: func(context.Context, string, string) ([]byte, error) { return sealCheckKey(1), nil }})
	require.ErrorIs(t, err, errs.ErrConfiguration)
}

func TestWithoutSealCheckEnclaveIsReusable(t *testing.T) {
	require.False(t, NewForTest("enclave.example", nil).SingleUse())
}
