package enclave

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/verifyhook"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// SealCheck fetches and checks a fresh attestation document from host, through
// relay when it isn't empty, and returns the X25519 HPKE public key that the
// one request about to be sent is sealed to. An error refuses the replica,
// without a retry. The application supplies it, so that a check other than
// verify's appraises the replica, and this module never imports that check.
type SealCheck func(ctx context.Context, relay, host string) (hpkeKey []byte, err error)

const (
	// sealCheckLifetime bounds the gap between a seal check and the send that
	// claims its key. The verification is used for one send only (see
	// SingleUse), so this isn't a freshness window that later sends share.
	sealCheckLifetime = time.Minute
	sealCheckVerifier = "seal-check"
	hpkeKeySize       = 32
)

var errSealCheckKey = fmt.Errorf("seal check returned an HPKE key that isn't %d bytes", hpkeKeySize)

func newSealChecked(c Config) (*Enclave, error) {
	if c.Host == "" {
		return nil, errs.Configuration(errors.New("enclave host is required"))
	}
	return &Enclave{host: c.Host, relay: c.Relay, pin: c.Pin, check: c.VerificationCheck, sealCheck: c.SealCheck}, nil
}

// SingleUse reports whether each verification may protect only one request:
// true when a SealCheck verifies the enclave, since the check releases its
// key for a single send.
func (e *Enclave) SingleUse() bool {
	return e.sealCheck != nil
}

// runSealCheck runs the SealCheck and reports its key as a verification. The
// verification carries only that key, under the hpke id, and an expiry: its
// code, config and measurement facts are empty, because the SealCheck, not
// verify, appraised them.
func (e *Enclave) runSealCheck() (*verify.Verification, error) {
	// As with fetchVerification, no single caller's context applies; the
	// SealCheck bounds its own fetch.
	key, err := e.sealCheck(context.Background(), e.relay, e.host)
	if err != nil {
		return nil, errs.Attestation(&rejectedError{host: e.host, err: fmt.Errorf("seal check: %w", err)})
	}
	if len(key) != hpkeKeySize {
		return nil, errs.Attestation(&rejectedError{host: e.host, err: errSealCheckKey})
	}
	now := time.Now()
	return verifyhook.NewVerification(verifyhook.Fields{
		CryptoMaterial: []document.CryptoMaterialItem{{
			ID:     document.CryptoMaterialIDHPKE,
			Format: document.KeyX25519HPKEV1Format,
			Data:   hex.EncodeToString(key),
		}},
		FreshnessExpiresAt: now.Add(sealCheckLifetime),
		VerifierName:       sealCheckVerifier,
		VerifiedAt:         now,
	}).(*verify.Verification), nil
}
