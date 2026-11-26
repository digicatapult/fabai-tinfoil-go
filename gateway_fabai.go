package tinfoil

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

// SealCheck fetches and checks a fresh attestation document from host,
// through the gateway at relay, and returns the X25519 HPKE public key that
// the one request about to be sent is sealed to. An error refuses the
// replica, and isn't retried. ctx is not the request's context: the check
// must bound its own duration.
type SealCheck = enclave.SealCheck

// githubOwner is a GitHub user or organization name.
var githubOwner = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)

var errSealCheckWithVerifier = errors.New("SealCheck replaces the verifier: leave Verifier, VerificationCheck and every ModelPin.Verifier unset")

// checkFabAIOptions checks the FabAI options in opts, and returns the
// repository owner as the gateway transport takes it: empty, or ending in a
// slash.
func checkFabAIOptions(opts *GatewayOptions) (string, error) {
	if opts.SealCheck != nil {
		if opts.Verifier != nil || opts.VerificationCheck != nil {
			return "", errs.Configuration(errSealCheckWithVerifier)
		}
		for _, pin := range opts.ModelPins {
			if pin.Verifier != nil {
				return "", errs.Configuration(errSealCheckWithVerifier)
			}
		}
	}
	if opts.RepositoryOwner == "" {
		return "", nil
	}
	if !githubOwner.MatchString(opts.RepositoryOwner) {
		return "", errs.Configuration(fmt.Errorf("repository owner %q isn't a GitHub user or organization name", opts.RepositoryOwner))
	}
	return opts.RepositoryOwner + "/", nil
}
