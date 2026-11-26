#!/usr/bin/env bash
# Checks that this fork differs from its pinned upstream release only in
# FabAI's gateway client patches and their tests. Upstream's own files,
# tests included, must be unchanged, so upstream's test suite runs against
# the patched client with no FabAI option set.
#
#   scripts/check-fabai-diff.sh             # compare HEAD with the pin
#   scripts/check-fabai-diff.sh --upstream  # also check the pin against the upstream tag
#
# The pinned commit must be in this checkout's history (fetch-depth: 0).
set -euo pipefail

readonly UPSTREAM_REPO="https://github.com/tinfoilsh/tinfoil-go"
readonly UPSTREAM_TAG="v0.17.0-rc.12"
readonly UPSTREAM_COMMIT="05ca0ef060def7b9aa12f1a00ddae6cc6a236571"

# Every path the patches may add or change.
readonly ALLOWED=(
	.github/workflows/fabai-test.yml
	.github/workflows/fabai-release.yml
	gateway.go
	gateway_fabai.go
	gateway_fabai_test.go
	internal/enclave/enclave.go
	internal/enclave/sealcheck.go
	internal/enclave/sealcheck_test.go
	internal/gateway/catalog.go
	internal/gateway/fabai_test.go
	internal/gateway/gateway.go
	internal/transport/singleuse_test.go
	internal/transport/transport.go
	internal/transport/verification.go
	internal/verifyhook/verifyhook.go
	scripts/check-fabai-diff.sh
)

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${1:-}" == "--upstream" ]]; then
	# A lightweight tag lists the commit; an annotated one lists its tag
	# object, then the commit under ^{}.
	tagged="$(git ls-remote "$UPSTREAM_REPO" "refs/tags/$UPSTREAM_TAG" "refs/tags/$UPSTREAM_TAG^{}" | awk 'END { print $1 }')"
	if [[ "$tagged" != "$UPSTREAM_COMMIT" ]]; then
		printf '%s %s is %s, not the pinned %s\n' "$UPSTREAM_REPO" "$UPSTREAM_TAG" "${tagged:-missing}" "$UPSTREAM_COMMIT" >&2
		exit 1
	fi
elif [[ $# -gt 0 ]]; then
	printf 'usage: %s [--upstream]\n' "$0" >&2
	exit 2
fi

if ! git merge-base --is-ancestor "$UPSTREAM_COMMIT" HEAD; then
	printf 'the pinned %s (%s) is not in HEAD'"'"'s history: fetch the full history, or rebase onto it\n' "$UPSTREAM_TAG" "$UPSTREAM_COMMIT" >&2
	exit 1
fi

status=0
while IFS= read -r path; do
	allowed=false
	for candidate in "${ALLOWED[@]}"; do
		if [[ "$path" == "$candidate" ]]; then
			allowed=true
			break
		fi
	done
	if [[ "$allowed" == false ]]; then
		printf 'changed outside the FabAI patches: %s\n' "$path" >&2
		status=1
	fi
done < <(git diff --name-only --no-renames "$UPSTREAM_COMMIT" HEAD)

if [[ "$status" -eq 0 ]]; then
	printf 'only the FabAI patches differ from %s (%s)\n' "$UPSTREAM_TAG" "$UPSTREAM_COMMIT"
fi
exit "$status"
