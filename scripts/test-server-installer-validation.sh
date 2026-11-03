#!/usr/bin/env bash
# Regression tests for Go-native ML-DSA endpoint PKI validation in the server installer.
# All fixtures live in a temporary directory; expected failures occur before installation.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/scripts/install-server.sh"
command -v sudo >/dev/null 2>&1 || { echo 'FAIL: sudo is required' >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo 'FAIL: Go 1.27+ is required' >&2; exit 2; }

TMP="$(mktemp -d -t pqtunnel-server-installer-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
SOURCE="$TMP/source"
PKI="$TMP/pki"
PKI_BIN="$TMP/pqtunnel-pki"
mkdir -p "$SOURCE/deploy/systemd" "$PKI"
printf '[Unit]\nDescription=Test fixture\n' > "$SOURCE/deploy/systemd/pqtunneld.service"
GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -o "$PKI_BIN" "$ROOT/cmd/pqtunnel-pki"
"$PKI_BIN" init --out "$PKI" --server-name gateway.example.test

run_expect_failure() {
  local label="$1" expected="$2" log="$TMP/run.log" rc
  if sudo env PQTUNNEL_PKI_BIN="$PKI_BIN" bash "$INSTALLER" --source "$SOURCE" --pki "$PKI" >"$log" 2>&1; then
    echo "FAIL: installer unexpectedly succeeded for $label" >&2
    cat "$log" >&2
    exit 1
  else
    rc=$?
  fi
  if ! grep -Fq "$expected" "$log"; then
    echo "FAIL: installer rejected $label for an unexpected reason (exit $rc)" >&2
    cat "$log" >&2
    exit 1
  fi
  echo "PASS: installer rejects $label before installation."
}

# The CA signing key must never be staged in the endpoint PKI directory.
run_expect_failure 'an endpoint PKI directory containing ca.key' 'Keep the CA private key offline'

rm -f "$PKI/ca.key"
"$PKI_BIN" issue-server --out "$PKI" --server-name other.example.test --prefix wrong
cp "$PKI/server.key" "$TMP/correct.key"
cp "$PKI/wrong-server.key" "$PKI/server.key"
run_expect_failure 'a certificate/private-key mismatch' 'load endpoint certificate/private-key pair'

cp "$TMP/correct.key" "$PKI/server.key"
cp "$PKI/server.crt" "$TMP/correct.crt"
printf 'not a certificate\n' > "$PKI/server.crt"
run_expect_failure 'a malformed server certificate' 'load endpoint certificate/private-key pair'

echo 'PASS: server installer Go-native ML-DSA PKI validation regression tests completed.'
