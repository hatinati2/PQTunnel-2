#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFLIGHT="$ROOT/scripts/site-to-site-preflight.sh"

[[ -f "$PREFLIGHT" ]] || { echo "missing preflight script" >&2; exit 1; }
bash -n "$PREFLIGHT"
bash -n "$ROOT/scripts/pqtunnel-bootstrap.sh"
BOOTSTRAP_HELP="$(bash "$ROOT/scripts/pqtunnel-bootstrap.sh" --help)"
grep -q 'install-server' <<< "$BOOTSTRAP_HELP"
grep -q 'install-client' <<< "$BOOTSTRAP_HELP"
grep -q 'curl -fsSL .* install-server .*--start --apply-network' <<< "$BOOTSTRAP_HELP"
grep -q 'curl -fsSL .* install-client .*--start' <<< "$BOOTSTRAP_HELP"
grep -q 'PQTUNNEL_REF' <<< "$BOOTSTRAP_HELP"
grep -q 'REPLACE_WITH_REVIEWED_40_CHAR_SHA' <<< "$BOOTSTRAP_HELP"
if PQTUNNEL_REF=main bash "$ROOT/scripts/pqtunnel-bootstrap.sh" install-server >/dev/null 2>&1; then
  echo "install-server unexpectedly accepted a mutable source ref" >&2
  exit 1
fi
if PQTUNNEL_REF=main bash "$ROOT/scripts/pqtunnel-bootstrap.sh" install-client >/dev/null 2>&1; then
  echo "install-client unexpectedly accepted a mutable source ref" >&2
  exit 1
fi
bash "$ROOT/scripts/pqtunnel-bootstrap.sh" check-config --kind gateway --app-env "$ROOT/scripts/pqtunneld.site-to-site.env.example" --network-env "$ROOT/scripts/site-to-site-gateway.env.example"
bash "$ROOT/scripts/pqtunnel-bootstrap.sh" check-config --kind dialer --app-env "$ROOT/scripts/pqtunnel-client.env.example" --network-env "$ROOT/scripts/site-to-site.env.example"

# A shell-expression payload must be rejected as data, never evaluated.
TMP_CONFIG_DIR="$(mktemp -d)"
FAKE_BIN_DIR=""
trap 'rm -rf "$TMP_CONFIG_DIR" /tmp/pqtunnel-config-pwned; [[ -z "$FAKE_BIN_DIR" ]] || rm -rf "$FAKE_BIN_DIR"' EXIT
cp "$ROOT/scripts/pqtunneld.site-to-site.env.example" "$TMP_CONFIG_DIR/gateway.env"
sed -i 's|^PQTUNNEL_PEER_NAME=.*|PQTUNNEL_PEER_NAME=$(touch /tmp/pqtunnel-config-pwned)|' "$TMP_CONFIG_DIR/gateway.env"
if bash "$ROOT/scripts/pqtunnel-bootstrap.sh" check-config --kind gateway --app-env "$TMP_CONFIG_DIR/gateway.env" --network-env "$ROOT/scripts/site-to-site-gateway.env.example" >/dev/null 2>&1; then
  echo "unsafe shell expression was unexpectedly accepted" >&2
  exit 1
fi
if [[ -e /tmp/pqtunnel-config-pwned ]]; then
  echo "configuration validator evaluated a shell expression" >&2
  exit 1
fi

HELP="$(bash "$PREFLIGHT" --help)"
grep -q 'READ-ONLY' <<< "$HELP"
grep -q 'check_certificate_bundle' "$PREFLIGHT"
grep -q 'pqtunnel-pki' "$PREFLIGHT"
if grep -Eq 'openssl (x509|verify|pkey)' "$PREFLIGHT"; then
  echo "preflight must not use OpenSSL to parse ML-DSA certificates" >&2
  exit 1
fi
grep -q 'PQTUNNEL_PREFLIGHT_PKI_DIR' <<< "$HELP"
grep -q 'dialer-ca.crt' "$PREFLIGHT"
grep -q 'nftables query failed' "$PREFLIGHT"
grep -q 'iptables-save query failed' "$PREFLIGHT"
if bash "$PREFLIGHT" --role invalid >/dev/null 2>&1; then
  echo "invalid role was unexpectedly accepted" >&2
  exit 1
fi
if bash "$PREFLIGHT" --unknown >/dev/null 2>&1; then
  echo "unknown option was unexpectedly accepted" >&2
  exit 1
fi

# Run against the disposable CI runner. The test checks a stable contract,
# not whether runner state matches any production VPS.
OUTPUT="$(bash "$PREFLIGHT" --role both)"
grep -q 'READ-ONLY GUARANTEE:' <<< "$OUTPUT"
BOOT_OUTPUT="$(bash "$ROOT/scripts/pqtunnel-bootstrap.sh" preflight --role both)"
grep -q 'READ-ONLY GUARANTEE:' <<< "$BOOT_OUTPUT"
grep -q '^SUMMARY pass=' <<< "$OUTPUT"
if grep -Eq '^[[:space:]]*(sysctl[[:space:]]+-w|nft[[:space:]]+-f|ip[[:space:]]+link[[:space:]]+(set|add|del)|systemctl[[:space:]]+(start|stop|restart|enable|disable)|iptables-restore[[:space:]]|iptables[[:space:]]+-)' "$PREFLIGHT"; then
  echo "Potential network-changing command detected in read-only preflight script" >&2
  exit 1
fi
printf '%s\n' "$OUTPUT"

# Simulate existing firewall rules without modifying runner networking.
# These wrappers return only read-only fixture data to the preflight.
FAKE_BIN_DIR="$(mktemp -d)"
REAL_IP="$(command -v ip)"
cat >"$FAKE_BIN_DIR/nft" <<'NFT_WRAPPER'
#!/usr/bin/env bash
set -eu
case "$*" in
  "list tables")
    printf '%s\n' 'table ip filter' 'table ip raw' 'table ip mangle'
    ;;
  "list ruleset")
    cat <<'RULESET'
table ip raw {
  chain OUTPUT { type filter hook output priority raw; policy accept;
    tcp sport 45420-45547 notrack
  }
}
table ip mangle {
  chain OUTPUT { type route hook output priority mangle; policy accept;
    meta mark set 20561
  }
}
RULESET
    ;;
  *) exit 2 ;;
esac
NFT_WRAPPER
cat >"$FAKE_BIN_DIR/iptables-save" <<'IPTABLES_WRAPPER'
#!/usr/bin/env bash
cat <<'RULES'
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -m tcp --sport 45420:45547 -j NOTRACK
COMMIT
*mangle
:OUTPUT ACCEPT [0:0]
-A OUTPUT -j MARK --set-mark 20561
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
RULES
IPTABLES_WRAPPER
cat >"$FAKE_BIN_DIR/ip6tables-save" <<'IP6TABLES_WRAPPER'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
IP6TABLES_WRAPPER
cat >"$FAKE_BIN_DIR/sysctl" <<'SYSCTL_WRAPPER'
#!/usr/bin/env bash
set -eu
case "$*" in
  "-n net.ipv4.ip_forward") printf '%s\n' "${FAKE_FORWARD4:-0}" ;;
  "-n net.ipv6.conf.all.forwarding") printf '%s\n' "${FAKE_FORWARD6:-0}" ;;
  "-n net.ipv4.conf.all.rp_filter") printf '%s\n' "${FAKE_RPFILTER_ALL:-2}" ;;
  "-n net.ipv4.conf.default.rp_filter") printf '%s\n' "${FAKE_RPFILTER_DEFAULT:-2}" ;;
  -n\ net.ipv4.conf.*.rp_filter) printf '%s\n' "${FAKE_RPFILTER_INTERFACE:-0}" ;;
  *) exit 1 ;;
esac
SYSCTL_WRAPPER
cat >"$FAKE_BIN_DIR/ip" <<'IP_WRAPPER'
#!/usr/bin/env bash
set -eu
case "$*" in
  "tuntap show") printf '%s\n' 'tun0: tun' ;;
  *) exec "$PQTUNNEL_REAL_IP" "$@" ;;
esac
IP_WRAPPER
chmod 0700 "$FAKE_BIN_DIR/nft" "$FAKE_BIN_DIR/iptables-save" "$FAKE_BIN_DIR/ip6tables-save" "$FAKE_BIN_DIR/sysctl" "$FAKE_BIN_DIR/ip"
DIAGNOSTIC_OUTPUT="$(PATH="$FAKE_BIN_DIR:$PATH" PQTUNNEL_REAL_IP="$REAL_IP" bash "$PREFLIGHT" --role both)"
grep -q 'Existing raw-table NOTRACK rules detected' <<< "$DIAGNOSTIC_OUTPUT"
grep -q 'Existing packet-marking rules detected' <<< "$DIAGNOSTIC_OUTPUT"
grep -q 'Other pre-existing TUN/TAP interface(s) detected (count=1): tun0' <<< "$DIAGNOSTIC_OUTPUT"
grep -q '^SUMMARY pass=' <<< "$DIAGNOSTIC_OUTPUT"
echo 'PASS: preflight reports simulated NOTRACK, packet-marking, and existing TUN/TAP hazards.'

# Verify Linux rp_filter semantics: 2 means loose, while 1 means strict.
# The effective mode is max(conf/all, conf/<interface>), not conf/default.
LOOSE_OUTPUT="$(PATH="$FAKE_BIN_DIR:$PATH" PQTUNNEL_REAL_IP="$REAL_IP" FAKE_RPFILTER_ALL=2 FAKE_RPFILTER_DEFAULT=2 FAKE_RPFILTER_INTERFACE=0 bash "$PREFLIGHT" --role both)"
grep -q 'ipv4_rp_filter_all=2 (loose reverse-path filtering' <<< "$LOOSE_OUTPUT"
grep -q 'rp_filter_interface=lo configured=0 effective=2 mode=loose' <<< "$LOOSE_OUTPUT"
if grep -q 'enabled/strict' <<< "$LOOSE_OUTPUT"; then
  echo 'rp_filter=2 was incorrectly described as strict' >&2
  exit 1
fi
STRICT_OUTPUT="$(PATH="$FAKE_BIN_DIR:$PATH" PQTUNNEL_REAL_IP="$REAL_IP" FAKE_RPFILTER_ALL=1 FAKE_RPFILTER_DEFAULT=0 FAKE_RPFILTER_INTERFACE=0 bash "$PREFLIGHT" --role both)"
grep -q 'ipv4_rp_filter_all=1 (strict reverse-path filtering' <<< "$STRICT_OUTPUT"
grep -q 'rp_filter_interface=lo configured=0 effective=1 mode=strict' <<< "$STRICT_OUTPUT"
echo 'PASS: preflight distinguishes strict and loose rp_filter modes and reports effective interface values.'

# Generate ML-DSA fixtures with the same Go-native PKI tool used by the runtime.
PKI_BIN="$TMP_CONFIG_DIR/pqtunnel-pki"
GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -o "$PKI_BIN" "$ROOT/cmd/pqtunnel-pki"

FIXTURE_PKI="$TMP_CONFIG_DIR/pki-dedicated"
mkdir -m 0700 "$FIXTURE_PKI" "$FIXTURE_PKI/server-ca" "$FIXTURE_PKI/dialer-ca-work"
"$PKI_BIN" init --server-name gateway.example.test --out "$FIXTURE_PKI/server-ca"
"$PKI_BIN" init --server-name dialer-ca.example.test --out "$FIXTURE_PKI/dialer-ca-work"
"$PKI_BIN" issue-client --ip 192.0.2.10 --out "$FIXTURE_PKI/dialer-ca-work"
cp "$FIXTURE_PKI/server-ca/ca.crt" "$FIXTURE_PKI/ca.crt"
cp "$FIXTURE_PKI/dialer-ca-work/ca.crt" "$FIXTURE_PKI/dialer-ca.crt"
cp "$FIXTURE_PKI/dialer-ca-work/client-192_0_2_10.crt" "$FIXTURE_PKI/client.crt"
cp "$FIXTURE_PKI/dialer-ca-work/client-192_0_2_10.key" "$FIXTURE_PKI/client.key"
chmod 0600 "$FIXTURE_PKI/client.key"
DEDICATED_CA_OUTPUT="$(PQTUNNEL_PKI_BIN="$PKI_BIN" PQTUNNEL_PREFLIGHT_PEER_NAME=192.0.2.10 PQTUNNEL_PREFLIGHT_PKI_DIR="$FIXTURE_PKI" bash "$PREFLIGHT" --role dialer)"
grep -F 'client_certificate_ca=dialer-ca.crt' <<< "$DEDICATED_CA_OUTPUT"
grep -q 'Client/peer ML-DSA certificate chain, EKU, identity, key match and permissions verified by pqtunnel-pki.' <<< "$DEDICATED_CA_OUTPUT"
if grep -q '^\[FAIL\]' <<< "$DEDICATED_CA_OUTPUT"; then
  echo 'Dedicated dialer CA ML-DSA fixture unexpectedly failed preflight:' >&2
  printf '%s\n' "$DEDICATED_CA_OUTPUT" >&2
  exit 1
fi
echo 'PASS: dialer preflight validates ML-DSA client certificates against a separate dialer-ca.crt.'

# A standard single-CA ML-DSA bundle must keep using ca.crt.
FIXTURE_SINGLE="$TMP_CONFIG_DIR/pki-single"
mkdir -m 0700 "$FIXTURE_SINGLE"
"$PKI_BIN" init --server-name gateway.example.test --out "$FIXTURE_SINGLE"
"$PKI_BIN" issue-client --ip 192.0.2.11 --out "$FIXTURE_SINGLE"
cp "$FIXTURE_SINGLE/client-192_0_2_11.crt" "$FIXTURE_SINGLE/client.crt"
cp "$FIXTURE_SINGLE/client-192_0_2_11.key" "$FIXTURE_SINGLE/client.key"
chmod 0600 "$FIXTURE_SINGLE/client.key"
SINGLE_CA_OUTPUT="$(PQTUNNEL_PKI_BIN="$PKI_BIN" PQTUNNEL_PREFLIGHT_PEER_NAME=192.0.2.11 PQTUNNEL_PREFLIGHT_PKI_DIR="$FIXTURE_SINGLE" bash "$PREFLIGHT" --role dialer)"
grep -F 'client_certificate_ca=ca.crt' <<< "$SINGLE_CA_OUTPUT"
grep -q 'Client/peer ML-DSA certificate chain, EKU, identity, key match and permissions verified by pqtunnel-pki.' <<< "$SINGLE_CA_OUTPUT"
if grep -q '^\[FAIL\]' <<< "$SINGLE_CA_OUTPUT"; then
  echo 'Single-CA ML-DSA fixture unexpectedly failed preflight:' >&2
  printf '%s\n' "$SINGLE_CA_OUTPUT" >&2
  exit 1
fi
echo 'PASS: dialer preflight validates ML-DSA certificates with a single CA.'

# Gateway validation must check the certificate SAN with the Go verifier.
GATEWAY_FIXTURE="$TMP_CONFIG_DIR/pki-gateway"
mkdir -m 0700 "$GATEWAY_FIXTURE"
"$PKI_BIN" init --server-name gateway.example.test --out "$GATEWAY_FIXTURE"
chmod 0600 "$GATEWAY_FIXTURE/server.key"
GATEWAY_OUTPUT="$(PQTUNNEL_PKI_BIN="$PKI_BIN" PQTUNNEL_PREFLIGHT_SERVER_NAME=gateway.example.test PQTUNNEL_PREFLIGHT_PKI_DIR="$GATEWAY_FIXTURE" bash "$PREFLIGHT" --role gateway)"
grep -q 'Server ML-DSA certificate chain, EKU, identity, key match and permissions verified by pqtunnel-pki.' <<< "$GATEWAY_OUTPUT"
if grep -q '^\[FAIL\]' <<< "$GATEWAY_OUTPUT"; then
  echo 'Gateway ML-DSA fixture unexpectedly failed preflight:' >&2
  printf '%s\n' "$GATEWAY_OUTPUT" >&2
  exit 1
fi
WRONG_NAME_OUTPUT="$(PQTUNNEL_PKI_BIN="$PKI_BIN" PQTUNNEL_PREFLIGHT_SERVER_NAME=wrong.example.test PQTUNNEL_PREFLIGHT_PKI_DIR="$GATEWAY_FIXTURE" bash "$PREFLIGHT" --role gateway || true)"
grep -q '^\[FAIL\] Server ML-DSA certificate/key/chain validation failed with Go pqtunnel-pki\.' <<< "$WRONG_NAME_OUTPUT"
echo 'PASS: gateway preflight verifies ML-DSA certificate SAN and rejects a wrong server name.'
echo 'PASS: read-only preflight entry points and non-mutating guard verified.'
