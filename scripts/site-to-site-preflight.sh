#!/usr/bin/env bash
# Read-only PQTunnel host preflight. Never applies network or service changes.
set -uo pipefail

ROLE=both
ENDPOINT=
usage() {
  cat <<'USAGE'
PQTunnel VPS preflight (READ-ONLY; no network or service changes)
Usage: bash scripts/site-to-site-preflight.sh [--role dialer|gateway|both] [--endpoint IP_OR_HOST]
Checks OS, tools, routes, forwarding, policy table conflicts, firewall presence,
PQTunnel files/service state and certificate expiry. Does not source config files,
print certificate/private-key contents, write reports, or apply changes.
--endpoint optionally checks the existing route to a literal IP or resolved hostname.
PQTUNNEL_PREFLIGHT_PKI_DIR optionally overrides the PKI directory (mainly for isolated fixture tests).
PQTUNNEL_PKI_BIN optionally selects the Go-native pqtunnel-pki verifier.
PQTUNNEL_PREFLIGHT_SERVER_NAME and PQTUNNEL_PREFLIGHT_PEER_NAME optionally pin certificate identities.
USAGE
}
while (($#)); do
  case "$1" in
    --role) [[ $# -ge 2 ]] || { echo "missing --role value" >&2; exit 2; }; ROLE=$2; shift 2 ;;
    --endpoint) [[ $# -ge 2 ]] || { echo "missing --endpoint value" >&2; exit 2; }; ENDPOINT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$ROLE" in dialer|gateway|both) ;; *) echo "role must be dialer, gateway or both" >&2; exit 2 ;; esac

PKI_DIR="${PQTUNNEL_PREFLIGHT_PKI_DIR:-/etc/pqtunnel/pki}"
if [[ "$PKI_DIR" != /* ]]; then
  echo "PQTUNNEL_PREFLIGHT_PKI_DIR must be an absolute path" >&2
  exit 2
fi

PASS=0; WARN=0; FAIL=0
report() {
  level=$1; shift
  printf '[%s] %s\n' "$level" "$*"
  case "$level" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac
}
have() { command -v "$1" >/dev/null 2>&1; }

PKI_BIN="${PQTUNNEL_PKI_BIN:-}"
if [[ -z "$PKI_BIN" ]]; then
  if have pqtunnel-pki; then
    PKI_BIN="$(command -v pqtunnel-pki)"
  elif [[ -x /usr/local/bin/pqtunnel-pki ]]; then
    PKI_BIN=/usr/local/bin/pqtunnel-pki
  elif [[ -x /usr/local/sbin/pqtunnel-pki ]]; then
    PKI_BIN=/usr/local/sbin/pqtunnel-pki
  fi
fi
PKI_AVAILABLE=0
if [[ -n "$PKI_BIN" && -f "$PKI_BIN" && -x "$PKI_BIN" ]]; then
  PKI_AVAILABLE=1
  report PASS 'Go-native pqtunnel-pki verifier is available.'
else
  report WARN 'Go-native pqtunnel-pki verifier is unavailable; configured endpoint certificates cannot be validated.'
fi

printf '%s\n' 'PQTunnel host preflight — READ-ONLY'
printf 'time_utc=%s role=%s\n' "$(date -u +%FT%TZ 2>/dev/null || printf unknown)" "$ROLE"
printf 'host=%s uid=%s\n' "$(hostname 2>/dev/null || printf unknown)" "$(id -u 2>/dev/null || printf unknown)"
printf '%s\n' 'Privacy: config values, IP addresses, certificate contents, and private keys are not printed.'

if [[ -r /etc/os-release ]]; then
  OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
  OS_VERSION=$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
  printf 'os=%s version=%s\n' "$OS_ID" "$OS_VERSION"
  if [[ "$OS_ID" == ubuntu && ( "$OS_VERSION" == 24.04 || "$OS_VERSION" == 26.04 ) ]]; then
    report PASS "Ubuntu $OS_VERSION matches the project's CI targets."
  elif [[ "$OS_ID" == ubuntu ]]; then
    report WARN "Ubuntu $OS_VERSION is outside the currently tested 24.04/26.04 matrix."
  else
    report WARN 'OS is not Ubuntu; deployment helpers target Ubuntu/Linux with systemd.'
  fi
else report WARN '/etc/os-release is not readable; OS could not be identified.'; fi

if [[ $(id -u 2>/dev/null || echo 1) -eq 0 ]]; then report PASS 'Running as root; read-only metadata checks can be more complete.'; else report WARN 'Not root; firewall/service checks may be incomplete. This script still changes nothing.'; fi
for cmd in ip nft sysctl systemctl stat awk grep; do
  if have "$cmd"; then report PASS "command available: $cmd"; else report WARN "command unavailable: $cmd"; fi
done

if have ip; then
  DEFAULT4=$(ip -4 route show default 2>/dev/null | awk 'END{print NR+0}')
  DEFAULT6=$(ip -6 route show default 2>/dev/null | awk 'END{print NR+0}')
  WAN_NAMES=$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' | sort -u | paste -sd, -)
  printf 'default_route_count_v4=%s default_route_count_v6=%s default_route_interfaces=%s\n' "$DEFAULT4" "$DEFAULT6" "${WAN_NAMES:-none}"
  if [[ "$DEFAULT4" -gt 0 ]]; then report PASS 'At least one IPv4 default route exists.'; else report WARN 'No IPv4 default route found.'; fi
  if ip link show dev pqtun0 >/dev/null 2>&1; then report WARN 'pqtun0 already exists; do not assume PQTunnel owns it.'; else report PASS 'pqtun0 is not currently present.'; fi

  # A different TUN/TAP device can be owned by another active VPN/tunnel.
  # Record its presence without assuming the name or ownership of any device.
  if TUNTAP_OUTPUT=$(ip tuntap show 2>/dev/null); then
    TUNTAP_NAMES=$(printf '%s\n' "$TUNTAP_OUTPUT" | awk -F: '
      NF > 1 {
        name=$1
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
        if (name != "" && name != "pqtun0") print name
      }' | sort -u | paste -sd, -)
    if [[ -n "$TUNTAP_NAMES" ]]; then
      TUNTAP_COUNT=$(printf '%s\n' "$TUNTAP_NAMES" | awk -F, '{print NF}')
      report WARN "Other pre-existing TUN/TAP interface(s) detected (count=$TUNTAP_COUNT): $TUNTAP_NAMES; review ownership before any network apply."
    fi
  else
    report WARN 'Could not query existing TUN/TAP interfaces; interface ownership review is incomplete.'
  fi

  if ip -4 rule show 2>/dev/null | grep -Eq '^(10518|10519):'; then report WARN 'Policy-routing priority 10518 or 10519 is occupied.'; else report PASS 'Policy-routing priorities 10518/10519 appear free.'; fi
  for table in 518 519; do
    R4=$(ip -4 route show table "$table" 2>/dev/null | awk 'END{print NR+0}')
    R6=$(ip -6 route show table "$table" 2>/dev/null | awk 'END{print NR+0}')
    if [[ "$R4" == 0 && "$R6" == 0 ]]; then report PASS "Routing table $table is empty."; else report WARN "Routing table $table has entries (v4=$R4 v6=$R6)."; fi
  done
else report FAIL 'iproute2 command "ip" is required for meaningful network preflight.'; fi

read_sysctl() {
  key=$1; label=$2
  if have sysctl && value=$(sysctl -n "$key" 2>/dev/null); then
    printf '%s=%s\n' "$label" "$value"
    case "$label:$value" in
      ipv4_forwarding:1|ipv6_forwarding:1) report WARN "$label is already enabled; helper apply may refuse this host because it could already be routing traffic." ;;
      ipv4_rp_filter_all:0) report PASS "$label=0 (disabled at the all setting; per-interface values may still enable filtering)." ;;
      ipv4_rp_filter_all:1) report WARN "$label=1 (strict reverse-path filtering at the all setting; effective per-interface mode is max(all, interface))." ;;
      ipv4_rp_filter_all:2) report WARN "$label=2 (loose reverse-path filtering at the all setting; effective per-interface mode is max(all, interface))." ;;
      ipv4_rp_filter_default:0) report PASS "$label=0 (default for newly created interfaces; existing interfaces may differ)." ;;
      ipv4_rp_filter_default:1) report WARN "$label=1 (strict default for newly created interfaces; inspect effective current interface modes)." ;;
      ipv4_rp_filter_default:2) report WARN "$label=2 (loose default for newly created interfaces; inspect effective current interface modes)." ;;
      *) report PASS "$label is readable (value=$value)." ;;
    esac
  else report WARN "$label could not be read."; fi
}
read_sysctl net.ipv4.ip_forward ipv4_forwarding
read_sysctl net.ipv6.conf.all.forwarding ipv6_forwarding
read_sysctl net.ipv4.conf.all.rp_filter ipv4_rp_filter_all
read_sysctl net.ipv4.conf.default.rp_filter ipv4_rp_filter_default

# Linux computes the effective rp_filter mode as max(conf/all, conf/<interface>).
# conf/default is a template for newly created interfaces, not the current
# effective value of every existing interface.
read_rp_filter_interfaces() {
  have sysctl || return 0
  local all_value path iface iface_value effective mode strict_ifaces='' loose_ifaces=''

  if ! all_value=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null) || [[ ! "$all_value" =~ ^[012]$ ]]; then
    report WARN 'Could not determine conf/all rp_filter; effective per-interface modes are unknown.'
    return 0
  fi

  for path in /proc/sys/net/ipv4/conf/*/rp_filter; do
    [[ -r "$path" ]] || continue
    iface="${path%/rp_filter}"
    iface="${iface##*/}"
    case "$iface" in all|default) continue ;; esac

    if ! iface_value=$(sysctl -n "net.ipv4.conf.${iface}.rp_filter" 2>/dev/null) || [[ ! "$iface_value" =~ ^[012]$ ]]; then
      report WARN "rp_filter for interface $iface could not be read or interpreted."
      continue
    fi

    effective=$all_value
    if (( iface_value > effective )); then effective=$iface_value; fi
    case "$effective" in
      0) mode=disabled ;;
      1) mode=strict; strict_ifaces+=" $iface" ;;
      2) mode=loose; loose_ifaces+=" $iface" ;;
    esac
    printf 'rp_filter_interface=%s configured=%s effective=%s mode=%s\n' "$iface" "$iface_value" "$effective" "$mode"
  done

  if [[ -n "$strict_ifaces" ]]; then
    report WARN "Effective strict reverse-path filtering detected on interface(s):${strict_ifaces}; asymmetric or policy-routed traffic may be affected."
  fi
  if [[ -n "$loose_ifaces" ]]; then
    report WARN "Effective loose reverse-path filtering detected on interface(s):${loose_ifaces}."
  fi
}
read_rp_filter_interfaces

NOTRACK_FOUND=0
MARK_RULE_FOUND=0
NFT_RULESET=

if have nft; then
  if NFT_TABLES=$(nft list tables 2>/dev/null); then
    if [[ -n "$NFT_TABLES" ]]; then
      NFT_COUNT=$(printf '%s\n' "$NFT_TABLES" | grep -c '^table ' || true)
      report WARN "Existing nftables tables detected (count=$NFT_COUNT); review before any apply."
      if printf '%s\n' "$NFT_TABLES" | grep -Eq '^table inet (pqtunnel_selective|pqtunnel_gateway)$'; then report WARN 'A PQTunnel-named nftables table already exists.'; fi
    else report PASS 'nftables query succeeded and reported no tables.'; fi
  else report WARN 'nftables query failed; state is unknown (possibly permissions or missing kernel support).'; fi

  if NFT_RULESET=$(nft list ruleset 2>/dev/null); then
    if grep -Eiq '(^|[[:space:]])notrack([[:space:]]|$)' <<< "$NFT_RULESET"; then NOTRACK_FOUND=1; fi
    if grep -Eiq '(meta[[:space:]]+mark[[:space:]]+set|ct[[:space:]]+mark[[:space:]]+set)' <<< "$NFT_RULESET"; then MARK_RULE_FOUND=1; fi
  else
    report WARN 'nftables ruleset could not be read; NOTRACK and native packet-mark checks may be incomplete.'
  fi
else report WARN 'nft unavailable; nftables state was not checked.'; fi

if have ufw; then
  if UFW_OUTPUT=$(ufw status 2>/dev/null); then
    UFW_STATUS=$(printf '%s\n' "$UFW_OUTPUT" | awk 'NR==1{print $2}')
    if [[ "$UFW_STATUS" == active ]]; then report WARN 'UFW is active; current network helper deliberately refuses this host.'; elif [[ "$UFW_STATUS" == inactive ]]; then report PASS 'UFW reports inactive.'; else report WARN 'UFW status output was not understood; state is unknown.'; fi
  else report WARN 'UFW status query failed; firewall state is unknown.'; fi
else report WARN 'ufw unavailable; UFW status could not be checked.'; fi
if have iptables-save; then
  if IPTABLES_OUTPUT=$(iptables-save 2>/dev/null); then
    if grep -qE '^-A[[:space:]]' <<< "$IPTABLES_OUTPUT"; then report WARN 'Existing iptables rules detected; review before any apply.'; else report PASS 'iptables-save query succeeded and reported no -A rules.'; fi
    if grep -Eiq -- '(-j[[:space:]]+NOTRACK|--notrack)' <<< "$IPTABLES_OUTPUT"; then NOTRACK_FOUND=1; fi
    if grep -Eiq -- '(-j[[:space:]]+(MARK|CONNMARK)|--set-mark|--set-xmark|--restore-mark|--save-mark)' <<< "$IPTABLES_OUTPUT"; then MARK_RULE_FOUND=1; fi
  else report WARN 'iptables-save query failed; legacy firewall state is unknown.'; fi
else report WARN 'iptables-save unavailable; legacy firewall rules were not checked.'; fi

if have ip6tables-save; then
  if IPT6TABLES_OUTPUT=$(ip6tables-save 2>/dev/null); then
    if grep -Eiq -- '(-j[[:space:]]+NOTRACK|--notrack)' <<< "$IPT6TABLES_OUTPUT"; then NOTRACK_FOUND=1; fi
    if grep -Eiq -- '(-j[[:space:]]+(MARK|CONNMARK)|--set-mark|--set-xmark|--restore-mark|--save-mark)' <<< "$IPT6TABLES_OUTPUT"; then MARK_RULE_FOUND=1; fi
  else report WARN 'ip6tables-save query failed; legacy IPv6 firewall rule inspection may be incomplete.'; fi
fi

if (( NOTRACK_FOUND )); then
  report WARN 'Existing raw-table NOTRACK rules detected; matching flows bypass conntrack and may break PQTunnel SNAT/DNAT. Review destination and source-port overlap before any deployment.'
fi
if (( MARK_RULE_FOUND )); then
  report WARN 'Existing packet-marking rules detected; compare mark values/masks and policy-routing priorities before any deployment.'
fi

check_file() {
  path=$1; label=$2; private=0
  if [[ $# -ge 3 ]]; then private=$3; fi
  if [[ ! -e "$path" ]]; then report WARN "$label not found: $path"; return; fi
  if [[ ! -f "$path" ]]; then report WARN "$label is not a regular file: $path"; return; fi
  if have stat; then
    owner=$(stat -c '%u' "$path" 2>/dev/null || printf '?')
    mode=$(stat -c '%a' "$path" 2>/dev/null || printf '?')
    printf 'file=%s exists=yes owner_uid=%s mode=%s\n' "$path" "$owner" "$mode"
    if [[ "$private" == 1 && "$mode" =~ ^[0-7]+$ ]]; then
      perm=$((8#$mode))
      if (( (perm & 0077) == 0 )); then report PASS "$label permissions restrict access to owner."; else report WARN "$label permissions are broader than 0600."; fi
    fi
    if [[ "$owner" != 0 ]]; then report WARN "$label is not owned by root."; fi
  fi
}


verify_endpoint_with_ca() {
  local purpose="$1" cert="$2" key="$3" ca="$4"
  [[ "$PKI_AVAILABLE" == 1 ]] || return 127
  local -a args=(verify --purpose "$purpose" --cert "$cert" --key "$key" --ca "$ca")
  if [[ "$purpose" == server && -n "${PQTUNNEL_PREFLIGHT_SERVER_NAME:-}" ]]; then
    args+=(--server-name "$PQTUNNEL_PREFLIGHT_SERVER_NAME")
  elif [[ "$purpose" == client && -n "${PQTUNNEL_PREFLIGHT_PEER_NAME:-}" ]]; then
    args+=(--common-name "$PQTUNNEL_PREFLIGHT_PEER_NAME")
  fi
  "$PKI_BIN" "${args[@]}" >/dev/null 2>&1
}

check_certificate_bundle() {
  local cert="$1" key="$2" ca="$3" purpose="$4" label="$5"
  if [[ ! -s "$cert" && ! -s "$key" && ! -s "$ca" ]]; then
    return 0
  fi
  if [[ ! -s "$cert" || ! -s "$key" || ! -s "$ca" ]]; then
    report FAIL "$label certificate bundle is incomplete (certificate, private key and CA are all required)."
    return 0
  fi
  if [[ "$PKI_AVAILABLE" != 1 ]]; then
    report FAIL "$label certificate cannot be validated; install pqtunnel-pki or set PQTUNNEL_PKI_BIN."
    return 0
  fi
  if verify_endpoint_with_ca "$purpose" "$cert" "$key" "$ca"; then
    report PASS "$label ML-DSA certificate chain, EKU, identity, key match and permissions verified by pqtunnel-pki."
  else
    report FAIL "$label ML-DSA certificate/key/chain validation failed with Go pqtunnel-pki."
  fi
}

if [[ "$ROLE" == gateway || "$ROLE" == both ]]; then
  printf '%s\n' '--- gateway/listener checks ---'
  check_file /usr/local/sbin/pqtunneld 'pqtunneld binary'
  check_file /etc/default/pqtunneld 'pqtunneld environment file'
  check_file "$PKI_DIR/server.crt" 'server certificate'
  check_file "$PKI_DIR/server.key" 'server private key' 1
  check_file "$PKI_DIR/ca.crt" 'peer CA certificate'
  if have systemctl; then
    if systemctl is-active --quiet pqtunneld 2>/dev/null; then report WARN 'pqtunneld service is active.'; else report PASS 'pqtunneld service is not active.'; fi
    if systemctl is-enabled --quiet pqtunneld 2>/dev/null; then report WARN 'pqtunneld is enabled at boot.'; else report PASS 'pqtunneld is not enabled at boot.'; fi
  fi
  check_certificate_bundle "$PKI_DIR/server.crt" "$PKI_DIR/server.key" "$PKI_DIR/ca.crt" server 'Server'
fi

if [[ "$ROLE" == dialer || "$ROLE" == both ]]; then
  printf '%s\n' '--- dialer/client checks ---'
  check_file /usr/local/bin/pqtunnel-client 'pqtunnel-client binary'
  check_file /etc/pqtunnel/site-to-site.env 'selective network config'
  check_file "$PKI_DIR/client.crt" 'client/peer certificate'
  check_file "$PKI_DIR/client.key" 'client/peer private key' 1
  check_file "$PKI_DIR/ca.crt" 'server CA certificate'
  if have pgrep; then
    CLIENT_COUNT=$(pgrep -x pqtunnel-client 2>/dev/null | awk 'END{print NR+0}')
    printf 'pqtunnel_client_process_count=%s\n' "$CLIENT_COUNT"
    if [[ "$CLIENT_COUNT" -gt 0 ]]; then report WARN 'pqtunnel-client process is running.'; else report PASS 'No pqtunnel-client process is running.'; fi
  fi
  if have systemctl; then
    if systemctl is-active --quiet pqtunnel-client 2>/dev/null; then report WARN 'pqtunnel-client systemd unit is active.'; else report PASS 'pqtunnel-client systemd unit is not active.'; fi
  fi
  CLIENT_CA="$PKI_DIR/ca.crt"
  if [[ -s "$PKI_DIR/dialer-ca.crt" && -s "$PKI_DIR/client.crt" && -s "$PKI_DIR/client.key" && "$PKI_AVAILABLE" == 1 ]]; then
    if verify_endpoint_with_ca client "$PKI_DIR/client.crt" "$PKI_DIR/client.key" "$PKI_DIR/dialer-ca.crt"; then
      CLIENT_CA="$PKI_DIR/dialer-ca.crt"
    elif verify_endpoint_with_ca client "$PKI_DIR/client.crt" "$PKI_DIR/client.key" "$PKI_DIR/ca.crt"; then
      report WARN 'dialer-ca.crt does not verify the client certificate; ca.crt matches, so the compatibility fallback CA is being used.'
    else
      report FAIL 'Client/peer certificate does not verify against dialer-ca.crt or ca.crt.'
      CLIENT_CA="$PKI_DIR/dialer-ca.crt"
    fi
  elif [[ -s "$PKI_DIR/dialer-ca.crt" && "$PKI_AVAILABLE" != 1 ]]; then
    CLIENT_CA="$PKI_DIR/dialer-ca.crt"
  fi
  printf 'client_certificate_ca=%s\n' "${CLIENT_CA##*/}"
  if [[ "$CLIENT_CA" != "$PKI_DIR/ca.crt" ]]; then
    check_file "$CLIENT_CA" 'client/peer CA certificate'
  fi
  check_certificate_bundle "$PKI_DIR/client.crt" "$PKI_DIR/client.key" "$CLIENT_CA" client 'Client/peer'
fi

if [[ -n "$ENDPOINT" ]]; then
  printf '%s\n' '--- optional endpoint route check ---'
  candidate=
  if [[ "$ENDPOINT" =~ ^[0-9.]+$ || "$ENDPOINT" =~ ^[0-9a-fA-F:]+$ ]]; then
    candidate=$ENDPOINT
  elif have getent; then
    candidate=$(getent ahosts "$ENDPOINT" 2>/dev/null | awk 'NR==1{print $1}')
  fi
  if [[ -z "$candidate" ]]; then report WARN 'Endpoint did not resolve to an IP; route check skipped.'; elif ip route get "$candidate" >/dev/null 2>&1 || ip -6 route get "$candidate" >/dev/null 2>&1; then report PASS 'An existing route to an endpoint address is present.'; else report WARN 'No route could be confirmed to the endpoint.'; fi
fi

printf '\nSUMMARY pass=%s warn=%s fail=%s\n' "$PASS" "$WARN" "$FAIL"
printf '%s\n' 'READ-ONLY GUARANTEE: no files were created/deleted; no routes, sysctls, firewall state, or services were changed.'
printf '%s\n' 'Warnings are not permission to apply the network helper. Review all findings and retain console/out-of-band recovery.'
exit $(( FAIL > 0 ? 1 : 0 ))
