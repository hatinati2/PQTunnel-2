# Two-host Linux acceptance runbook

**Status:** planned acceptance procedure; no two-host run has been recorded yet.  
**Project status:** experimental. This is not approval for production deployment.

This runbook defines the evidence needed after CI for a candidate commit. Run it only on two disposable, independently addressable Linux lab VMs with console or out-of-band recovery on both. Do not use production VPSs, sensitive traffic, production credentials, or a live office/home network as the first test.

## 1. Lab topology and prerequisites

Use two separate hosts:

- **Gateway / Listener:** runs `pqtunneld`, owns the listener-side test prefixes, and accepts the Dialer connection.
- **Dialer / Client:** runs `pqtunnel-client`, initiates the connection, and owns the dialer-side test prefixes.

Both hosts need Ubuntu 24.04 or 26.04, systemd, TUN support, Go 1.27+ for source-based installation, and the networking prerequisites listed by the scripts. Keep the two lab LANs non-overlapping. Use static test addresses and DNS records that exist only in the lab.

Before beginning, record the VM image IDs, architecture, kernel, WAN interface name, test LAN prefixes, test target addresses, and the exact candidate commit SHA. Confirm console access and a clean VM snapshot on both hosts. The cloud/provider firewall is managed separately; PQTunnel does not edit it.

Do not continue if either host has pre-existing UFW/nftables/iptables rules, active forwarding, or policy-routing state that the helper reports as incompatible. A warning is not permission to bypass the guard.

## 2. Candidate source and artifacts

Choose a reviewed lowercase 40-character commit SHA only after CI and Security checks pass for that exact SHA:

```sh
git clone https://github.com/hatinati2/PQTunnel-2.git
cd PQTunnel-2
git checkout <CANDIDATE_SHA>
test "$(git rev-parse HEAD)" = "<CANDIDATE_SHA>"
test -z "$(git status --porcelain)"
go version
```

Use the same commit on both hosts. Go 1.27 or newer is required. Do not use `main` as an install ref; the bootstrap installer rejects mutable refs.

## 3. Create fresh test PKI

On a trusted lab administration workstation with the candidate checkout:

```sh
umask 077
bash scripts/prepare-site-to-site-pki.sh \
  --server-name gateway.lab.example \
  --client-ip 10.66.0.2 \
  --out "$HOME/pqtunnel-lab-pki"
```

Replace the example server name and client IP with values assigned only to the lab. The script creates:

- `gateway-pki/`: server certificate/key and CA certificate.
- `dialer-pki/`: client certificate/key and CA certificate.
- `ca-offline/`: CA certificate and signing key.

Keep `ca-offline/ca.key` offline. Copy only `gateway-pki/` to the Gateway and only `dialer-pki/` to the Dialer over a trusted channel. Do not put the CA signing key on either host. Protect the copied private keys and input directories with owner-only permissions.

The client certificate CN is the `--client-ip` value. In this example it is `10.66.0.2`; the Gateway's `PQTUNNEL_PEER_NAME` must match it exactly. The example Gateway environment file now reflects this convention.

## 4. Prepare and validate configuration

Start from the repository examples, but do not use documentation-only CIDRs or sample WAN interface names unchanged:

- Gateway application: `scripts/pqtunneld.site-to-site.env.example`
- Gateway network helper: `scripts/site-to-site-gateway.env.example`
- Dialer application: `scripts/pqtunnel-client.env.example`
- Dialer network helper: `scripts/site-to-site.env.example`

Set actual, non-overlapping lab prefixes and the actual WAN interface names. Keep the source/return-prefix policy, local destination prefixes, client-side local/remote prefixes, and destination-port allowlist consistent in both directions. Use only the narrow test ports and prefixes needed for the acceptance cases. Do not configure default routes unless a separate, reviewed test specifically requires them.

Stage all files under a root-owned directory on each endpoint, mode `0700`; private key files must be mode `0600`. The gateway environment must contain:

- `PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt`
- `PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key`
- `PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt`
- `PQTUNNEL_MAX_CLIENTS=1`
- `PQTUNNEL_PEER_NAME` equal to the Dialer certificate CN.

The Dialer environment must set `PQTUNNEL_SERVER`, `PQTUNNEL_SERVER_NAME`, `PQTUNNEL_LOCAL_PREFIXES`, and `PQTUNNEL_REMOTE_PREFIXES`. The server name must match the Gateway certificate SAN.

## 5. Read-only preflight

Build the Go-native verifier from the same checkout on each host:

```sh
go build -trimpath -o /tmp/pqtunnel-pki ./cmd/pqtunnel-pki
```

On the Gateway:

```sh
sudo env \
  PQTUNNEL_PKI_BIN=/tmp/pqtunnel-pki \
  PQTUNNEL_PREFLIGHT_PKI_DIR=/root/pqtunnel-input/gateway-pki \
  PQTUNNEL_PREFLIGHT_SERVER_NAME=gateway.lab.example \
  bash scripts/site-to-site-preflight.sh --role gateway
```

On the Dialer:

```sh
sudo env \
  PQTUNNEL_PKI_BIN=/tmp/pqtunnel-pki \
  PQTUNNEL_PREFLIGHT_PKI_DIR=/root/pqtunnel-input/dialer-pki \
  PQTUNNEL_PREFLIGHT_PEER_NAME=10.66.0.2 \
  bash scripts/site-to-site-preflight.sh --role dialer
```

Use the actual staged paths and identities. Preflight is read-only. It must report successful Go-native ML-DSA certificate/key/chain validation for the relevant role; investigate every FAIL and WARN before proceeding. Do not treat preflight as proof of routed connectivity.

## 6. Controlled install on disposable hosts

Only after the configuration and network plan have been independently reviewed, and only on the disposable lab pair, install from the pinned checkout.

Gateway:

```sh
sudo env PQTUNNEL_REF="<CANDIDATE_SHA>" \
  bash scripts/pqtunnel-bootstrap.sh install-server \
  --pki-dir /root/pqtunnel-input/gateway-pki \
  --server-env-file /root/pqtunnel-input/gateway-app.env \
  --network-env-file /root/pqtunnel-input/gateway-network.env \
  --start --apply-network
```

Dialer:

```sh
sudo env PQTUNNEL_REF="<CANDIDATE_SHA>" \
  bash scripts/pqtunnel-bootstrap.sh install-client \
  --pki-dir /root/pqtunnel-input/dialer-pki \
  --client-env-file /root/pqtunnel-input/dialer-app.env \
  --network-env-file /root/pqtunnel-input/dialer-network.env \
  --start
```

These commands start services and apply the explicitly requested lab network policy. They are state-changing. Do not run them on a host whose network is needed for unrelated workloads. The Gateway provider firewall still needs a separately reviewed rule allowing the Dialer's test source to reach the selected TCP listener port.

## 7. Acceptance cases

Record expected and actual results, exact commands, timestamps, and redacted logs for each case.

| Case | Expected result |
|---|---|
| Mutual TLS with fresh ML-DSA-65 certificates | Both peers authenticate; the intended tunnel becomes established. |
| Hybrid mode on both ends | TLS 1.3 handshake succeeds with only the configured `X25519MLKEM768` group. |
| Pure-PQ mode on both ends | Experimental TLS 1.3 handshake succeeds with only `MLKEM1024`, on the tested Go/runtime pair. |
| Hybrid on one end, pure-PQ on the other | Handshake fails; there is no key-exchange fallback. Restore both sides to the same mode afterward. |
| Wrong CA, wrong server SAN, wrong peer CN, wrong EKU, expired cert, mismatched key | Authentication fails closed. |
| Allowed IPv4 and IPv6 prefixes/ports | Only the planned test traffic passes in both directions. |
| Unlisted source prefix or destination port | Traffic is rejected. |
| Gateway restart / Dialer restart | The Dialer reconnects and allowed traffic recovers. |
| Network helper rollback | Only PQTunnel-owned lab resources are removed; pre-test route/firewall snapshots are restored. |
| Long-running transfer and sustained load | No unexplained disconnect, resource leak, or host-level network mutation. |

Run the four OS pairings separately: 24.04↔24.04, 24.04↔26.04, 26.04↔24.04, and 26.04↔26.04. Repeat a role-reversal case with a separately issued server certificate and peer identity if reverse listener placement is part of the intended scope.

For each run, compare the two hosts' routes, rules, addresses, forwarding sysctls and firewall state before and after. Run allowed/denied TCP and UDP cases against lab-only services; do not use public endpoints as test targets.

## 8. Recovery and evidence

Keep console/out-of-band access available throughout. To recover, stop the client/server services first, then use the matching `dialer-down` or `gateway-down` action from the installed `site-to-site-selective.sh` helper, following the state file and service-stop checks in the script. Do not delete routing tables or firewall rules manually unless the console recovery procedure has been reviewed.

For every case, retain:

- Candidate SHA, Go version, OS/kernel, architecture and topology.
- Redacted preflight output and redacted service logs.
- Before/after snapshots of routes, rules, addresses, sysctls and firewall state.
- Test result, failure injection/recovery result, and operator go/no-go.

Never retain private keys, access tokens, manager credentials, or unredacted configuration in the evidence bundle. A failed, skipped, or unrecorded case is not passed.

## 9. Release decision

Passing this runbook is necessary evidence for the Linux MVP gate, not an independent security audit and not proof of production readiness. Do not publish a stable release until the full Linux release gate, two-host matrix, recovery rehearsal, and independent security review are complete. Windows and Android remain unsupported until their separate gates pass.
