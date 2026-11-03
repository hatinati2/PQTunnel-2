# Pre-release validation checklist

Do not mark PQTunnel 2 stable until these items have been performed and their results are documented.

## Build and CI

- [ ] Run `go test -race ./...` with Go 1.27 or newer (CI uses 1.27.x).
- [ ] Run `go vet ./...` and dependency vulnerability scanning.
- [ ] Confirm Linux amd64/arm64 and Windows amd64 artifacts build from the tagged commit.
- [ ] Build the Android AAR with the documented `gomobile` version, SDK and NDK; install it on physical devices.

See [the two-host Linux acceptance runbook](TWO-HOST-ACCEPTANCE.md) for the controlled lab procedure and evidence template.

## TLS and identity

- [ ] Verify a real handshake selects exactly `X25519MLKEM768` in hybrid mode.
- [ ] Verify a real handshake selects exactly `MLKEM1024` in experimental pure-PQ mode on supported peers.
- [ ] Connect hybrid-only and pure-PQ-only peers in both directions and prove that the handshake fails without fallback.
- [ ] Verify CA, server, client, and peer certificates all use ML-DSA-65 public keys and ML-DSA-65 signatures.
- [ ] Verify classical certificates (including Ed25519 and ECDSA) and chains with a classical intermediate are rejected.
- [ ] Test expired, wrong-CA, wrong-server-name, wrong-client-EKU, missing certificates, and mismatched private key/certificate pairs.
- [ ] Review private-key file permissions and provisioning for CA, server, desktop clients and Android.

## Packet and network tests

- [ ] Run protocol tests and fuzzing for malformed/truncated/oversized frames and IP packets.
- [ ] Keep `scripts/test-site-to-site-netns.sh` and `scripts/test-selective-forward-netns.sh` passing on Ubuntu 24.04 and 26.04. They exercise real Linux TUN devices, dual-stack routes, and inbound TCP/UDP port-forward round trips over IPv4 and IPv6 in disposable namespaces. They do not replace a two-VPS test or validate provider firewalls, public routing, or production firewall/NAT integration.
- [ ] Test two clients with unique identities and reject duplicate identities/source spoofing.
- [ ] Test reconnects, packet loss, long RTT, server restart, sleep/resume and TCP-over-TCP degradation.
- [ ] Keep `scripts/test-selective-egress-netns.sh` and `scripts/test-site-to-site-selective-fail-closed.sh` passing on Ubuntu 24.04 and 26.04. These tests run only in disposable namespaces; separate real-host recovery rehearsals with out-of-band access remain required before stable release.
- [ ] Verify IPv4 forwarding/NAT with and without UFW or another host firewall. Verify rollback from console access.
- [ ] Check DNS and IPv6 on all desktop OSs using independent leak tests; test before tunnel, while connected, after transport loss, during sleep/resume and after reboot.
- [ ] Confirm the Linux client route helper refuses ambiguous existing routes and that its explicit `down` path restores original connectivity.

## Platform completeness

- [ ] Windows: provision Wintun from the official source; implement and test address, route, DNS and firewall/kill-switch management; confirm cleanup on crash and reboot.
- [ ] Android: implement certificate import/provisioning, proper status/error reporting, duplicate-start protection, foreground-service lifecycle and physical-device tests on supported Android versions.
- [ ] Verify no system firewall, SSH route, DNS setting or unrelated route is modified by default.

## Release documentation

- [ ] State clearly that all project-generated certificate keys and certificate signatures use ML-DSA-65; clearly distinguish hybrid key exchange from pure-PQ key exchange.
- [ ] Publish a threat model and independently review the implementation.
- [ ] Do not use claims such as "unbreakable", "leak-proof" or "production-ready" without evidence.
- [ ] Run end-to-end tests for both listener/dialer directions with domain, IPv4 and IPv6 transport endpoints.
- [ ] Test the four Ubuntu 24.04/26.04 pairings (24↔24, 24↔26, 26↔24, 26↔26).
- [ ] Test routed IPv4/IPv6 prefix allowlists, spoofed source rejection, route overlap behavior, reconnects and DNS behavior in a lab.
- [ ] Validate endpoint-route pinning before default-route changes; verify IPv4/IPv6 behavior and rollback from console/out-of-band access.
- [ ] Do not publish as a stable release until the two-host routing, firewall, recovery, and cryptographic compatibility gates pass.
