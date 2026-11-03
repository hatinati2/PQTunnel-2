# Security policy

PQTunnel 2 is experimental and has not undergone an independent security audit. Do not use it for sensitive activity or on production infrastructure.

## Reporting a vulnerability

Do not open public issues containing private keys, certificates, connection tokens, operator IP addresses, hostnames, or unredacted logs. Report security issues privately through a trusted channel and include a minimal reproducible description. There is no response-time SLA for this experimental project.

## Current cryptographic design

- TLS 1.3 only.
- Default key exchange: strict hybrid `X25519MLKEM768`; no other key-exchange group is enabled in that connection.
- Optional experimental key exchange: strict `MLKEM1024` only, with no classical fallback.
- Mutual TLS using a private CA.
- All CA, server, client, and peer signing keys and certificate signatures are ML-DSA-65.
- TLS peer verification checks that every certificate in the presented and verified chains uses ML-DSA-65 public keys and ML-DSA-65 signatures. Classical certificate chains, including Ed25519, are rejected.
- The default hybrid mode still includes classical X25519 as one component of key exchange. It must be described as hybrid, not pure post-quantum key exchange.
- No custom cipher, KDF, or cryptographic primitive is implemented by this project.

## Known gaps

- No independent security review or full fuzzing campaign.
- No online certificate revocation service or safe automated enrollment workflow.
- Pure-PQ key exchange remains experimental pending broader interoperability and deployment testing.
- Windows routes/DNS/kill-switch and Android certificate import/build verification remain incomplete.
- Network configuration helpers are prototypes and are not persistent, audited kill-switches.
- The site-to-site helper's namespace tests do not validate real VPS pairs, provider firewalls, arbitrary existing host firewall/routing policy, or recovery after real-host failure.
- Traffic may be exposed if endpoints, client keys, CA signing keys, host firewall rules, or device permissions are compromised.

## Handling operator-specific data

Tests must use only generated keys, loopback addresses, reserved documentation address ranges, and reserved example domains such as `.example.test`. Never copy operator-supplied IP addresses, DNS names, SSH targets, ports, tokens, passwords, certificates, private keys, server identifiers, or other deployment-specific values into source code, test fixtures, examples, CI files, logs, or screenshots. Inject deployment settings only at runtime through protected configuration and do not commit them.

Please avoid claims that the software is "unbreakable", "fully secure", "leak-proof", "fully post-quantum" in hybrid mode, or production-ready.
