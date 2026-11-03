package tunnel

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

type TLSKeyExchangeMode string

const (
	// TLSKeyExchangeHybrid combines X25519 with ML-KEM-768.
	TLSKeyExchangeHybrid TLSKeyExchangeMode = "hybrid"
	// TLSKeyExchangePurePQ uses ML-KEM-1024 without a classical key-exchange component.
	// Keep this mode experimental until interoperability and deployment testing is complete.
	TLSKeyExchangePurePQ TLSKeyExchangeMode = "pure-pq"
)

var ErrHybridPQUnavailable = errors.New("strict X25519MLKEM768 key exchange unavailable; classical fallback is disabled")

// TLS13ConfigForMode creates a TLS 1.3 configuration with exactly one allowed
// key-exchange group and strict ML-DSA-65 peer-certificate-chain verification.
// "hybrid" is the default deployment mode. "pure-pq" is experimental.
func TLS13ConfigForMode(mode TLSKeyExchangeMode) (*tls.Config, error) {
	var group tls.CurveID
	switch mode {
	case TLSKeyExchangeHybrid:
		group = tls.X25519MLKEM768
	case TLSKeyExchangePurePQ:
		group = tls.MLKEM1024
	default:
		return nil, fmt.Errorf("unsupported TLS key-exchange mode %q (expected %q or %q)", mode, TLSKeyExchangeHybrid, TLSKeyExchangePurePQ)
	}

	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{group},
		SessionTicketsDisabled: true,
		VerifyConnection:       VerifyMLDSA65PeerChain,
	}, nil
}

// StrictTLS13Config keeps the historical default API and selects hybrid
// X25519 + ML-KEM-768 with ML-DSA-65 certificate authentication.
func StrictTLS13Config() *tls.Config {
	cfg, err := TLS13ConfigForMode(TLSKeyExchangeHybrid)
	if err != nil {
		// The only way to reach this is a programming error in the fixed mode above.
		panic(err)
	}
	return cfg
}

// VerifyMLDSA65PeerChain rejects classical or differently parameterized
// public keys and certificate signatures in the presented and verified chains.
// Normal TLS certificate and hostname verification must remain enabled.
func VerifyMLDSA65PeerChain(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer certificate is required")
	}
	if len(state.VerifiedChains) == 0 {
		return errors.New("a verified peer certificate chain is required")
	}
	for _, cert := range state.PeerCertificates {
		if err := requireMLDSA65Certificate(cert); err != nil {
			return fmt.Errorf("peer certificate chain: %w", err)
		}
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 {
			return errors.New("verified peer certificate chain is empty")
		}
		for _, cert := range chain {
			if err := requireMLDSA65Certificate(cert); err != nil {
				return fmt.Errorf("verified peer certificate chain: %w", err)
			}
		}
	}
	return nil
}

func requireMLDSA65Certificate(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is missing")
	}
	if cert.SignatureAlgorithm != x509.MLDSA65 {
		return fmt.Errorf("certificate signature must be ML-DSA-65, got %s", cert.SignatureAlgorithm)
	}
	pub, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok || pub.Parameters() != mldsa.MLDSA65() {
		return errors.New("certificate public key must be ML-DSA-65")
	}
	if cert.PublicKeyAlgorithm != x509.MLDSA {
		return errors.New("certificate public-key algorithm must be ML-DSA")
	}
	return nil
}

// VerifyPeerCommonName enforces an exact application identity after the TLS
// stack has validated the peer certificate chain, key algorithms and usage.
func VerifyPeerCommonName(state tls.ConnectionState, expected string) error {
	if expected == "" {
		return errors.New("expected peer common name is required")
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer certificate is required")
	}
	if state.PeerCertificates[0].Subject.CommonName != expected {
		return errors.New("peer certificate common name mismatch")
	}
	return nil
}
