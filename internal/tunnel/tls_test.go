package tunnel

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestTLSKeyExchangeModesAreStrict(t *testing.T) {
	tests := []struct {
		name string
		mode TLSKeyExchangeMode
		want tls.CurveID
	}{
		{name: "hybrid", mode: TLSKeyExchangeHybrid, want: tls.X25519MLKEM768},
		{name: "pure pq experimental", mode: TLSKeyExchangePurePQ, want: tls.MLKEM1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := TLS13ConfigForMode(tt.mode)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
				t.Fatal("TLS 1.3 must be the only enabled version")
			}
			if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tt.want {
				t.Fatalf("unexpected key-exchange policy: %#v", cfg.CurvePreferences)
			}
			if !cfg.SessionTicketsDisabled {
				t.Fatal("session tickets should be disabled for this prototype")
			}
			if cfg.VerifyConnection == nil {
				t.Fatal("strict ML-DSA-65 peer-chain verification must be enabled")
			}
		})
	}
}

func TestTLSKeyExchangeRejectsUnknownMode(t *testing.T) {
	if _, err := TLS13ConfigForMode("classical"); err == nil {
		t.Fatal("expected an unsupported key-exchange mode to be rejected")
	}
}

func TestVerifyMLDSA65PeerChainAcceptsOnlyVerifiedMLDSAChain(t *testing.T) {
	ca, caKey, _ := createPolicyTestCA(t)
	leafTLS := createPolicyTestCert(t, ca, caKey, "peer-fixture", "", x509.ExtKeyUsageClientAuth)
	leaf, err := x509.ParseCertificate(leafTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, ca},
		VerifiedChains:   [][]*x509.Certificate{{leaf, ca}},
	}
	if err := VerifyMLDSA65PeerChain(state); err != nil {
		t.Fatalf("valid ML-DSA-65 chain rejected: %v", err)
	}
}

func TestVerifyMLDSA65PeerChainRejectsEd25519Leaf(t *testing.T) {
	leaf := &x509.Certificate{
		SignatureAlgorithm: x509.PureEd25519,
		PublicKeyAlgorithm: x509.Ed25519,
		PublicKey:          ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)),
	}
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	if err := VerifyMLDSA65PeerChain(state); err == nil {
		t.Fatal("classical Ed25519 certificate unexpectedly passed strict ML-DSA verification")
	}
}

func TestVerifyMLDSA65PeerChainRequiresVerifiedChain(t *testing.T) {
	if err := VerifyMLDSA65PeerChain(tls.ConnectionState{}); err == nil {
		t.Fatal("expected missing peer certificate and verified chain to be rejected")
	}
}

func TestVerifyPeerCommonName(t *testing.T) {
	tests := []struct {
		name     string
		state    tls.ConnectionState
		expected string
		wantErr  bool
	}{
		{
			name: "exact match",
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{
				{Subject: pkixName("dialer.test")},
			}},
			expected: "dialer.test",
		},
		{
			name: "mismatch",
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{
				{Subject: pkixName("other.test")},
			}},
			expected: "dialer.test",
			wantErr:  true,
		},
		{name: "missing expected identity", state: tls.ConnectionState{}, wantErr: true},
		{name: "missing peer certificate", state: tls.ConnectionState{}, expected: "dialer.test", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPeerCommonName(tt.state, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyPeerCommonName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName}
}
