package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSafeIdentity(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"iran", true},
		{"germany-1", true},
		{"peer.example", true},
		{"", false},
		{"../outside", false},
		{"has space", false},
		{"slash/name", false},
		{strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeIdentity(tt.name); got != tt.ok {
				t.Fatalf("safeIdentity(%q) = %v, want %v", tt.name, got, tt.ok)
			}
		})
	}
}

func TestIssueServerCreatesVerifiableCertificateAndPrivateKey(t *testing.T) {
	for _, host := range []string{"vpn.example.test", "192.0.2.10", "2001:db8::10"} {
		t.Run(host, func(t *testing.T) {
			out := t.TempDir()
			caCert, caKey := testCA(t)
			issueServer(out, host, caCert, caKey)

			certPEM, err := os.ReadFile(filepath.Join(out, "server.crt"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(certPEM)
			if block == nil {
				t.Fatal("server.crt is not PEM")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(caCert)
			opts := x509.VerifyOptions{Roots: roots, CurrentTime: time.Now()}
			if ip, err := netip.ParseAddr(host); err == nil {
				opts.DNSName = ip.String()
			} else {
				opts.DNSName = host
			}
			if _, err := leaf.Verify(opts); err != nil {
				t.Fatalf("issued server certificate does not verify for %q: %v", host, err)
			}
			if leaf.SignatureAlgorithm != x509.MLDSA65 || leaf.PublicKeyAlgorithm != x509.MLDSA {
				t.Fatalf("server certificate is not ML-DSA-65: signature=%v public-key=%v", leaf.SignatureAlgorithm, leaf.PublicKeyAlgorithm)
			}
			if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Fatalf("unexpected extended key usages: %v", leaf.ExtKeyUsage)
			}

			info, err := os.Stat(filepath.Join(out, "server.key"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("server private key mode = %04o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func testCA(t *testing.T) (*x509.Certificate, *mldsa.PrivateKey) {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		SignatureAlgorithm: x509.MLDSA65,
		Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}


func TestInitAndIssueArtifactsUseMLDSA65(t *testing.T) {
	out := t.TempDir()
	initCA([]string{"--out", out, "--server-name", "vpn.example.test"})
	issueClient([]string{"--out", out, "--ip", "192.0.2.10"})
	issuePeer([]string{"--out", out, "--name", "peer-fixture"})

	caPEM, err := os.ReadFile(filepath.Join(out, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		t.Fatal("ca.crt is not PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ca.SignatureAlgorithm != x509.MLDSA65 || ca.PublicKeyAlgorithm != x509.MLDSA {
		t.Fatalf("CA is not ML-DSA-65: signature=%v public-key=%v", ca.SignatureAlgorithm, ca.PublicKeyAlgorithm)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	cases := []struct {
		name, certFile, keyFile, identity string
		usage x509.ExtKeyUsage
		dnsName string
	}{
		{name: "server", certFile: "server.crt", keyFile: "server.key", identity: "vpn.example.test", usage: x509.ExtKeyUsageServerAuth, dnsName: "vpn.example.test"},
		{name: "client", certFile: "client-192_0_2_10.crt", keyFile: "client-192_0_2_10.key", identity: "192.0.2.10", usage: x509.ExtKeyUsageClientAuth},
		{name: "peer", certFile: "peer-peer-fixture.crt", keyFile: "peer-peer-fixture.key", identity: "peer-fixture", usage: x509.ExtKeyUsageClientAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPath := filepath.Join(out, tc.certFile)
			keyPath := filepath.Join(out, tc.keyFile)
			pair, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("load generated certificate/key pair: %v", err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if leaf.Subject.CommonName != tc.identity {
				t.Fatalf("certificate identity=%q, want %q", leaf.Subject.CommonName, tc.identity)
			}
			if leaf.SignatureAlgorithm != x509.MLDSA65 || leaf.PublicKeyAlgorithm != x509.MLDSA {
				t.Fatalf("certificate is not ML-DSA-65: signature=%v public-key=%v", leaf.SignatureAlgorithm, leaf.PublicKeyAlgorithm)
			}
			verify := x509.VerifyOptions{
				Roots: roots,
				CurrentTime: time.Now(),
				KeyUsages: []x509.ExtKeyUsage{tc.usage},
			}
			if tc.dnsName != "" {
				verify.DNSName = tc.dnsName
			}
			if _, err := leaf.Verify(verify); err != nil {
				t.Fatalf("certificate chain verification failed: %v", err)
			}
			for _, secretPath := range []string{keyPath} {
				info, err := os.Stat(secretPath)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0600 {
					t.Fatalf("private key mode=%04o, want 0600", info.Mode().Perm())
				}
			}
		})
	}
}

func TestValidateCAKeyRejectsMismatchedKey(t *testing.T) {
	caCert, _ := testCA(t)
	otherKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCAKey(caCert, otherKey); err == nil {
		t.Fatal("expected mismatched CA key to be rejected")
	}
}

func TestValidateCAKeyRejectsNonCA(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pub := key.PublicKey()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		SignatureAlgorithm: x509.MLDSA65,
		Subject: pkix.Name{CommonName: "not a CA"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCAKey(cert, key); err == nil {
		t.Fatal("expected non-CA certificate to be rejected")
	}
}


func TestValidateCAKeyRejectsExpiredCA(t *testing.T) {
	caCert, key := testCA(t)
	caCert.NotAfter = time.Now().Add(-time.Minute)
	if err := validateCAKey(caCert, key); err == nil {
		t.Fatal("expected expired CA certificate to be rejected")
	}
}

func TestValidateCAKeyRejectsNilKey(t *testing.T) {
	caCert, _ := testCA(t)
	if err := validateCAKey(caCert, nil); err == nil {
		t.Fatal("expected nil ML-DSA key to be rejected")
	}
}
