package tunnel

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/prefixset"
	"github.com/hatinati2/PQTunnel-2/internal/protocol"
)

type serverPolicyTestDevice struct {
	writes chan []byte
	closed chan struct{}
	once sync.Once
}

func newServerPolicyTestDevice() *serverPolicyTestDevice {
	return &serverPolicyTestDevice{writes: make(chan []byte, 8), closed: make(chan struct{})}
}
func (d *serverPolicyTestDevice) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.ErrClosedPipe
}
func (d *serverPolicyTestDevice) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	d.writes <- append([]byte(nil), p...)
	return len(p), nil
}
func (d *serverPolicyTestDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func createPolicyTestCert(t *testing.T, ca *x509.Certificate, caKey *mldsa.PrivateKey, cn, dnsName string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil { t.Fatal(err) }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		SignatureAlgorithm: x509.MLDSA65,
		Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: nil,
	}
	if dnsName != "" { tmpl.DNSNames = []string{dnsName} }
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.PublicKey(), caKey)
	if err != nil { t.Fatal(err) }
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil { t.Fatal(err) }
	certPEM := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil { t.Fatal(err) }
	return cert
}

func createPolicyTestCA(t *testing.T) (*x509.Certificate, *mldsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil { t.Fatal(err) }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		SignatureAlgorithm: x509.MLDSA65,
		Subject: pkix.Name{CommonName:"PQTunnel policy test CA"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(2*time.Hour),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
	if err != nil { t.Fatal(err) }
	ca, err := x509.ParseCertificate(der)
	if err != nil { t.Fatal(err) }
	pemBytes := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) { t.Fatal("could not append generated test CA") }
	return ca, key, pool
}

func policyTestIPv4Packet(src, dst string) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}


func TestTLSKeyExchangeModeMismatchFailsClosed(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	clientCert := createPolicyTestCert(t, ca, caKey, "peer", "", x509.ExtKeyUsageClientAuth)

	serverConfig, err := ServerTLSConfigForMode(serverCert, roots, TLSKeyExchangePurePQ)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := TLS13ConfigForMode(TLSKeyExchangeHybrid)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.RootCAs = roots
	clientConfig.ServerName = "gateway.example.test"
	clientConfig.Certificates = []tls.Certificate{clientCert}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := tls.Client(clientRaw, clientConfig)
	serverConn := tls.Server(serverRaw, serverConfig)
	serverErr := make(chan error, 1)
	go func() { serverErr <- serverConn.Handshake() }()

	if err := clientConn.Handshake(); err == nil {
		t.Fatal("hybrid client unexpectedly negotiated with a pure-PQ-only server; a fallback may have occurred")
	}
	select {
	case err := <-serverErr:
		if err == nil {
			t.Fatal("pure-PQ-only server unexpectedly completed a handshake with a hybrid-only client")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server handshake did not terminate after the key-exchange mismatch")
	}
}

func TestServerHandleAuthenticatesPeerAndEnforcesCIDRPolicy(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	peerCert := createPolicyTestCert(t, ca, caKey, "iran", "", x509.ExtKeyUsageClientAuth)
	peerPrefixes, err := prefixset.ParseCSV("192.0.2.0/24")
	if err != nil { t.Fatal(err) }
	localPrefixes, err := prefixset.ParseCSV("10.66.0.0/24")
	if err != nil { t.Fatal(err) }

	dev := newServerPolicyTestDevice()
	s := &Server{
		TLSConfig: ServerTLSConfig(serverCert, roots),
		Device: dev,
		MaxClients: 1,
		PeerPrefixes: peerPrefixes,
		LocalPrefixes: localPrefixes,
		PeerIdentity: "iran",
		clients: make(map[string]*peer),
	}

	clientRaw, serverRaw := net.Pipe()
	serverConn := tls.Server(serverRaw, s.TLSConfig.Clone())
	clientTLSConfig := StrictTLS13Config()
	clientTLSConfig.RootCAs = roots
	clientTLSConfig.ServerName = "gateway.example.test"
	clientTLSConfig.Certificates = []tls.Certificate{peerCert}
	clientConn := tls.Client(clientRaw, clientTLSConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.handle(ctx, serverConn)
		close(done)
	}()
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("mutual TLS handshake failed: %v", err)
	}
	if got := clientConn.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("client negotiated key exchange group %v, want X25519MLKEM768", got)
	}
	if got := serverConn.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("server negotiated key exchange group %v, want X25519MLKEM768", got)
	}

	disallowedDst := policyTestIPv4Packet("192.0.2.7", "198.51.100.9")
	allowed := policyTestIPv4Packet("192.0.2.8", "10.66.0.2")
	for _, p := range [][]byte{disallowedDst, allowed} {
		if err := protocol.WriteFrame(clientConn, p); err != nil {
			t.Fatalf("write test frame: %v", err)
		}
	}
	select {
	case got := <-dev.writes:
		if string(got) != string(allowed) {
			t.Fatalf("server forwarded unexpected packet: got %v, want %v", got, allowed)
		}
	case <-time.After(2*time.Second):
		t.Fatal("server did not forward the allowed packet")
	}
	select {
	case extra := <-dev.writes:
		t.Fatalf("server forwarded disallowed packet: %v", extra)
	case <-time.After(30*time.Millisecond):
	}

	// Close the authenticated test session cleanly after the policy assertions.
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2*time.Second):
		t.Fatal("server handler did not exit after the peer connection closed")
	}
	_ = dev.Close()
}

func TestServerHandleRejectsWrongPeerIdentity(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	wrongPeerCert := createPolicyTestCert(t, ca, caKey, "not-iran", "", x509.ExtKeyUsageClientAuth)
	peerPrefixes, _ := prefixset.ParseCSV("192.0.2.0/24")
	localPrefixes, _ := prefixset.ParseCSV("10.66.0.0/24")
	dev := newServerPolicyTestDevice()
	s := &Server{
		TLSConfig: ServerTLSConfig(serverCert, roots),
		Device: dev,
		MaxClients: 1,
		PeerPrefixes: peerPrefixes,
		LocalPrefixes: localPrefixes,
		PeerIdentity: "iran",
		clients: make(map[string]*peer),
	}
	clientRaw, serverRaw := net.Pipe()
	serverConn := tls.Server(serverRaw, s.TLSConfig.Clone())
	clientCfg := StrictTLS13Config()
	clientCfg.RootCAs = roots
	clientCfg.ServerName = "gateway.example.test"
	clientCfg.Certificates = []tls.Certificate{wrongPeerCert}
	clientConn := tls.Client(clientRaw, clientCfg)
	done := make(chan struct{})
	go func() { s.handle(context.Background(), serverConn); close(done) }()
	if err := clientConn.Handshake(); err != nil {
		// An early handshake error is acceptable for rejected identity.
		_ = clientConn.Close()
	} else {
		_ = protocol.WriteFrame(clientConn, policyTestIPv4Packet("192.0.2.1", "10.66.0.2"))
		_ = clientConn.Close()
	}
	select {
	case <-done:
	case <-time.After(2*time.Second):
		t.Fatal("server did not close connection for mismatched peer identity")
	}
	select {
	case got := <-dev.writes:
		t.Fatalf("server accepted data from wrong peer identity: %v", got)
	default:
	}
	_ = clientConn.Close()
	_ = dev.Close()
}

func TestStrictTLSRejectsClassicalOnlyPeer(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	peerCert := createPolicyTestCert(t, ca, caKey, "iran", "", x509.ExtKeyUsageClientAuth)

	serverRaw, clientRaw := net.Pipe()
	serverConn := tls.Server(serverRaw, ServerTLSConfig(serverCert, roots))
	clientConn := tls.Client(clientRaw, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		RootCAs:          roots,
		ServerName:       "gateway.example.test",
		Certificates:     []tls.Certificate{peerCert},
	})
	defer serverConn.Close()
	defer clientConn.Close()

	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	go func() { serverDone <- serverConn.Handshake() }()
	go func() { clientDone <- clientConn.Handshake() }()

	var clientErr, serverErr error
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for completed := 0; completed < 2; completed++ {
		select {
		case clientErr = <-clientDone:
		case serverErr = <-serverDone:
		case <-timeout.C:
			t.Fatal("classical-only TLS handshake did not fail promptly")
		}
	}
	if clientErr == nil || serverErr == nil {
		t.Fatalf("strict hybrid-only TLS unexpectedly negotiated without a shared hybrid group: client=%v server=%v", clientErr, serverErr)
	}
}
