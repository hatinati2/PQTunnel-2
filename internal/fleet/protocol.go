package fleet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
)

// Envelope is the authenticated, encrypted carrier used over the HTTP agent
// channel. NodeID is routing metadata; all operational data is inside Ciphertext.
type Envelope struct {
	NodeID     string `json:"node_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type EnrollRequest struct {
	Token     string `json:"token"`
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	PublicKey string `json:"public_key"`
}

type EnrollResponse struct {
	ServerPublicKey string `json:"server_public_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

type Credentials struct {
	NodeID string `json:"node_id"`
	Key    string `json:"key"`
}

type AgentRequest struct {
	Sequence  int64                      `json:"sequence"`
	Timestamp int64                      `json:"timestamp"`
	Snapshot  adminapi.ManagerSnapshot   `json:"snapshot"`
	Result    *CommandResult             `json:"result,omitempty"`
}

type AgentResponse struct {
	AckID   string  `json:"ack_id,omitempty"`
	Command *Command `json:"command,omitempty"`
}

type Command struct {
	ID        string                         `json:"id"`
	Action    string                         `json:"action"`
	Config    adminapi.TunnelConfiguration   `json:"config,omitempty"`
	NodeSetup adminapi.NodeSetupRequest      `json:"node_setup,omitempty"`
	Bundle    []byte                         `json:"bundle,omitempty"`
	SizeMiB   int                            `json:"size_mib,omitempty"`
}

type CommandResult struct {
	ID          string                       `json:"id"`
	Success     bool                         `json:"success"`
	Message     string                       `json:"message,omitempty"`
	Logs        string                       `json:"logs,omitempty"`
	Bundle      []byte                       `json:"bundle,omitempty"`
	SetupStatus *adminapi.NodeSetupStatus    `json:"setup_status,omitempty"`
}

type NodeSnapshot struct {
	ID        string                    `json:"id"`
	Name      string                    `json:"name"`
	Role      string                    `json:"role"`
	Connected bool                      `json:"connected"`
	LastSeen  time.Time                 `json:"last_seen,omitempty"`
	Snapshot  adminapi.ManagerSnapshot  `json:"snapshot"`
}

const (
	agentFreshnessWindow = 2 * time.Minute
	agentOnlineWindow    = 12 * time.Second
	maxAgentMessageBytes = 2 << 20
)

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, v := range b {
		out[2*i] = hex[v>>4]
		out[2*i+1] = hex[v&0x0f]
	}
	return string(out), nil
}

func seal(key []byte, value any) (Envelope, error) {
	if len(key) != 32 {
		return Envelope{}, errors.New("agent encryption key must be 32 bytes")
	}
	plain, err := json.Marshal(value)
	if err != nil {
		return Envelope{}, fmt.Errorf("encode agent message: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, []byte("PQTunnel fleet agent v1"))
	return Envelope{
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

func openEnvelope(key []byte, envelope Envelope, dst any) error {
	if len(key) != 32 {
		return errors.New("agent encryption key must be 32 bytes")
	}
	if len(envelope.Ciphertext) > maxAgentMessageBytes*2 {
		return errors.New("agent message is too large")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return errors.New("agent message nonce is invalid")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) > maxAgentMessageBytes {
		return errors.New("agent message ciphertext is invalid or too large")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(nonce) != aead.NonceSize() {
		return errors.New("agent message nonce has an invalid size")
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte("PQTunnel fleet agent v1"))
	if err != nil {
		return errors.New("agent message authentication failed")
	}
	if err := json.Unmarshal(plain, dst); err != nil {
		return errors.New("agent message payload is invalid")
	}
	return nil
}

func deriveEnrollmentKey(shared []byte, token string) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("PQTunnel fleet enrollment v1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(token))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(shared)
	return hash.Sum(nil)
}

func completeEnrollment(token string, privateKey *ecdh.PrivateKey, response EnrollResponse) (Credentials, error) {
	curve := ecdh.X25519()
	serverPublic, err := base64.RawURLEncoding.DecodeString(response.ServerPublicKey)
	if err != nil {
		return Credentials{}, errors.New("server enrollment public key is invalid")
	}
	publicKey, err := curve.NewPublicKey(serverPublic)
	if err != nil {
		return Credentials{}, errors.New("server enrollment public key is invalid")
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return Credentials{}, errors.New("could not establish enrollment key agreement")
	}
	key := deriveEnrollmentKey(shared, token)
	env := Envelope{Nonce: response.Nonce, Ciphertext: response.Ciphertext}
	var credentials Credentials
	if err := openEnvelope(key, env, &credentials); err != nil {
		return Credentials{}, err
	}
	if credentials.NodeID == "" || len(credentials.Key) != 64 {
		return Credentials{}, errors.New("server returned invalid agent credentials")
	}
	return credentials, nil
}

func newEnrollmentReply(token string, publicKeyText string, credentials Credentials) (EnrollResponse, error) {
	publicRaw, err := base64.RawURLEncoding.DecodeString(publicKeyText)
	if err != nil {
		return EnrollResponse{}, errors.New("agent enrollment public key is invalid")
	}
	curve := ecdh.X25519()
	agentPublic, err := curve.NewPublicKey(publicRaw)
	if err != nil {
		return EnrollResponse{}, errors.New("agent enrollment public key is invalid")
	}
	serverPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return EnrollResponse{}, err
	}
	shared, err := serverPrivate.ECDH(agentPublic)
	if err != nil {
		return EnrollResponse{}, errors.New("could not establish enrollment key agreement")
	}
	key := deriveEnrollmentKey(shared, token)
	envelope, err := seal(key, credentials)
	if err != nil {
		return EnrollResponse{}, err
	}
	return EnrollResponse{
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(serverPrivate.PublicKey().Bytes()),
		Nonce: envelope.Nonce,
		Ciphertext: envelope.Ciphertext,
	}, nil
}

func CompleteEnrollmentForAgent(token string, privateKey *ecdh.PrivateKey, response EnrollResponse) (Credentials, error) {
	return completeEnrollment(token, privateKey, response)
}

func SealForAgent(key []byte, nodeID string, value any) (Envelope, error) {
	envelope, err := seal(key, value)
	if err != nil {
		return Envelope{}, err
	}
	envelope.NodeID = nodeID
	return envelope, nil
}

func OpenForAgent(key []byte, envelope Envelope, dst any) error {
	return openEnvelope(key, envelope, dst)
}
