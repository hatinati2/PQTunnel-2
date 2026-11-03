package fleet

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
)

func TestEnrollmentEncryptedPollingCommandAndReplayProtection(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "fleet", "state.json")
	broker, err := NewBroker(statePath)
	if err != nil { t.Fatal(err) }
	token, expires, err := broker.CreateInvite()
	if err != nil { t.Fatal(err) }
	if time.Until(expires) <= 0 { t.Fatal("invite already expired") }

	curve := ecdh.X25519()
	clientPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	const nodeID = "0123456789abcdef0123456789abcdef"
	reply, err := broker.Enroll(EnrollRequest{
		Token: token, NodeID: nodeID, Name: "dialer-test", Role: "dialer",
		PublicKey: base64.RawURLEncoding.EncodeToString(clientPrivate.PublicKey().Bytes()),
	})
	if err != nil { t.Fatal(err) }
	credentials, err := completeEnrollment(token, clientPrivate, reply)
	if err != nil { t.Fatal(err) }
	if credentials.NodeID != nodeID { t.Fatalf("node id=%q", credentials.NodeID) }
	key, err := decodeHexKey(credentials.Key)
	if err != nil { t.Fatal(err) }

	request := AgentRequest{
		Sequence: time.Now().UnixNano(), Timestamp: time.Now().Unix(),
		Snapshot: adminapi.ManagerSnapshot{Role: "dialer", ActiveState: "active"},
	}
	firstEnvelope, err := SealForAgent(key, nodeID, request)
	if err != nil { t.Fatal(err) }
	firstReply, err := broker.Poll(firstEnvelope)
	if err != nil { t.Fatal(err) }
	var firstResponse AgentResponse
	if err := OpenForAgent(key, firstReply, &firstResponse); err != nil { t.Fatal(err) }
	if firstResponse.Command != nil { t.Fatal("unexpected command on heartbeat") }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resultCh := make(chan CommandResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, callErr := broker.Execute(ctx, Command{Action: "restart"})
		if callErr != nil { errCh <- callErr; return }
		resultCh <- result
	}()

	var command *Command
	for deadline := time.Now().Add(3*time.Second); time.Now().Before(deadline); {
		request.Sequence = time.Now().UnixNano()
		request.Timestamp = time.Now().Unix()
		env, sealErr := SealForAgent(key, nodeID, request)
		if sealErr != nil { t.Fatal(sealErr) }
		responseEnvelope, pollErr := broker.Poll(env)
		if pollErr != nil { t.Fatal(pollErr) }
		var response AgentResponse
		if err := OpenForAgent(key, responseEnvelope, &response); err != nil { t.Fatal(err) }
		if response.Command != nil {
			command = response.Command
			break
		}
		time.Sleep(50*time.Millisecond)
	}
	if command == nil || command.Action != "restart" { t.Fatal("queued command was not delivered") }

	result := &CommandResult{ID: command.ID, Success: true, Message: "restarted"}
	request.Sequence = time.Now().UnixNano()
	request.Timestamp = time.Now().Unix()
	request.Result = result
	env, err := SealForAgent(key, nodeID, request)
	if err != nil { t.Fatal(err) }
	responseEnvelope, err := broker.Poll(env)
	if err != nil { t.Fatal(err) }
	var ack AgentResponse
	if err := OpenForAgent(key, responseEnvelope, &ack); err != nil { t.Fatal(err) }
	if ack.AckID != command.ID { t.Fatalf("ack=%q want %q", ack.AckID, command.ID) }

	select {
	case callErr := <-errCh:
		t.Fatal(callErr)
	case result := <-resultCh:
		if !result.Success || result.ID != command.ID { t.Fatalf("unexpected result: %#v", result) }
	case <-ctx.Done():
		t.Fatal("central command did not receive Dialer result")
	}

	if _, err := broker.Poll(firstEnvelope); err == nil {
		t.Fatal("replayed agent message was accepted")
	}
	if snapshot := broker.DialerSnapshot(); !snapshot.Connected || snapshot.Snapshot.ActiveState != "active" {
		t.Fatalf("Dialer snapshot not updated: %#v", snapshot)
	}
	info, err := os.Stat(statePath)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("fleet state mode=%o, want 0600", info.Mode().Perm()) }
}

func decodeHexKey(value string) ([]byte, error) {
	const digits = "0123456789abcdef"
	if len(value)%2 != 0 { return nil, os.ErrInvalid }
	out := make([]byte, len(value)/2)
	for i := range out {
		hi := indexByte(digits, value[2*i]); lo := indexByte(digits, value[2*i+1])
		if hi < 0 || lo < 0 { return nil, os.ErrInvalid }
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func indexByte(value string, b byte) int {
	for i := range value { if value[i] == b { return i } }
	return -1
}
