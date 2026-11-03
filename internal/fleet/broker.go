package fleet

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
)

type pendingCall struct {
	command Command
	result  chan CommandResult
}

type nodeState struct {
	ID           string
	Name         string
	Key          []byte
	LastSequence int64
	LastSeen     time.Time
	Snapshot     adminapi.ManagerSnapshot
	Pending      *pendingCall
}

type storedNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type storedState struct {
	Version int          `json:"version"`
	Nodes   []storedNode `json:"nodes"`
}

type Broker struct {
	mu         sync.Mutex
	statePath  string
	nodes      map[string]*nodeState
	invite     string
	inviteTill time.Time
}

var (
	nodeIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$`)
)

func NewBroker(statePath string) (*Broker, error) {
	if statePath == "" || !filepath.IsAbs(statePath) {
		return nil, errors.New("fleet state path must be absolute")
	}
	b := &Broker{statePath: statePath, nodes: make(map[string]*nodeState)}
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Broker) load() error {
	info, err := os.Lstat(b.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect fleet state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("fleet state must be a regular root-only file")
	}
	data, err := os.ReadFile(b.statePath)
	if err != nil {
		return fmt.Errorf("read fleet state: %w", err)
	}
	var state storedState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 {
		return errors.New("fleet state file is invalid or uses an unsupported version")
	}
	for _, item := range state.Nodes {
		key, err := hex.DecodeString(item.Key)
		if err != nil || len(key) != 32 || !nodeIDPattern.MatchString(item.ID) || !nodeNamePattern.MatchString(item.Name) {
			return errors.New("fleet state contains an invalid node record")
		}
		b.nodes[item.ID] = &nodeState{ID: item.ID, Name: item.Name, Key: key}
	}
	return nil
}

func (b *Broker) persistLocked() error {
	state := storedState{Version: 1}
	for _, node := range b.nodes {
		state.Nodes = append(state.Nodes, storedNode{
			ID: node.ID, Name: node.Name, Key: hex.EncodeToString(node.Key),
		})
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(b.statePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".fleet-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, b.statePath); err != nil {
		return err
	}
	ok = true
	return nil
}

// CreateInvite creates a one-use Dialer enrollment credential. It expires after
// fifteen minutes and is invalidated as soon as one Dialer has enrolled.
func (b *Broker) CreateInvite() (string, time.Time, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(15 * time.Minute)
	b.mu.Lock()
	b.invite, b.inviteTill = token, expires
	b.mu.Unlock()
	return token, expires, nil
}

func (b *Broker) Enroll(req EnrollRequest) (EnrollResponse, error) {
	if !nodeIDPattern.MatchString(req.NodeID) || !nodeNamePattern.MatchString(req.Name) || req.Role != "dialer" || len(req.Token) != 64 {
		return EnrollResponse{}, errors.New("invalid enrollment request")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.invite == "" || time.Now().After(b.inviteTill) ||
		subtle.ConstantTimeCompare([]byte(req.Token), []byte(b.invite)) != 1 {
		return EnrollResponse{}, errors.New("enrollment token is invalid or expired")
	}
	if _, exists := b.nodes[req.NodeID]; exists {
		return EnrollResponse{}, errors.New("this Dialer is already registered")
	}
	keyHex, err := randomHex(32)
	if err != nil {
		return EnrollResponse{}, err
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return EnrollResponse{}, err
	}
	credentials := Credentials{NodeID: req.NodeID, Key: keyHex}
	response, err := newEnrollmentReply(req.Token, req.PublicKey, credentials)
	if err != nil {
		return EnrollResponse{}, err
	}
	b.nodes[req.NodeID] = &nodeState{ID: req.NodeID, Name: req.Name, Key: key}
	if err := b.persistLocked(); err != nil {
		delete(b.nodes, req.NodeID)
		return EnrollResponse{}, errors.New("could not securely save enrolled Dialer credentials")
	}
	b.invite, b.inviteTill = "", time.Time{}
	return response, nil
}

func (b *Broker) Poll(envelope Envelope) (Envelope, error) {
	if !nodeIDPattern.MatchString(envelope.NodeID) {
		return Envelope{}, errors.New("unknown agent")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	node := b.nodes[envelope.NodeID]
	if node == nil {
		return Envelope{}, errors.New("unknown agent")
	}
	var request AgentRequest
	if err := openEnvelope(node.Key, envelope, &request); err != nil {
		return Envelope{}, err
	}
	now := time.Now()
	if request.Timestamp < now.Add(-agentFreshnessWindow).Unix() || request.Timestamp > now.Add(agentFreshnessWindow).Unix() ||
		request.Sequence <= 0 || request.Sequence <= node.LastSequence {
		return Envelope{}, errors.New("stale or replayed agent message")
	}
	if request.Snapshot.Role != "dialer" {
		return Envelope{}, errors.New("agent role mismatch")
	}
	node.LastSequence = request.Sequence
	node.LastSeen = now
	node.Snapshot = request.Snapshot

	response := AgentResponse{}
	if request.Result != nil && node.Pending != nil && request.Result.ID == node.Pending.command.ID {
		result := *request.Result
		response.AckID = result.ID
		pending := node.Pending
		node.Pending = nil
		select {
		case pending.result <- result:
		default:
		}
		close(pending.result)
	}
	if node.Pending != nil {
		copyCommand := node.Pending.command
		response.Command = &copyCommand
	}
	sealed, err := seal(node.Key, response)
	if err != nil {
		return Envelope{}, err
	}
	sealed.NodeID = node.ID
	return sealed, nil
}

func (b *Broker) DialerSnapshot() NodeSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	var result NodeSnapshot
	for _, node := range b.nodes {
		connected := !node.LastSeen.IsZero() && time.Since(node.LastSeen) <= agentOnlineWindow
		snapshot := node.Snapshot
		snapshot.Peers = append([]adminapi.Peer(nil), node.Snapshot.Peers...)
		if result.ID == "" || node.LastSeen.After(result.LastSeen) {
			result = NodeSnapshot{
				ID: node.ID, Name: node.Name, Role: "dialer", Connected: connected,
				LastSeen: node.LastSeen, Snapshot: snapshot,
			}
		}
	}
	return result
}

func (b *Broker) Execute(ctx context.Context, command Command) (CommandResult, error) {
	if command.Action == "" {
		return CommandResult{}, errors.New("remote action is required")
	}
	id, err := randomHex(16)
	if err != nil {
		return CommandResult{}, err
	}
	command.ID = id
	b.mu.Lock()
	var node *nodeState
	for _, candidate := range b.nodes {
		node = candidate
		break
	}
	if node == nil {
		b.mu.Unlock()
		return CommandResult{}, errors.New("no Dialer is enrolled")
	}
	if node.LastSeen.IsZero() || time.Since(node.LastSeen) > agentOnlineWindow {
		b.mu.Unlock()
		return CommandResult{}, errors.New("Dialer agent is offline; it must reconnect before remote management")
	}
	if node.Pending != nil {
		if time.Since(node.LastSeen) > 30*time.Second {
			node.Pending = nil
		} else {
			b.mu.Unlock()
			return CommandResult{}, errors.New("another remote operation is still pending")
		}
	}
	resultCh := make(chan CommandResult, 1)
	node.Pending = &pendingCall{command: command, result: resultCh}
	b.mu.Unlock()

	select {
	case result, ok := <-resultCh:
		if !ok {
			return CommandResult{}, errors.New("remote operation ended without a result")
		}
		if !result.Success {
			if result.Message == "" {
				result.Message = "remote operation failed"
			}
			return result, errors.New(result.Message)
		}
		return result, nil
	case <-ctx.Done():
		return CommandResult{}, errors.New("remote operation timed out or was cancelled; check Dialer status before retrying")
	}
}

func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/enroll", b.handleEnroll)
	mux.HandleFunc("/agent/poll", b.handlePoll)
	return mux
}

func (b *Broker) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var request EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	response, err := b.Enroll(request)
	if err != nil {
		http.Error(w, "enrollment rejected", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (b *Broker) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentMessageBytes)
	var envelope Envelope
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		http.Error(w, "invalid agent message", http.StatusBadRequest)
		return
	}
	response, err := b.Poll(envelope)
	if err != nil {
		http.Error(w, "agent message rejected", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// ReadJSONBody is shared with the agent command-line client and enforces a
// bounded response body before decoding.
func ReadJSONBody(r io.Reader, limit int64, dst any) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("response body exceeds size limit")
	}
	return json.Unmarshal(data, dst)
}

var _ = strings.TrimSpace
