package main

import (
	"strings"
	"testing"

	"github.com/hatinati2/PQTunnel-2/internal/fleet"
)

func TestValidateBaseURLRequiresHTTPSAndSecretPath(t *testing.T) {
	path := "/" + strings.Repeat("a", 64)
	if _, err := validateBaseURL("http://gateway.example.test:6100" + path); err == nil {
		t.Fatal("plaintext HTTP control URL was accepted")
	}
	if _, err := validateBaseURL("https://gateway.example.test:6100/not-secret"); err == nil {
		t.Fatal("control URL without a 256-bit path was accepted")
	}
	got, err := validateBaseURL("https://gateway.example.test:6100" + path)
	if err != nil { t.Fatal(err) }
	if got != "https://gateway.example.test:6100"+path {
		t.Fatalf("normalized URL = %q", got)
	}
}


func TestAgentConfigPersistsSequenceAndCommandResult(t *testing.T) {
	path := t.TempDir() + "/agent.json"
	cfg := agentConfig{
		BaseURL: "https://gateway.example.test:6100/" + strings.Repeat("a", 64),
		NodeID: strings.Repeat("b", 32), Name: "dialer-test", Key: strings.Repeat("c", 64),
		Sequence: 1234567, LastCommandID: strings.Repeat("d", 32),
		LastResult: &fleet.CommandResult{ID: strings.Repeat("d", 32), Success: true, Message: "done"},
	}
	if err := writeConfig(path, cfg); err != nil { t.Fatal(err) }
	loaded, err := readConfig(path)
	if err != nil { t.Fatal(err) }
	if loaded.Sequence != cfg.Sequence || loaded.LastCommandID != cfg.LastCommandID || loaded.LastResult == nil || loaded.LastResult.Message != "done" {
		t.Fatalf("persistent state did not round-trip: %#v", loaded)
	}
}

func TestRecoverInterruptedCommandNeverSchedulesReplay(t *testing.T) {
	path := t.TempDir() + "/agent.json"
	cfg := agentConfig{
		BaseURL: "https://gateway.example.test:6100/" + strings.Repeat("a", 64),
		NodeID: strings.Repeat("b", 32), Name: "dialer-test", Key: strings.Repeat("c", 64),
		InProgressCommandID: strings.Repeat("d", 32),
	}
	if err := writeConfig(path, cfg); err != nil { t.Fatal(err) }
	loaded, err := readConfig(path)
	if err != nil { t.Fatal(err) }
	if err := recoverInterruptedCommand(&loaded); err != nil { t.Fatal(err) }
	reloaded, err := readConfig(path)
	if err != nil { t.Fatal(err) }
	if reloaded.InProgressCommandID != "" || reloaded.LastCommandID != cfg.InProgressCommandID || reloaded.LastResult == nil || reloaded.LastResult.Success {
		t.Fatalf("interrupted command was not safely marked indeterminate: %#v", reloaded)
	}
	if !strings.Contains(reloaded.LastResult.Message, "was not replayed") {
		t.Fatalf("recovery message does not explain no-replay policy: %q", reloaded.LastResult.Message)
	}
}
