package main

import (
	"strings"
	"testing"
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
