package main

import "testing"

func TestValidPublicHTTPHost(t *testing.T) {
	for _, host := range []string{"control.example.com", "vpn.example.net", "198.51.100.10"} {
		if !validPublicHTTPHost(host) { t.Errorf("expected valid public host: %q", host) }
	}
	for _, host := range []string{"", "localhost", "example", "-bad.example.com", "bad-.example.com", "bad..example.com", "http://example.com", "example.com:6100", "bad_name.example.com", "127.0.0.1", "0.0.0.0"} {
		if validPublicHTTPHost(host) { t.Errorf("expected invalid public host: %q", host) }
	}
}

func TestValidatePublicHTTPListener(t *testing.T) {
	if err := validatePublicHTTPListener("0.0.0.0:6100", "198.51.100.10"); err != nil { t.Fatalf("valid listener rejected: %v", err) }
	for _, address := range []string{"127.0.0.1:6100", "localhost:6100", "0.0.0.0:0", "0.0.0.0:65536"} {
		if err := validatePublicHTTPListener(address, "198.51.100.10"); err == nil { t.Errorf("invalid listener accepted: %q", address) }
	}
}
