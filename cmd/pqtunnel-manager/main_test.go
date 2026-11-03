package main

import "testing"

func TestValidPublicTLSHost(t *testing.T) {
	for _, host := range []string{"control.example.com", "vpn.example.net"} {
		if !validPublicTLSHost(host) { t.Errorf("expected valid public DNS name: %q", host) }
	}
	for _, host := range []string{"", "localhost", "example", "-bad.example.com", "bad-.example.com", "bad..example.com", "https://example.com", "example.com:6100", "bad_name.example.com", "192.168.1.10"} {
		if validPublicTLSHost(host) { t.Errorf("expected invalid public TLS host: %q", host) }
	}
}
