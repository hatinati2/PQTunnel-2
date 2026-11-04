package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminui"
	"github.com/hatinati2/PQTunnel-2/internal/fleet"
	"github.com/hatinati2/PQTunnel-2/internal/fleetui"
	"github.com/hatinati2/PQTunnel-2/internal/manager"
	"github.com/hatinati2/PQTunnel-2/internal/speedtest"
)

func main() {
	roleText := os.Getenv("PQTUNNEL_MANAGER_ROLE")
	role := manager.Role(roleText)
	if role != manager.RoleGateway && role != manager.RoleDialer {
		fatalIf(fmt.Errorf("PQTUNNEL_MANAGER_ROLE must be gateway or dialer"))
	}
	listen := envString("PQTUNNEL_MANAGER_LISTEN", "127.0.0.1:9091")
	publicHost := os.Getenv("PQTUNNEL_MANAGER_PUBLIC_HOST")
	isLoopback := adminui.ValidateLoopbackAddress(listen) == nil
	allowInsecurePublicHTTP := strings.EqualFold(os.Getenv("PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP"), "true")
	pathToken := os.Getenv("PQTUNNEL_MANAGER_PATH_TOKEN")
	if !isLoopback {
		if !allowInsecurePublicHTTP {
			fatalIf(errors.New("public HTTP requires explicit PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=true"))
		}
		if pathToken == "" {
			fatalIf(fmt.Errorf("public manager listeners require a per-install PQTUNNEL_MANAGER_PATH_TOKEN with 64 lowercase hexadecimal characters"))
		}
		fatalIf(validatePublicHTTPListener(listen, publicHost))
	}
	token := os.Getenv("PQTUNNEL_MANAGER_TOKEN")
	if len([]byte(token)) < 32 {
		fatalIf(fmt.Errorf("PQTUNNEL_MANAGER_TOKEN must contain at least 32 bytes"))
	}
	controlSocket := "/run/pqtunnel/control.sock"
	if role == manager.RoleDialer {
		controlSocket = "/run/pqtunnel/client-control.sock"
	}
	controller, err := manager.New(manager.Options{
		Role: role,
		ConfigPath: manager.ConfigPathForRole(role),
		BackupDir: "/var/lib/pqtunnel-manager/backups",
		IPCSocket: controlSocket,
		SpeedTestPeer: os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_PEER"),
		SpeedTestToken: os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_TOKEN"),
		EndpointMode: os.Getenv("PQTUNNEL_MANAGER_ENDPOINT_MODE"),
	})
	fatalIf(err)
	var panelHandler http.Handler
	if role == manager.RoleGateway {
		statePath := envString("PQTUNNEL_FLEET_STATE", "/var/lib/pqtunnel-manager/fleet-state.json")
		broker, err := fleet.NewBroker(statePath)
		fatalIf(err)
		coordinator, err := fleet.NewCoordinator(controller, broker)
		fatalIf(err)
		handler, err := fleetui.New(
			token,
			coordinator,
			os.Getenv("PQTUNNEL_MANAGER_PUBLIC_URL"),
			os.Getenv("PQTUNNEL_MANAGER_INSTALL_REF"),
		)
		fatalIf(err)
		mux := http.NewServeMux()
		mux.Handle("/agent/", broker.Handler())
		mux.Handle("/", handler)
		panelHandler = mux
	} else {
		handler, err := adminui.NewWithPublicAccess(token, controller, publicHost, false)
		fatalIf(err)
		panelHandler = handler
	}
	if pathToken != "" {
		panelHandler, err = adminui.WithPathToken(pathToken, panelHandler)
		fatalIf(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agentListen := os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_LISTEN")
	agentToken := os.Getenv("PQTUNNEL_MANAGER_SPEEDTEST_TOKEN")
	if agentListen != "" || agentToken != "" {
		// Misconfigured optional benchmarking must not take the management UI
		// offline; keep the panel available so the operator can repair config.
		if agentListen == "" || len([]byte(agentToken)) < 32 {
			fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent disabled: set both the private listen address and a separate token of at least 32 bytes")
		} else if err := controller.ValidateSpeedTestListener(agentListen, agentToken); err != nil {
			fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent disabled:", err)
		} else {
			go func() {
				if err := speedtest.ServeAgent(ctx, agentListen, agentToken); err != nil && ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "pqtunnel-manager: speed-test agent:", err)
				}
			}()
		}
	}
	listener, err := net.Listen("tcp", listen)
	fatalIf(err)
	server := &http.Server{
		Addr: listen, Handler: panelHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second,
		WriteTimeout: 310 * time.Second,
		IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 8 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if isLoopback {
		fmt.Printf("PQTunnel manager (%s) available at http://%s/ (loopback-only; token protected)\n", role, listen)
	} else {
		panelURL := os.Getenv("PQTUNNEL_MANAGER_PUBLIC_URL")
		if panelURL == "" {
			_, panelPort, _ := net.SplitHostPort(listen)
			panelURL = fmt.Sprintf("http://%s:%s/%s/", publicHost, panelPort, pathToken)
		}
		fmt.Printf("PQTunnel manager (%s) available at %s (PLAINTEXT HTTP; restrict firewall to trusted IPs)\n", role, panelURL)
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalIf(err)
	}
}

func validPublicHTTPHost(host string) bool {
	if host == "" || len(host) > 253 { return false }
	if ip, err := netip.ParseAddr(host); err == nil {
		return !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 { return false }
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return false }
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') { return false }
		}
	}
	return true
}

func validatePublicHTTPListener(address, publicHost string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil { return fmt.Errorf("public manager listen address must be IP:port (for example 0.0.0.0:6100)") }
	bindIP, err := netip.ParseAddr(host)
	if err != nil { return fmt.Errorf("public manager listener must use a literal IP or wildcard address") }
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 { return fmt.Errorf("public manager listen port must be between 1 and 65535") }
	if !validPublicHTTPHost(publicHost) { return fmt.Errorf("PQTUNNEL_MANAGER_PUBLIC_HOST must be a public DNS hostname or IP address") }
	if !bindIP.IsUnspecified() { return fmt.Errorf("bind the public HTTP listener to 0.0.0.0:%s", port) }
	return nil
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqtunnel-manager:", err)
		os.Exit(1)
	}
}
