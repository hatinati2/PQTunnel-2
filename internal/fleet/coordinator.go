package fleet

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
)

type DashboardSnapshot struct {
	Gateway adminapi.ManagerSnapshot
	Dialer  NodeSnapshot
}

type Coordinator struct {
	local  adminapi.ManagerController
	broker *Broker
}

func NewCoordinator(local adminapi.ManagerController, broker *Broker) (*Coordinator, error) {
	if local == nil || broker == nil {
		return nil, errors.New("local manager and fleet broker are required")
	}
	if local.ManagementSnapshot().Role != "gateway" {
		return nil, errors.New("central fleet control plane must run on a Gateway manager")
	}
	return &Coordinator{local: local, broker: broker}, nil
}

func (c *Coordinator) Snapshot() DashboardSnapshot {
	return DashboardSnapshot{
		Gateway: c.local.ManagementSnapshot(),
		Dialer:  c.broker.DialerSnapshot(),
	}
}

func (c *Coordinator) CreateInvite() (string, time.Time, error) {
	return c.broker.CreateInvite()
}

func (c *Coordinator) Execute(ctx context.Context, role string, command Command) (CommandResult, error) {
	switch role {
	case "gateway":
		return ExecuteLocal(ctx, c.local, command), nil
	case "dialer":
		return c.broker.Execute(ctx, command)
	default:
		return CommandResult{}, errors.New("unknown server role")
	}
}

func (c *Coordinator) PairNodes(ctx context.Context, publicName string, listenPort int, tcpPorts, udpPorts string) error {
	localSetup, ok := c.local.(adminapi.NodeSetupController)
	if !ok {
		return errors.New("Gateway node setup worker is unavailable; install the Gateway endpoint package first")
	}
	gatewayRequest := adminapi.NodeSetupRequest{
		Operation: "gateway-init", PublicName: publicName,
		ListenPort: listenPort, TCPPorts: tcpPorts, UDPPorts: udpPorts,
	}
	if err := localSetup.StartNodeSetup(ctx, gatewayRequest); err != nil {
		return fmt.Errorf("start Gateway profile generation: %w", err)
	}
	gatewayStatus, err := waitLocalSetup(ctx, localSetup, true)
	if err != nil {
		return fmt.Errorf("Gateway profile generation: %w", err)
	}
	gatewayBundle, err := localSetup.ReadNodeSetupBundle(ctx)
	if err != nil {
		return fmt.Errorf("read Gateway public profile: %w", err)
	}
	if len(gatewayBundle) == 0 || len(gatewayBundle) > 1<<20 {
		return errors.New("Gateway public profile bundle has an invalid size")
	}
	_ = gatewayStatus

	if _, err := c.broker.Execute(ctx, Command{Action: "setup-upload", Bundle: gatewayBundle}); err != nil {
		return fmt.Errorf("send Gateway public profile to Dialer: %w", err)
	}
	if _, err := c.broker.Execute(ctx, Command{
		Action: "setup-start",
		NodeSetup: adminapi.NodeSetupRequest{Operation: "dialer-import-gateway"},
	}); err != nil {
		return fmt.Errorf("start Dialer profile import: %w", err)
	}
	if _, err := waitRemoteSetup(ctx, c.broker, true); err != nil {
		return fmt.Errorf("Dialer profile import: %w", err)
	}
	dialerBundleResult, err := c.broker.Execute(ctx, Command{Action: "setup-download"})
	if err != nil {
		return fmt.Errorf("read Dialer public profile: %w", err)
	}
	if len(dialerBundleResult.Bundle) == 0 || len(dialerBundleResult.Bundle) > 1<<20 {
		return errors.New("Dialer public profile bundle has an invalid size")
	}
	if err := localSetup.UploadNodeSetupBundle(ctx, dialerBundleResult.Bundle); err != nil {
		return fmt.Errorf("stage Dialer public profile on Gateway: %w", err)
	}
	if err := localSetup.StartNodeSetup(ctx, adminapi.NodeSetupRequest{
		Operation: "gateway-import-dialer",
	}); err != nil {
		return fmt.Errorf("start Gateway peer import: %w", err)
	}
	if _, err := waitLocalSetup(ctx, localSetup, false); err != nil {
		return fmt.Errorf("Gateway peer import: %w", err)
	}
	return nil
}

func waitLocalSetup(ctx context.Context, setup adminapi.NodeSetupController, requireBundle bool) (adminapi.NodeSetupStatus, error) {
	for {
		status, err := setup.NodeSetupStatus(ctx)
		if err != nil {
			return status, err
		}
		if status.State == "failed" {
			if status.Output != "" {
				return status, errors.New(status.Output)
			}
			return status, errors.New("setup worker reported failure")
		}
		if status.State == "ready" && (!requireBundle || status.BundleAvailable) {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, errors.New("timed out waiting for local setup worker")
		case <-time.After(2 * time.Second):
		}
	}
}

func waitRemoteSetup(ctx context.Context, broker *Broker, requireBundle bool) (adminapi.NodeSetupStatus, error) {
	for {
		result, err := broker.Execute(ctx, Command{Action: "setup-status"})
		if err != nil {
			return adminapi.NodeSetupStatus{}, err
		}
		if result.SetupStatus == nil {
			return adminapi.NodeSetupStatus{}, errors.New("Dialer returned no setup status")
		}
		status := *result.SetupStatus
		if status.State == "failed" {
			if status.Output != "" {
				return status, errors.New(status.Output)
			}
			return status, errors.New("Dialer setup worker reported failure")
		}
		if status.State == "ready" && (!requireBundle || status.BundleAvailable) {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, errors.New("timed out waiting for Dialer setup worker")
		case <-time.After(2 * time.Second):
		}
	}
}
