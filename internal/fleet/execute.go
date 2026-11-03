package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
)

func ExecuteLocal(ctx context.Context, controller adminapi.ManagerController, command Command) CommandResult {
	result := CommandResult{ID: command.ID}
	if controller == nil {
		result.Message = "local tunnel manager is unavailable"
		return result
	}
	switch command.Action {
	case "start", "stop", "restart":
		if err := controller.ServiceAction(ctx, command.Action); err != nil {
			result.Message = err.Error()
			return result
		}
	case "config":
		if err := controller.ApplyConfiguration(ctx, command.Config); err != nil {
			result.Message = err.Error()
			return result
		}
	case "logs":
		logs, err := controller.RecentLogs(ctx)
		if err != nil {
			result.Message = err.Error()
			return result
		}
		result.Logs = logs
	case "setup-status":
		setup, ok := controller.(adminapi.NodeSetupController)
		if !ok {
			result.Message = "local endpoint setup is unavailable"
			return result
		}
		status, err := setup.NodeSetupStatus(ctx)
		if err != nil {
			result.Message = err.Error()
			return result
		}
		result.Message = fmt.Sprintf("%s|%s|%t|%s", status.State, status.Role, status.BundleAvailable, status.Output)
	case "setup-start":
		setup, ok := controller.(adminapi.NodeSetupController)
		if !ok {
			result.Message = "local endpoint setup is unavailable"
			return result
		}
		if err := setup.StartNodeSetup(ctx, command.NodeSetup); err != nil {
			result.Message = err.Error()
			return result
		}
	case "setup-upload":
		setup, ok := controller.(adminapi.NodeSetupController)
		if !ok {
			result.Message = "local endpoint setup is unavailable"
			return result
		}
		if len(command.Bundle) == 0 || len(command.Bundle) > 1<<20 {
			result.Message = "profile bundle must be between 1 byte and 1 MiB"
			return result
		}
		if err := setup.UploadNodeSetupBundle(ctx, command.Bundle); err != nil {
			result.Message = err.Error()
			return result
		}
	case "setup-download":
		setup, ok := controller.(adminapi.NodeSetupController)
		if !ok {
			result.Message = "local endpoint setup is unavailable"
			return result
		}
		bundle, err := setup.ReadNodeSetupBundle(ctx)
		if err != nil {
			result.Message = err.Error()
			return result
		}
		if len(bundle) == 0 || len(bundle) > 1<<20 {
			result.Message = "downloaded profile bundle has an invalid size"
			return result
		}
		result.Bundle = bundle
	default:
		result.Message = "unsupported management operation"
		return result
	}
	result.Success = true
	if result.Message == "" {
		result.Message = strings.TrimSpace(command.Action) + " completed"
	}
	return result
}

var _ = errors.New
