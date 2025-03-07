package main

import (
	"context"
	"fmt"
	policyManager "github.com/chris-cmsoft/concom/policy-manager"
	"github.com/chris-cmsoft/concom/runner"
	"github.com/chris-cmsoft/concom/runner/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"time"
)

type CompliancePlugin struct {
	logger hclog.Logger
	data   map[string]interface{}
	config map[string]string
}

// Configure, PrepareForEval, and Eval are called at different times during the plugin execution lifecycle,
// and are responsible for different tasks:
//
// Configure is called on plugin startup. It is primarily used to configure a plugin for its lifetime.
// Here you should store any configurations like usernames and password required by the plugin.
//
// PrepareForEval is called on a scheduled execution of the plugin. Whenever the plugin is going to be run,
// PrepareForEval is called, so it can collect any data necessary for making assertions.
// Here you should run any commands, call any endpoints, or process any reports, which you want to turn into
// compliance findings and observations.
//
// Eval is called multiple times for each scheduled execution. It is responsible for running policies against the
// collected data from PrepareForEval. When a user passed multiple matching policy bundles to the agent, each of them
// will be passed to Eval in sequence. Eval will run against the collected data N times, where N is the amount
// of matching policies passed into the agent.
//
// A user starts the agent, and passes the plugin and any policy bundles.
//
// The agent will:
// * Start the plugin
// * Call Configure() with teh required config
// * Call PrepareForEval() so the plugin can collect the relevant state
// * Call Eval() with the first policy bundles (one by one, in turn),
//   so the plugin can report any violations against the configuration
func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	// Configure is used to set up any configuration needed by this plugin over its lifetime.
	// This will likely only be called once on plugin startup, which may then run for an extended period of time.

	// In this method, you should save any configuration values to your plugin struct, so you can later
	// re-use them in PrepareForEval and Eval.

	l.config = req.Config
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {

	// PrepareForEval is called once on every scheduled plugin execution.
	// Here you should collect the data that should be evaluated with policies or checks.
	// You should not make any observations or findings here. Only collect the data you need for policy / compliance checks.

	// This method does most of the heavy lifting for your plugin.
	// Here are a few examples of when it will be used:
	//   Local SSH Plugin: Fetch the SSH configuration from the local machine
	//   SAST Report Plugin: Convert a SAST sarif report into a usable structure for policies to be written against
	//   Azure VM Label Plugin: Collect all the VMs from the Azure API so they can be evaluated against policies
	l.data = map[string]interface{}{
		"hello": "world",
	}
	return &proto.PrepareForEvalResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest) (*proto.EvalResponse, error) {

	// Eval is used to run policies against the data you've collected in PrepareForEval.
	// Eval will be called N times for every scheduled plugin execution where N is the amount of matching policies
	// passed to the agent.

	// When a user passes multiple policy bundles to the agent, each will be passed to Eval in turn to run against the
	// same data collected in PrepareForEval.

	ctx := context.TODO()
	start_time := time.Now().Format(time.RFC3339)

	// The Policy Manager aggregates much of the policy execution and output structuring.
	results, err := policyManager.
		New(ctx, l.logger, request.BundlePath).
		Execute(ctx, "compliance_plugin", l.data)

	if err != nil {
		return &proto.EvalResponse{}, err
	}

	response := runner.NewCallableEvalResponse()

	for _, result := range results {

		// There are no violations reported from the policies.
		// We'll send the observation back to the agent
		if len(result.Violations) == 0 {
			response.AddObservation(&proto.Observation{
				Id:          uuid.New().String(),
				Title:       "The plugin succeeded. No compliance issues to report.",
				Description: "The plugin policies did not return any violations. The configuration is in compliance with policies.",
				Collected:   time.Now().Format(time.RFC3339),
				Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339), // Add one month for the expiration
				RelevantEvidence: []*proto.Evidence{
					{
						Description: fmt.Sprintf("Policy %v was evaluated, and no violations were found on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345"),
					},
				},
			})
		}

		// There are violations in the policy checks.
		// We'll send these observations back to the agent
		if len(result.Violations) > 0 {
			observation := &proto.Observation{
				Id:          uuid.New().String(),
				Title:       fmt.Sprintf("The plugin found violations for policy %s on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345"),
				Description: fmt.Sprintf("Observed %d violation(s) for policy %s within the Plugin on machineId: %s.", len(result.Violations), result.Policy.Package.PurePackage(), "ARN:12345"),
				Collected:   time.Now().Format(time.RFC3339),
				Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339), // Add one month for the expiration
				RelevantEvidence: []*proto.Evidence{
					{
						Description: fmt.Sprintf("Policy %v was evaluated, and %d violations were found on machineId: %s", result.Policy.Package.PurePackage(), len(result.Violations), "ARN:12345"),
					},
				},
			}
			response.AddObservation(observation)

			for _, violation := range result.Violations {
				response.AddFinding(&proto.Finding{
					Id:                  uuid.New().String(),
					Title:               violation.GetString("title", fmt.Sprintf("Validation on %s failed with violation %v", result.Policy.Package.PurePackage(), violation)),
					Description:         violation.GetString("description", ""),
					Remarks:             violation.GetString("remarks", ""),
					RelatedObservations: []string{observation.Id},
				})
			}

		}
	}

	response.AddLogEntry(&proto.LogEntry{
		Title: "Plugin checks completed",
		Start: start_time,
		End:   time.Now().Format(time.RFC3339),
	})

	return response.Result(), err
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
