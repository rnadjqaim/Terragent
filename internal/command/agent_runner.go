// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package command

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/internal/agentrunner"
)

// AgentRunnerCommand is an experimental command for sending Terraform work to
// a trusted runner instead of executing directly on the caller's machine.
type AgentRunnerCommand struct {
	Meta
}

func (c *AgentRunnerCommand) Run(args []string) int {
	args = c.Meta.process(args)
	if len(args) == 0 {
		c.Ui.Output(c.Help())
		return 0
	}

	action := agentrunner.Action(args[0])
	switch action {
	case agentrunner.ActionPlan, agentrunner.ActionApply, agentrunner.ActionCheckVersions:
	default:
		c.Ui.Error(fmt.Sprintf("unknown agent-runner subcommand %q", args[0]))
		c.Ui.Error(c.Help())
		return 1
	}

	req, jsonOutput, err := c.parseRequest(action, args[1:])
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	run, err := agentrunner.NewRunner().Run(c.CommandContext(), req)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if jsonOutput {
		c.renderJSON(run)
	} else {
		c.renderRun(run)
	}
	if run.Decision == "block" {
		return 1
	}
	return 0
}

func (c *AgentRunnerCommand) parseRequest(action agentrunner.Action, args []string) (agentrunner.Request, bool, error) {
	flags := flag.NewFlagSet("agent-runner "+string(action), flag.ContinueOnError)

	req := agentrunner.Request{Action: action}
	var jsonOutput bool
	flags.StringVar(&req.Workspace, "workspace", "default", "workspace id")
	flags.StringVar(&req.Environment, "env", "dev", "environment name")
	flags.StringVar(&req.Actor, "actor", "", "actor name")
	flags.StringVar(&req.SourceDir, "source", ".", "source directory")
	flags.StringVar(&req.Reason, "reason", "", "run reason")
	flags.StringVar(&req.TerraformVersion, "terraform-version", "1.13.0", "terraform version")
	flags.StringVar(&req.ProviderVersion, "aws-provider-version", "", "aws provider version")
	flags.StringVar(&req.ModuleVersion, "module-version", "", "platform module version")
	flags.StringVar(&req.ApprovedPlanID, "approved-plan-id", "", "approved plan id for apply")
	flags.BoolVar(&req.PolicyScan, "policy-scan", false, "scan terraform source for security policy findings")
	flags.BoolVar(&jsonOutput, "json", false, "render machine-readable json output")

	if err := flags.Parse(args); err != nil {
		return agentrunner.Request{}, false, err
	}
	if len(flags.Args()) != 0 {
		return agentrunner.Request{}, false, fmt.Errorf("unexpected argument %q", flags.Args()[0])
	}
	return req, jsonOutput, nil
}

func (c *AgentRunnerCommand) renderRun(run agentrunner.Run) {
	c.Ui.Output(fmt.Sprintf("agent runner run: %s", run.ID))
	c.Ui.Output(fmt.Sprintf("status: %s", run.Status))
	c.Ui.Output(fmt.Sprintf("decision: %s", run.Decision))
	c.Ui.Output(fmt.Sprintf("risk: %s", run.Risk))
	if run.PlanID != "" {
		c.Ui.Output(fmt.Sprintf("plan id: %s", run.PlanID))
	}
	if run.BlastRadius.FilesScanned > 0 {
		c.Ui.Output(fmt.Sprintf("blast radius: files=%d resources=%d security=%d secrets=%d protected=%d",
			run.BlastRadius.FilesScanned,
			run.BlastRadius.ResourcesObserved,
			run.BlastRadius.SecurityFindings,
			run.BlastRadius.SecretsFound,
			run.BlastRadius.ProtectedFindings,
		))
	}

	if len(run.Events) > 0 {
		c.Ui.Output("")
		c.Ui.Output("events:")
		for _, event := range run.Events {
			c.Ui.Output(fmt.Sprintf("  %02d %-10s %-5s %s", event.Sequence, event.Phase, event.Level, event.Message))
		}
	}

	if len(run.Deprecations) > 0 {
		c.Ui.Output("")
		c.Ui.Output("deprecations:")
		for _, notice := range run.Deprecations {
			line := fmt.Sprintf("  [%s] %s %s -> %s", notice.Severity, notice.Subject, notice.CurrentVersion, notice.RecommendedVersion)
			if notice.Deadline != "" {
				line += fmt.Sprintf(" deadline=%s", notice.Deadline)
			}
			c.Ui.Output(line)
			if notice.Message != "" {
				c.Ui.Output(fmt.Sprintf("       %s", notice.Message))
			}
		}
	}

	if len(run.Findings) > 0 {
		c.Ui.Output("")
		c.Ui.Output("findings:")
		for _, finding := range run.Findings {
			line := fmt.Sprintf("  [%s] %s: %s", finding.Severity, finding.Code, finding.Message)
			if finding.File != "" {
				line += fmt.Sprintf(" file=%s", finding.File)
			}
			c.Ui.Output(line)
		}
	}
}

func (c *AgentRunnerCommand) renderJSON(run agentrunner.Run) {
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		c.Ui.Error(err.Error())
		return
	}
	c.Ui.Output(string(data))
}

func (c *AgentRunnerCommand) Help() string {
	return strings.TrimSpace(`
Usage: terraform agent-runner <subcommand> [options]

  Send Terraform work to a trusted runner over RPC.

Subcommands:

  plan             create a remote plan run
  apply            apply an approved plan run
  check-versions   check terraform/provider/module lifecycle rules

Common options:

  -workspace=NAME
  -env=NAME
  -actor=NAME
  -source=DIR
  -terraform-version=VERSION
  -aws-provider-version=VERSION
  -module-version=VERSION
  -approved-plan-id=ID
  -policy-scan
  -json

Examples:

  terraform agent-runner plan -workspace=payments-prod -module-version=2.3.1
  terraform agent-runner plan -source=infra -policy-scan -json
  terraform agent-runner apply -workspace=payments-prod -approved-plan-id=plan-123
  terraform agent-runner check-versions -terraform-version=1.9.0
`)
}

func (c *AgentRunnerCommand) Synopsis() string {
	return "Run Terraform through an experimental RPC agent"
}

type uiErrorWriter struct {
	ui interface {
		Error(string)
	}
}

func (w *uiErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		w.ui.Error(msg)
	}
	return len(p), nil
}
