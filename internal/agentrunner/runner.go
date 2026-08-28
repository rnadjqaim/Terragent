// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package agentrunner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

type Action string

const (
	ActionPlan          Action = "plan"
	ActionApply         Action = "apply"
	ActionCheckVersions Action = "check-versions"
)

type Request struct {
	Action           Action
	Workspace        string
	Environment      string
	Actor            string
	SourceDir        string
	Reason           string
	TerraformVersion string
	ProviderVersion  string
	ModuleVersion    string
	ApprovedPlanID   string
}

type Run struct {
	ID           string
	Status       string
	Decision     string
	PlanID       string
	Events       []Event
	Findings     []Finding
	Deprecations []Deprecation
}

type Event struct {
	Sequence int64
	Phase    string
	Level    string
	Message  string
}

type Finding struct {
	Severity string
	Code     string
	Message  string
}

type Deprecation struct {
	Severity           string
	Subject            string
	CurrentVersion     string
	RecommendedVersion string
	Deadline           string
	Message            string
}

type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Run(ctx context.Context, req Request) (Run, error) {
	select {
	case <-ctx.Done():
		return Run{}, ctx.Err()
	default:
	}

	if req.Workspace == "" {
		req.Workspace = "default"
	}
	if req.Environment == "" {
		req.Environment = "dev"
	}
	if req.Actor == "" {
		req.Actor = os.Getenv("USER")
	}
	if req.Actor == "" {
		req.Actor = "unknown"
	}
	if req.SourceDir == "" {
		req.SourceDir = "."
	}
	if req.TerraformVersion == "" {
		req.TerraformVersion = "1.13.0"
	}

	now := time.Now().UnixNano()
	run := Run{
		ID:       fmt.Sprintf("run-%d", now),
		Status:   "completed",
		Decision: "allow",
	}

	run.Events = append(run.Events,
		event(1, "received", "info", fmt.Sprintf("run accepted for workspace %q", req.Workspace)),
		event(2, "identity", "info", fmt.Sprintf("actor %q requested %s in %s", req.Actor, req.Action, req.Environment)),
	)

	deprecations := CheckDeprecations(req)
	run.Deprecations = deprecations
	for _, notice := range deprecations {
		if notice.Severity == "block" {
			run.Decision = "block"
			run.Status = "blocked"
		} else if run.Decision == "allow" {
			run.Decision = "warn"
		}
	}

	run.Events = append(run.Events, event(3, "versions", levelForDecision(run.Decision), versionMessage(run.Decision)))

	switch req.Action {
	case ActionCheckVersions:
		return run, nil
	case ActionPlan:
		run.PlanID = fmt.Sprintf("plan-%d", now)
		run.Events = append(run.Events,
			event(4, "lock", "info", "state lock checked"),
			event(5, "init", "info", "terraform init scheduled on agent"),
			event(6, "validate", "info", "terraform validate scheduled on agent"),
			event(7, "plan", "info", fmt.Sprintf("plan artifact prepared as %s", run.PlanID)),
		)
	case ActionApply:
		if req.ApprovedPlanID == "" {
			run.Status = "blocked"
			run.Decision = "block"
			run.Findings = append(run.Findings, Finding{
				Severity: "block",
				Code:     "missing_approved_plan",
				Message:  "apply requires an approved plan id",
			})
			run.Events = append(run.Events, event(4, "approval", "error", "approved plan id is missing"))
			return run, nil
		}
		run.Events = append(run.Events,
			event(4, "approval", "info", fmt.Sprintf("approved plan %s received", req.ApprovedPlanID)),
			event(5, "lock", "info", "state lock acquired"),
			event(6, "apply", "info", "terraform apply scheduled on agent"),
		)
	default:
		return Run{}, fmt.Errorf("unknown agent-runner action %q", req.Action)
	}

	if run.Decision == "block" {
		run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", "error", "run blocked by policy"))
		return run, nil
	}
	run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", levelForDecision(run.Decision), fmt.Sprintf("run decision: %s", run.Decision)))
	return run, nil
}

func CheckDeprecations(req Request) []Deprecation {
	var notices []Deprecation

	if versionLess(req.TerraformVersion, "1.10.5") {
		notices = append(notices, Deprecation{
			Severity:           "block",
			Subject:            "terraform",
			CurrentVersion:     req.TerraformVersion,
			RecommendedVersion: "1.13.0",
			Deadline:           "now",
			Message:            "terraform version is below the minimum security version",
		})
	} else if versionLess(req.TerraformVersion, "1.13.0") {
		notices = append(notices, Deprecation{
			Severity:           "warn",
			Subject:            "terraform",
			CurrentVersion:     req.TerraformVersion,
			RecommendedVersion: "1.13.0",
			Deadline:           "2026-12-31",
			Message:            "terraform version is allowed but should be upgraded",
		})
	}

	if req.ProviderVersion != "" && versionLess(req.ProviderVersion, "4.50.0") {
		notices = append(notices, Deprecation{
			Severity:           "block",
			Subject:            "aws provider",
			CurrentVersion:     req.ProviderVersion,
			RecommendedVersion: "5.80.0",
			Deadline:           "now",
			Message:            "provider version is blocked by workspace policy",
		})
	} else if req.ProviderVersion != "" && versionLess(req.ProviderVersion, "5.0.0") {
		notices = append(notices, Deprecation{
			Severity:           "warn",
			Subject:            "aws provider",
			CurrentVersion:     req.ProviderVersion,
			RecommendedVersion: "5.80.0",
			Deadline:           "2026-12-31",
			Message:            "provider version is deprecated",
		})
	}

	if req.ModuleVersion != "" && strings.HasPrefix(req.ModuleVersion, "2.") {
		notices = append(notices, Deprecation{
			Severity:           "warn",
			Subject:            "platform/vpc module",
			CurrentVersion:     req.ModuleVersion,
			RecommendedVersion: "3.1.0",
			Deadline:           "2026-12-31",
			Message:            "module version is deprecated; migrate to platform/network-foundation",
		})
	}

	return notices
}

func event(seq int64, phase, level, msg string) Event {
	return Event{Sequence: seq, Phase: phase, Level: level, Message: msg}
}

func levelForDecision(decision string) string {
	if decision == "block" {
		return "error"
	}
	if decision == "warn" {
		return "warn"
	}
	return "info"
}

func versionMessage(decision string) string {
	if decision == "block" {
		return "version/deprecation check blocked the run"
	}
	if decision == "warn" {
		return "version/deprecation check returned warnings"
	}
	return "version/deprecation check passed"
}

func versionLess(got, want string) bool {
	g := parseVersion(got)
	w := parseVersion(want)
	for i := 0; i < 3; i++ {
		if g[i] < w[i] {
			return true
		}
		if g[i] > w[i] {
			return false
		}
	}
	return false
}

func parseVersion(v string) [3]int {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	for i := 0; i < len(parts) && i < 3; i++ {
		for _, ch := range parts[i] {
			if ch < '0' || ch > '9' {
				break
			}
			out[i] = out[i]*10 + int(ch-'0')
		}
	}
	return out
}
