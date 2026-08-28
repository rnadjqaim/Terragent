// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package agentrunner

import (
	"context"
	"testing"
)

func TestRunnerPlanWarnsForDeprecatedModule(t *testing.T) {
	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionPlan,
		Workspace:        "payments-prod",
		TerraformVersion: "1.13.0",
		ModuleVersion:    "2.3.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.Status != "completed" {
		t.Fatalf("unexpected status %q", run.Status)
	}
	if run.Decision != "warn" {
		t.Fatalf("unexpected decision %q", run.Decision)
	}
	if run.PlanID == "" {
		t.Fatal("expected plan id")
	}
	if len(run.Deprecations) != 1 {
		t.Fatalf("expected one deprecation, got %d", len(run.Deprecations))
	}
}

func TestRunnerBlocksOldTerraformVersion(t *testing.T) {
	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionPlan,
		Workspace:        "payments-prod",
		TerraformVersion: "1.9.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.Status != "blocked" {
		t.Fatalf("unexpected status %q", run.Status)
	}
	if run.Decision != "block" {
		t.Fatalf("unexpected decision %q", run.Decision)
	}
}

func TestRunnerBlocksApplyWithoutApprovedPlan(t *testing.T) {
	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionApply,
		Workspace:        "payments-prod",
		TerraformVersion: "1.13.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.Decision != "block" {
		t.Fatalf("unexpected decision %q", run.Decision)
	}
	if len(run.Findings) != 1 || run.Findings[0].Code != "missing_approved_plan" {
		t.Fatalf("unexpected findings %#v", run.Findings)
	}
}
