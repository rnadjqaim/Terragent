// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package agentrunner

import (
	"context"
	"os"
	"path/filepath"
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
	if run.Risk != "medium" {
		t.Fatalf("unexpected risk %q", run.Risk)
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
	if run.Risk != "critical" {
		t.Fatalf("unexpected risk %q", run.Risk)
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

func TestRunnerBlocksPublicSSHPolicyFinding(t *testing.T) {
	sourceDir := t.TempDir()
	writeTestFile(t, sourceDir, "main.tf", `
resource "aws_security_group" "admin" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)

	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionPlan,
		Workspace:        "payments-prod",
		TerraformVersion: "1.13.0",
		SourceDir:        sourceDir,
		PolicyScan:       true,
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
	if run.Risk != "critical" {
		t.Fatalf("unexpected risk %q", run.Risk)
	}
	if run.PlanID != "" {
		t.Fatalf("blocked run should not create a plan id, got %q", run.PlanID)
	}
	if len(run.Findings) != 1 || run.Findings[0].Code != "public_ssh" {
		t.Fatalf("unexpected findings %#v", run.Findings)
	}
	if run.BlastRadius.SecurityFindings != 1 {
		t.Fatalf("unexpected blast radius %#v", run.BlastRadius)
	}
	for _, event := range run.Events {
		if event.Phase == "plan" {
			t.Fatal("blocked run should stop before scheduling plan")
		}
	}
}

func TestRunnerWarnsForRDSWithoutExplicitEncryption(t *testing.T) {
	sourceDir := t.TempDir()
	writeTestFile(t, sourceDir, "main.tf", `
resource "aws_db_instance" "app" {
  instance_class = "db.t3.micro"
}
`)

	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionPlan,
		Workspace:        "payments-prod",
		TerraformVersion: "1.13.0",
		SourceDir:        sourceDir,
		PolicyScan:       true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.Decision != "warn" {
		t.Fatalf("unexpected decision %q", run.Decision)
	}
	if run.Risk != "medium" {
		t.Fatalf("unexpected risk %q", run.Risk)
	}
	if len(run.Findings) != 1 || run.Findings[0].Code != "rds_encryption_unknown" {
		t.Fatalf("unexpected findings %#v", run.Findings)
	}
}

func writeTestFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
