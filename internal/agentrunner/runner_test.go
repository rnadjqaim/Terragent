// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package agentrunner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestAutoFixRemediatesPublicIngress(t *testing.T) {
	sourceDir := t.TempDir()
	path := writeTestFile(t, sourceDir, "main.tf", `
resource "aws_security_group" "admin" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)

	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionAutoFix,
		TerraformVersion: "1.13.0",
		SourceDir:        sourceDir,
		PolicyScan:       true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.Decision != "allow" {
		t.Fatalf("unexpected decision %q with findings %#v", run.Decision, run.Findings)
	}
	if len(run.AutoFixes) != 1 || !run.AutoFixes[0].Applied {
		t.Fatalf("unexpected autofixes %#v", run.AutoFixes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "0.0.0.0/0") {
		t.Fatalf("autofix did not remove public cidr: %s", data)
	}
}

func TestStateAuditBlocksProdWithoutRemoteState(t *testing.T) {
	sourceDir := t.TempDir()
	writeTestFile(t, sourceDir, "main.tf", `resource "aws_s3_bucket" "logs" {}`)

	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionStateAudit,
		TerraformVersion: "1.13.0",
		Environment:      "prod",
		SourceDir:        sourceDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.Decision != "block" {
		t.Fatalf("unexpected decision %q", run.Decision)
	}
	if len(run.Findings) != 1 || run.Findings[0].Code != "remote_state_missing" {
		t.Fatalf("unexpected findings %#v", run.Findings)
	}
}

func TestIACAIPromptRunsAutofixAndStateAudit(t *testing.T) {
	sourceDir := t.TempDir()
	writeTestFile(t, sourceDir, "main.tf", `
terraform {
  backend "s3" {
    bucket         = "state"
    key            = "prod/app.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "locks"
  }
}

resource "aws_security_group" "admin" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)

	run, err := NewRunner().Run(context.Background(), Request{
		Action:           ActionIACAI,
		TerraformVersion: "1.13.0",
		SourceDir:        sourceDir,
		Prompt:           "fix public access and audit remote state for production",
	})
	if err != nil {
		t.Fatal(err)
	}

	if run.State.Backend != "s3" {
		t.Fatalf("expected s3 state backend, got %#v", run.State)
	}
	if len(run.AutoFixes) == 0 {
		t.Fatal("expected prompt to trigger autofix")
	}
	if run.Decision != "allow" {
		t.Fatalf("unexpected decision %q with findings %#v", run.Decision, run.Findings)
	}
}

func writeTestFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
