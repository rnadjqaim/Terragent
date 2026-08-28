// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package agentrunner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	Action           Action `json:"action"`
	Workspace        string `json:"workspace"`
	Environment      string `json:"environment"`
	Actor            string `json:"actor"`
	SourceDir        string `json:"source_dir"`
	Reason           string `json:"reason"`
	TerraformVersion string `json:"terraform_version"`
	ProviderVersion  string `json:"provider_version"`
	ModuleVersion    string `json:"module_version"`
	ApprovedPlanID   string `json:"approved_plan_id"`
	PolicyScan       bool   `json:"policy_scan"`
}

type Run struct {
	ID           string        `json:"id"`
	Status       string        `json:"status"`
	Decision     string        `json:"decision"`
	Risk         string        `json:"risk"`
	PlanID       string        `json:"plan_id,omitempty"`
	BlastRadius  BlastRadius   `json:"blast_radius"`
	Events       []Event       `json:"events"`
	Findings     []Finding     `json:"findings,omitempty"`
	Deprecations []Deprecation `json:"deprecations,omitempty"`
}

type Event struct {
	Sequence int64  `json:"sequence"`
	Phase    string `json:"phase"`
	Level    string `json:"level"`
	Message  string `json:"message"`
}

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Resource string `json:"resource,omitempty"`
	File     string `json:"file,omitempty"`
}

type Deprecation struct {
	Severity           string `json:"severity"`
	Subject            string `json:"subject"`
	CurrentVersion     string `json:"current_version"`
	RecommendedVersion string `json:"recommended_version"`
	Deadline           string `json:"deadline"`
	Message            string `json:"message"`
}

type BlastRadius struct {
	FilesScanned      int `json:"files_scanned"`
	ResourcesObserved int `json:"resources_observed"`
	SecurityFindings  int `json:"security_findings"`
	SecretsFound      int `json:"secrets_found"`
	ProtectedFindings int `json:"protected_findings"`
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
		Risk:     "low",
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
			run.Risk = maxRisk(run.Risk, "critical")
		} else if run.Decision == "allow" {
			run.Decision = "warn"
			run.Risk = maxRisk(run.Risk, "medium")
		}
	}

	run.Events = append(run.Events, event(3, "versions", levelForDecision(run.Decision), versionMessage(run.Decision)))

	if req.PolicyScan && req.Action != ActionCheckVersions {
		findings, blastRadius := ScanPolicy(req.SourceDir)
		run.Findings = append(run.Findings, findings...)
		run.BlastRadius = blastRadius
		applyFindings(&run)
		run.Events = append(run.Events, event(4, "policy", levelForDecision(run.Decision), policyMessage(run)))
	}

	switch req.Action {
	case ActionCheckVersions:
		return run, nil
	case ActionPlan:
		if run.Decision == "block" {
			run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", "error", "run blocked by policy"))
			return run, nil
		}
		run.PlanID = fmt.Sprintf("plan-%d", now)
		next := int64(len(run.Events) + 1)
		run.Events = append(run.Events,
			event(next, "lock", "info", "state lock checked"),
			event(next+1, "init", "info", "terraform init scheduled on agent"),
			event(next+2, "validate", "info", "terraform validate scheduled on agent"),
			event(next+3, "plan", "info", fmt.Sprintf("plan artifact prepared as %s", run.PlanID)),
		)
	case ActionApply:
		if req.ApprovedPlanID == "" {
			run.Status = "blocked"
			run.Decision = "block"
			run.Risk = maxRisk(run.Risk, "critical")
			run.Findings = append(run.Findings, Finding{
				Severity: "block",
				Code:     "missing_approved_plan",
				Message:  "apply requires an approved plan id",
			})
			run.Events = append(run.Events, event(int64(len(run.Events)+1), "approval", "error", "approved plan id is missing"))
			return run, nil
		}
		if run.Decision == "block" {
			run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", "error", "run blocked by policy"))
			return run, nil
		}
		next := int64(len(run.Events) + 1)
		run.Events = append(run.Events,
			event(next, "approval", "info", fmt.Sprintf("approved plan %s received", req.ApprovedPlanID)),
			event(next+1, "lock", "info", "state lock acquired"),
			event(next+2, "apply", "info", "terraform apply scheduled on agent"),
		)
	default:
		return Run{}, fmt.Errorf("unknown agent-runner action %q", req.Action)
	}

	run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", levelForDecision(run.Decision), fmt.Sprintf("run decision: %s", run.Decision)))
	return run, nil
}

func ScanPolicy(sourceDir string) ([]Finding, BlastRadius) {
	var findings []Finding
	var blastRadius BlastRadius

	_ = filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			if entry != nil && entry.IsDir() && (entry.Name() == ".terraform" || entry.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if !isTerraformPolicyFile(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		body := strings.ToLower(string(data))
		normalizedBody := strings.Join(strings.Fields(body), " ")
		blastRadius.FilesScanned++
		blastRadius.ResourcesObserved += strings.Count(body, "resource \"")

		if strings.Contains(body, "0.0.0.0/0") && strings.Contains(normalizedBody, "from_port = 22") {
			blastRadius.SecurityFindings++
			findings = append(findings, Finding{
				Severity: "block",
				Code:     "public_ssh",
				Message:  "security group exposes SSH to the internet",
				File:     path,
			})
		}
		if strings.Contains(body, "0.0.0.0/0") && strings.Contains(normalizedBody, "from_port = 3389") {
			blastRadius.SecurityFindings++
			findings = append(findings, Finding{
				Severity: "block",
				Code:     "public_rdp",
				Message:  "security group exposes RDP to the internet",
				File:     path,
			})
		}
		if strings.Contains(body, "acl") && (strings.Contains(body, "public-read") || strings.Contains(body, "public-read-write")) {
			blastRadius.SecurityFindings++
			findings = append(findings, Finding{
				Severity: "block",
				Code:     "public_s3_acl",
				Message:  "s3 acl appears to grant public access",
				File:     path,
			})
		}
		if strings.Contains(body, "aws_db_instance") && !strings.Contains(body, "storage_encrypted") {
			blastRadius.SecurityFindings++
			findings = append(findings, Finding{
				Severity: "warn",
				Code:     "rds_encryption_unknown",
				Message:  "rds instance found without an explicit storage_encrypted setting",
				File:     path,
			})
		}
		if strings.Contains(body, "prevent_destroy = true") {
			blastRadius.ProtectedFindings++
		}
		if looksLikeSecret(body) {
			blastRadius.SecretsFound++
			findings = append(findings, Finding{
				Severity: "block",
				Code:     "secret_in_source",
				Message:  "source contains a value that looks like a secret or private key",
				File:     path,
			})
		}

		return nil
	})

	return findings, blastRadius
}

func isTerraformPolicyFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".tf" || ext == ".tfvars"
}

func looksLikeSecret(body string) bool {
	secretMarkers := []string{
		"aws_secret_access_key",
		"-----begin private key-----",
		"-----begin rsa private key-----",
		"password = \"",
		"token = \"",
		"secret = \"",
	}
	for _, marker := range secretMarkers {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

func applyFindings(run *Run) {
	for _, finding := range run.Findings {
		if finding.Severity == "block" {
			run.Decision = "block"
			run.Status = "blocked"
			run.Risk = maxRisk(run.Risk, "critical")
			continue
		}
		if finding.Severity == "warn" && run.Decision == "allow" {
			run.Decision = "warn"
			run.Risk = maxRisk(run.Risk, "medium")
		}
	}
	if run.BlastRadius.ResourcesObserved > 20 {
		run.Risk = maxRisk(run.Risk, "medium")
	}
}

func policyMessage(run Run) string {
	if len(run.Findings) == 0 {
		return fmt.Sprintf("policy scan passed: %d files, %d resources", run.BlastRadius.FilesScanned, run.BlastRadius.ResourcesObserved)
	}
	return fmt.Sprintf("policy scan found %d findings; risk=%s", len(run.Findings), run.Risk)
}

func maxRisk(current, candidate string) string {
	if riskRank(candidate) > riskRank(current) {
		return candidate
	}
	return current
}

func riskRank(risk string) int {
	switch risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
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
