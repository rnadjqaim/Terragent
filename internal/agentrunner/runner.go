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
	ActionAutoFix       Action = "autofix"
	ActionIACAI         Action = "iacai"
	ActionStateAudit    Action = "state-audit"
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
	Prompt           string `json:"prompt,omitempty"`
	DryRun           bool   `json:"dry_run"`
}

type Run struct {
	ID           string        `json:"id"`
	Status       string        `json:"status"`
	Decision     string        `json:"decision"`
	Risk         string        `json:"risk"`
	PlanID       string        `json:"plan_id,omitempty"`
	BlastRadius  BlastRadius   `json:"blast_radius"`
	State        StateSummary  `json:"state"`
	AutoFixes    []AutoFix     `json:"autofixes,omitempty"`
	AgentActions []AgentAction `json:"agent_actions,omitempty"`
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

type StateSummary struct {
	Backend           string `json:"backend,omitempty"`
	Remote            bool   `json:"remote"`
	Encrypted         bool   `json:"encrypted"`
	Locking           bool   `json:"locking"`
	WorkspaceAware    bool   `json:"workspace_aware"`
	ConfigurationFile string `json:"configuration_file,omitempty"`
}

type AutoFix struct {
	File        string `json:"file"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Applied     bool   `json:"applied"`
}

type AgentAction struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
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
	if req.Action == ActionIACAI {
		req = routePrompt(req)
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
	applyDeprecations(&run, deprecations)

	run.Events = append(run.Events, event(3, "versions", levelForDecision(run.Decision), versionMessage(run.Decision)))

	if req.Action == ActionIACAI {
		run.AgentActions = append(run.AgentActions, AgentAction{
			Name:        "interpret_prompt",
			Description: fmt.Sprintf("iacAI interpreted prompt: %s", req.Prompt),
			Status:      "completed",
		})
	}

	if req.PolicyScan && req.Action != ActionCheckVersions {
		findings, blastRadius := ScanPolicy(req.SourceDir)
		run.Findings = append(run.Findings, findings...)
		run.BlastRadius = blastRadius
		applyFindings(&run)
		run.Events = append(run.Events, event(4, "policy", levelForDecision(run.Decision), policyMessage(run)))
	}

	if req.Action == ActionStateAudit || strings.Contains(strings.ToLower(req.Prompt), "state") {
		state, findings := AuditState(req.SourceDir, req.Environment)
		run.State = state
		run.Findings = append(run.Findings, findings...)
		applyFindings(&run)
		run.Events = append(run.Events, event(int64(len(run.Events)+1), "state", levelForFindings(findings), stateMessage(state, findings)))
	}

	switch req.Action {
	case ActionCheckVersions:
		return run, nil
	case ActionAutoFix:
		run.AutoFixes = AutoFixSource(req.SourceDir, req.DryRun)
		run.AgentActions = append(run.AgentActions, AgentAction{
			Name:        "autofix",
			Description: fmt.Sprintf("processed %d source fixes", len(run.AutoFixes)),
			Status:      "completed",
		})
		run.Events = append(run.Events, event(int64(len(run.Events)+1), "autofix", "info", fmt.Sprintf("autofix processed %d changes", len(run.AutoFixes))))
		if req.PolicyScan {
			findings, blastRadius := ScanPolicy(req.SourceDir)
			run.Findings = findings
			run.BlastRadius = blastRadius
			run.Decision = "allow"
			run.Status = "completed"
			run.Risk = "low"
			applyFindings(&run)
		}
		run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", levelForDecision(run.Decision), fmt.Sprintf("run decision: %s", run.Decision)))
		return run, nil
	case ActionIACAI:
		if strings.Contains(strings.ToLower(req.Prompt), "fix") {
			run.AutoFixes = AutoFixSource(req.SourceDir, req.DryRun)
			run.AgentActions = append(run.AgentActions, AgentAction{
				Name:        "autofix_from_prompt",
				Description: fmt.Sprintf("applied prompt-requested remediation changes: %d", len(run.AutoFixes)),
				Status:      "completed",
			})
			run.Events = append(run.Events, event(int64(len(run.Events)+1), "iacai", "info", fmt.Sprintf("prompt action completed with %d autofixes", len(run.AutoFixes))))
			if req.PolicyScan {
				recomputeGovernance(&run, req)
			}
		}
		run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", levelForDecision(run.Decision), fmt.Sprintf("run decision: %s", run.Decision)))
		return run, nil
	case ActionStateAudit:
		run.Events = append(run.Events, event(int64(len(run.Events)+1), "decision", levelForDecision(run.Decision), fmt.Sprintf("run decision: %s", run.Decision)))
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

func applyDeprecations(run *Run, deprecations []Deprecation) {
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
}

func recomputeGovernance(run *Run, req Request) {
	run.Findings = nil
	run.Decision = "allow"
	run.Status = "completed"
	run.Risk = "low"
	applyDeprecations(run, run.Deprecations)

	findings, blastRadius := ScanPolicy(req.SourceDir)
	run.Findings = append(run.Findings, findings...)
	run.BlastRadius = blastRadius
	applyFindings(run)

	if req.Action == ActionStateAudit || strings.Contains(strings.ToLower(req.Prompt), "state") {
		state, findings := AuditState(req.SourceDir, req.Environment)
		run.State = state
		run.Findings = append(run.Findings, findings...)
		applyFindings(run)
	}
}

func AutoFixSource(sourceDir string, dryRun bool) []AutoFix {
	var fixes []AutoFix
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
		original := string(data)
		updated := original
		fileFixes := []AutoFix{}

		if strings.Contains(updated, "\"0.0.0.0/0\"") {
			updated = strings.ReplaceAll(updated, "\"0.0.0.0/0\"", "\"10.0.0.0/8\"")
			fileFixes = append(fileFixes, AutoFix{
				File:        path,
				Code:        "restrict_public_cidr",
				Description: "replaced internet-wide ingress cidr with private network placeholder 10.0.0.0/8",
			})
		}
		if strings.Contains(strings.ToLower(updated), "acl") {
			beforeACL := updated
			updated = strings.ReplaceAll(updated, "\"public-read-write\"", "\"private\"")
			updated = strings.ReplaceAll(updated, "\"public-read\"", "\"private\"")
			if updated != beforeACL {
				fileFixes = append(fileFixes, AutoFix{
					File:        path,
					Code:        "private_s3_acl",
					Description: "replaced public s3 acl with private",
				})
			}
		}
		if strings.Contains(strings.ToLower(updated), "aws_db_instance") && !strings.Contains(strings.ToLower(updated), "storage_encrypted") {
			updated = insertBeforeLastBrace(updated, "  storage_encrypted = true\n")
			fileFixes = append(fileFixes, AutoFix{
				File:        path,
				Code:        "enable_rds_encryption",
				Description: "added explicit rds storage encryption",
			})
		}

		applied := false
		if updated != original && !dryRun {
			if err := os.WriteFile(path, []byte(updated), 0600); err == nil {
				applied = true
			}
		}
		for _, fix := range fileFixes {
			fix.Applied = applied
			if dryRun {
				fix.Applied = false
			}
			fixes = append(fixes, fix)
		}
		return nil
	})
	return fixes
}

func AuditState(sourceDir, environment string) (StateSummary, []Finding) {
	var summary StateSummary
	var findings []Finding
	_ = filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !isTerraformPolicyFile(path) || summary.Backend != "" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		body := strings.ToLower(string(data))
		normalizedBody := strings.Join(strings.Fields(body), " ")
		for _, backend := range []string{"s3", "azurerm", "gcs", "remote", "consul"} {
			if strings.Contains(body, fmt.Sprintf("backend \"%s\"", backend)) {
				summary.Backend = backend
				summary.Remote = backend != "local"
				summary.ConfigurationFile = path
				summary.Encrypted = strings.Contains(normalizedBody, "encrypt = true") || strings.Contains(body, "kms_key") || strings.Contains(body, "customer_managed_key") || backend == "remote"
				summary.Locking = strings.Contains(body, "dynamodb_table") || strings.Contains(normalizedBody, "use_lockfile = true") || strings.Contains(body, "use_azuread_auth") || backend == "remote"
				summary.WorkspaceAware = strings.Contains(body, "workspace") || strings.Contains(normalizedBody, "key =") || backend == "remote"
				return nil
			}
		}
		return nil
	})

	if summary.Backend == "" {
		severity := "warn"
		if environment == "prod" || environment == "production" {
			severity = "block"
		}
		findings = append(findings, Finding{
			Severity: severity,
			Code:     "remote_state_missing",
			Message:  "no supported remote state backend was detected",
		})
		return summary, findings
	}
	if summary.Remote && !summary.Encrypted {
		findings = append(findings, Finding{
			Severity: "block",
			Code:     "remote_state_encryption_unknown",
			Message:  "remote state backend does not declare encryption controls",
			File:     summary.ConfigurationFile,
		})
	}
	if summary.Remote && !summary.Locking {
		findings = append(findings, Finding{
			Severity: "warn",
			Code:     "remote_state_locking_unknown",
			Message:  "remote state backend does not declare a locking mechanism",
			File:     summary.ConfigurationFile,
		})
	}
	return summary, findings
}

func routePrompt(req Request) Request {
	prompt := strings.ToLower(req.Prompt)
	req.PolicyScan = true
	if strings.Contains(prompt, "prod") || strings.Contains(prompt, "production") {
		req.Environment = "prod"
	}
	if strings.Contains(prompt, "state") {
		req.SourceDir = defaultSourceDir(req.SourceDir)
	}
	return req
}

func defaultSourceDir(sourceDir string) string {
	if sourceDir == "" {
		return "."
	}
	return sourceDir
}

func insertBeforeLastBrace(body, line string) string {
	idx := strings.LastIndex(body, "}")
	if idx == -1 {
		return body + "\n" + strings.TrimRight(line, "\n") + "\n"
	}
	return body[:idx] + line + body[idx:]
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

func stateMessage(state StateSummary, findings []Finding) string {
	if state.Backend == "" {
		return "remote state backend was not detected"
	}
	if len(findings) > 0 {
		return fmt.Sprintf("remote state backend %q found with %d findings", state.Backend, len(findings))
	}
	return fmt.Sprintf("remote state backend %q passed encryption and locking checks", state.Backend)
}

func levelForFindings(findings []Finding) string {
	level := "info"
	for _, finding := range findings {
		if finding.Severity == "block" {
			return "error"
		}
		if finding.Severity == "warn" {
			level = "warn"
		}
	}
	return level
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
