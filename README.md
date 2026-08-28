# Terraform Agent

- Repository: https://github.com/rnadjqaim/Terragent
- Base engine: Terraform-compatible command line workflow
- Focus: governed, auditable, agent-assisted Infrastructure as Code execution

<img alt="Terraform Agent" src="https://www.datocms-assets.com/2885/1731373310-terraform_white.svg" width="600px">

Terraform Agent is an experimental governance layer for Infrastructure as Code.
It keeps the familiar Terraform workflow, but adds an agent layer that can review,
explain, fix, and govern infrastructure changes before execution.

Terraform and OpenTofu execute infrastructure. Terragrunt organizes infrastructure.
Terraform Agent governs infrastructure execution.

## Purpose

Infrastructure teams need developer self-service without losing control over
security, state, approvals, versions, and auditability. Terraform Agent introduces
a trusted execution model where policy, risk, state safety, and agent-assisted
remediation happen before a run proceeds.

## Major Capabilities

- **Agent command mode**: Run agent workflows from the Terraform-compatible CLI.
- **Autofix**: Remediate supported IaC policy findings directly in source files.
- **iacAI prompt execution**: Give the agent a prompt and let it route review,
  autofix, policy scan, and state audit actions.
- **Readable run logs**: Human-friendly sections for summary, blast radius,
  remote state, agent actions, timeline, deprecations, and findings.
- **Policy scanner**: Detect risky Terraform source patterns before execution.
- **Risk scoring**: Classify runs as `low`, `medium`, `high`, or `critical`.
- **Blast radius summary**: Report scanned files, observed resources, security
  findings, secrets, and protected resource hints.
- **Remote state governance**: Detect remote backend usage, encryption, locking,
  and production state risks.
- **CI JSON output**: Emit machine-readable output for pipelines and policy gates.
- **Approval-ready apply model**: Block apply unless an approved plan ID is used.

## Commands

Build the local binary:

```bash
go build -o ./terragent .
```

Run a governed plan:

```bash
./terragent agent-runner plan -workspace=payments-prod -module-version=2.3.1
```

Run a policy scan:

```bash
./terragent agent-runner plan -source=infra -policy-scan
```

Run CI JSON output:

```bash
./terragent agent-runner plan -source=infra -policy-scan -json
```

Autofix supported findings:

```bash
./terragent agent-runner autofix -source=infra -policy-scan
```

Preview autofix without writing files:

```bash
./terragent agent-runner autofix -source=infra -policy-scan -dry-run
```

Execute an iacAI prompt:

```bash
./terragent agent-runner iacai -source=infra -prompt="fix public access and audit remote state" -json
```

Audit remote state:

```bash
./terragent agent-runner state-audit -source=infra -env=prod
```

Apply an approved plan:

```bash
./terragent agent-runner apply -workspace=payments-prod -approved-plan-id=plan-123
```

Check version lifecycle rules:

```bash
./terragent agent-runner check-versions -terraform-version=1.9.0
```

## Example Result

```text
Terraform Agent

Summary
  run id   : run-1787945913373123000
  status   : completed
  decision : warn
  risk     : medium
  plan id  : plan-1787945913373123000

Timeline
  01 | received   | info  | run accepted for workspace "payments-prod"
  02 | identity   | info  | actor "user" requested plan in dev
  03 | versions   | warn  | version/deprecation check returned warnings
  04 | lock       | info  | state lock checked
  05 | init       | info  | terraform init scheduled on agent
  06 | validate   | info  | terraform validate scheduled on agent
  07 | plan       | info  | plan artifact prepared
  08 | decision   | warn  | run decision: warn
```

## Policy Findings

Terraform Agent can detect and block:

- SSH exposed to `0.0.0.0/0`
- RDP exposed to `0.0.0.0/0`
- Public S3 ACLs
- Secrets in `.tf` or `.tfvars` files
- Unsupported Terraform versions
- Blocked provider versions
- Production stacks without supported remote state

Terraform Agent can warn on:

- Deprecated internal modules
- RDS resources without explicit encryption settings
- Remote state backends without obvious locking controls
- Large blast-radius source changes

## Remote State Governance

The `state-audit` command detects supported remote backends such as:

- `s3`
- `azurerm`
- `gcs`
- `remote`
- `consul`

It evaluates whether the backend appears remote, encrypted, lock-aware, and
workspace-aware. In production, missing remote state is treated as a blocking
finding.

## iacAI

`iacai` is an agent command mode for prompt-driven IaC operations. It interprets
the prompt, runs policy analysis, audits state when requested, and can execute
supported autofix actions.

Example:

```bash
./terragent agent-runner iacai \
  -source=infra \
  -prompt="fix public access and audit remote state for production" \
  -json
```

## Development

Run focused tests:

```bash
go test ./internal/agentrunner
go test ./internal/command -run AgentRunner
```

## License

This experimental branch is based on Terraform source and follows the license
terms included in this repository.
