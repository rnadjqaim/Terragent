# terraform agent runner

terraform agent runner is a small platform prototype for running terraform through a trusted agent instead of running everything directly on a developer machine.

the cli still feels like terraform, but the actual plan/apply work can happen somewhere safer.

## what it does

- sends terraform runs to an agent over rpc
- keeps cloud credentials inside the runner
- checks terraform, provider, and module versions
- warns or blocks deprecated modules
- locks state before apply
- streams logs back to the user
- stores run history and audit data

## why it matters

teams want self-service infrastructure, but they also need control. this design gives developers a normal workflow while giving platform teams a safer place to enforce rules.

## simple flow

```text
terraform cli
   |
   | rpc request
   v
agent runner gateway
   |
   | approved job
   v
terraform worker
   |
   v
cloud + state backend
```

## files

- `V-1.md` - first design
- `V-2.md` - policy, risk, blast-radius, and ci output design
- `agentrunner.v1.proto` - rpc draft
- `version-policy.example.json` - sample version/deprecation rules

## v-1 command

this branch adds an experimental command:

```text
terraform agent-runner plan
terraform agent-runner apply
terraform agent-runner check-versions
```

the command currently uses a local mock runner. it accepts a run, checks version/deprecation rules, streams simple events, and returns a final decision.

## examples

```text
terraform agent-runner plan -workspace=payments-prod -module-version=2.3.1
terraform agent-runner apply -workspace=payments-prod -approved-plan-id=plan-123
terraform agent-runner check-versions -terraform-version=1.9.0
```

## next build step

replace the mock runner with a real rpc client and a worker that runs terraform in an isolated directory.

## v-2 command additions

v-2 adds the first governance layer around a run:

```text
terraform agent-runner plan -source=infra -policy-scan
terraform agent-runner plan -source=infra -policy-scan -json
```

the policy scanner looks for dangerous source patterns before the runner schedules work:

- public ssh or rdp from `0.0.0.0/0`
- public s3 acl settings
- rds resources without an explicit encryption setting
- secrets committed in terraform or tfvars files
- protected resource hints such as `prevent_destroy = true`

each run now includes:

- `risk`: low, medium, high, or critical
- `blast radius`: scanned files, observed resources, security findings, secrets, and protected resource hints
- policy findings that can warn or block the run
- optional json output for ci systems
