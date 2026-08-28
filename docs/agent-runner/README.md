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
