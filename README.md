# ai-contained-provider-aws-cli

Executes AWS CLI commands on behalf of the AI, with a hard split between read-only and mutating operations. Fetches short-lived credentials per-request from [`ai-contained-provider-aws-secrets`](https://github.com/AI-Contained/ai-contained-provider-aws-secrets) via the trust-server protocol — this provider is fully stateless and stores no credentials.

## MCP surface

- **Tool `aws_read`** — executes a read-only AWS CLI command. Any command that looks mutating is rejected before the user is even prompted; ambiguous commands are also rejected (fail-safe).
- **Tool `aws_write`** — executes a mutating AWS CLI command. Passes through a smaller denylist (e.g. `sts assume-role` blocked) and always requires explicit user confirmation.

Both tools take the same shape:

| Parameter | Type | Purpose |
|---|---|---|
| `account`   | `str`           | 12-digit AWS account ID. Discoverable via the [`ai-contained://aws-secrets/accounts`](https://github.com/AI-Contained/ai-contained-provider-aws-secrets) resource. |
| `command`   | `list[str]`     | AWS CLI subcommand tokens, e.g. `["ec2", "describe-instances"]`. Do NOT include `aws` or `--profile`. |
| `flags`     | `list[str]`     | Extra flags in `--key=value` form, e.g. `["--region=us-east-1"]`. `--output` is not permitted (JSON is always used). |
| `jq_filter` | `str \| None`   | Optional jq expression applied to stdout before returning. |
| `summary`   | `str \| None`   | One-sentence description shown to the user during confirmation. |

Return value (JSON):
```json
{ "<account_id>": { "exit_status": "0", "stdout": "…", "stderr": "…" } }
```

## Safety model

- **Command classification** — `command_filter.py` holds an ordered rule chain that classifies each invocation as `ALLOW` or `DENY`. `aws_read` uses a strict allowlist of known read-only verbs (`describe-*`, `list-*`, `get-*`, `search-*`, etc.); `aws_write` uses a smaller denylist targeting the most dangerous operations (STS, IAM key rotation, etc.).
- **Elicitation** — every accepted command is confirmed with the user before it runs. The prompt shows the account (name + ID), the exact command, an optional purpose, and the tool name (green for `aws_read`, red for `aws_write`).
- **Credential isolation** — all `AWS_*` env vars are stripped from `os.environ` before invoking `aws`; only the freshly-fetched credentials are injected. jq runs in a separate subprocess with credentials removed, so filter code can't exfiltrate them.
- **`--output` denied** — JSON output is always forced. Reshape output via `jq_filter` instead.

## Configuration

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `TRUST_SERVERS` | yes (at MCP-host level) | Points at the trust-server that dispenses credentials — typically the `provider-aws-secrets` container. See the trust-client docs. |
| `COLOR` | no | Set to any value other than `ascii` (e.g. `off`) to disable ANSI colours in elicitation messages. Default: `ascii` (colours on). |
| `EXPERIMENTAL_APPROVE_ALL_READS` | no | If truthy, `aws_read` skips the user-confirmation elicitation and auto-approves. `aws_write` is unaffected. Intended for low-friction read-heavy sessions; use with care. |
| `AWS_PAGER` | (auto-set) | Forced to empty inside the subprocess to prevent the AWS CLI from paging. Do not set. |

### Prerequisites

The container running this provider must have both `aws` and `jq` on `$PATH`. When built via the standard AI-Contained image pipeline, `apk-packages.txt` in this repo installs them automatically.

## docker-compose example

The provider expects to run inside the `ai-contained` container, with `provider-aws-secrets` running as a peer that serves `TRUST_SERVERS`:

```yaml
services:
  ai-contained:
    environment:
      - TRUST_SERVERS=http://secrets:8080
      # optional:
      # - EXPERIMENTAL_APPROVE_ALL_READS=yes
    depends_on:
      secrets:
        condition: service_healthy

  secrets:
    # see ai-contained-provider-aws-secrets for the full config
    environment:
      - TRUST_CLIENTS=ai-contained
      - AWS_ACCOUNTS_CONFIG_PATH=/secrets/aws-secrets/accounts.json5
```

## Elicitation preview

What the user sees when the AI attempts a command (colours abbreviated):

```
I will run on Sandbox(123456789012):  (using tool: aws_read)

    aws secretsmanager list-secrets --region=us-east-1 --max-results=100 | jq '{count: (.SecretList | length), names...'

Purpose: List Secrets Manager secret names in Sandbox us-east-1

  ❯ Accept    Decline
```

- Account name is coloured deterministically per-name (same account always renders the same hue).
- Account ID is dimmed grey.
- Tool name is green for reads, red for writes.
- Long `jq_filter` expressions are truncated to 40 chars in the display; the *full* filter is still applied.

## Development

```bash
uv sync --extra dev

# Tests
uv run --extra dev pytest -v

# Lint + format
uv run --extra dev ruff check src/ tests/
uv run --extra dev ruff format --check src/ tests/

# Type check
uv run --extra dev mypy src/
```

## Installation

### Local development

```bash
uv sync --extra dev
```

### Production

```bash
uv pip install "ai-contained-provider-aws-cli @ git+https://github.com/AI-Contained/ai-contained-provider-aws-cli.git@main"
```
