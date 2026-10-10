# AgentShield

AgentShield is an early-stage security testing toolkit and self-hostable service for AI agents. It runs a fixed suite of adversarial prompts against an agent and returns structured findings. The web service includes email-verified accounts, tenant-scoped scan history, a scan queue/worker, and a browser dashboard.

**Important:** the built-in checks currently infer unsafe behavior from response text and OpenAI-compatible tool-call output. They do not prove that a tool actually executed, inspect memory/vector databases, ingest real documents, orchestrate a multi-agent system, or certify compliance. Use an isolated staging agent with least-privilege test credentials. A scan can still alter target state if the target agent has write-capable tools.

## What is implemented

- Seven prompt-based attack modules: direct and indirect prompt injection, tool-abuse probes, privilege escalation, memory poisoning, TOCTOU-themed probes, and spoofed peer-agent messages.
- Python library and CLI; locally imported Python targets are supported by the CLI only.
- OpenAI-compatible chat-completions HTTP targets, including HTTP tool-call output where returned by the target.
- JSON and escaped HTML reports. Incomplete checks are marked and do not receive a numeric safety score.
- Self-hosted FastAPI service with verified email/password accounts, password reset, account deletion, tenant-scoped scan records, per-IP authentication throttling, and a separate durable database-backed scan worker.
- Encrypted-at-rest target API keys while a job is pending/running; the key is erased when the scan reaches a terminal state.
- PostgreSQL migrations, HTTPS reverse proxy configuration, and Docker Compose deployment.

Each account currently creates a separate workspace; team invitations and shared workspaces are not implemented.

## Local CLI

Install the package:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Scan an OpenAI-compatible endpoint. Configure `AGENTSHIELD_ALLOWED_TARGET_HOSTS` with the endpoint hostname first:

```powershell
$env:AGENTSHIELD_ENVIRONMENT = "development"
$env:AGENTSHIELD_ALLOWED_TARGET_HOSTS = "agent-api.example.com"
$env:AGENTSHIELD_TARGET_API_KEY = "your-dedicated-test-key"
agentshield scan --url "https://agent-api.example.com/v1/chat/completions" --model "your-model" --format json --output report.json --confirm-authorized
agentshield scan --url "https://agent-api.example.com/v1/chat/completions" --model "your-model" --format html --output report.html --confirm-authorized
```

For a local test service only, opt in to loopback HTTP targets:

```powershell
$env:AGENTSHIELD_ALLOW_LOOPBACK_TARGETS = "true"
```

Try the CLI end-to-end without network access or API credentials:

```powershell
agentshield scan --python-target examples.mock_agent:create_agent --format html --output mock-report.html --confirm-authorized
```

An in-process Python target can be used with `--python-target package.module:factory --confirm-authorized`. Importing a plugin executes arbitrary Python code in the CLI process; only load code you trust. The hosted API never imports customer Python plugins. Both CLI and API require explicit authorization confirmation because test prompts can cause real target-side actions.

## Self-hosted service

The production Compose stack runs PostgreSQL, the API/dashboard, a separate scan worker, Alembic migrations, and Caddy for automatic HTTPS.

1. Point a DNS name (for example `agentshield.example.com`) at the host and allow inbound TCP ports 80 and 443.
2. Copy `.env.example` to `.env`. Generate independent secrets, for example:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Use fresh output for `AGENTSHIELD_JWT_SECRET_KEY`, `AGENTSHIELD_ENCRYPTION_KEY`, and `POSTGRES_PASSWORD`. Keep `.env` private and back up the encryption key securely; without it, pending job credentials cannot be decrypted.
3. Set the SMTP server and sender, `AGENTSHIELD_HOST`, `AGENTSHIELD_FRONTEND_URL`, `AGENTSHIELD_ALLOWED_WEB_HOSTS`, and the exact hostnames in `AGENTSHIELD_ALLOWED_TARGET_HOSTS`.
4. Start the services:

   ```powershell
   docker compose up --build -d
   docker compose ps
   ```

5. Open the configured HTTPS hostname, create an account, verify its email, then sign in and queue a scan.

Production startup refuses missing/weak secrets, non-PostgreSQL databases, missing SMTP, non-HTTPS account links, and an empty target-host allowlist. Each workspace is limited to two active scans and 50 scans per day by default. The API and worker are not published directly to the host; Caddy is the only public service. If you change the database schema, create and review an Alembic migration before deploying it.

### Egress and deployment security

The service rejects non-HTTPS targets in production, credentials/query strings in URLs, unapproved hostnames, non-public DNS results, and redirects. This validation is defense in depth, not a substitute for network isolation: configure outbound firewall/egress rules to block loopback, private, link-local, and cloud metadata networks, and permit only the intended model/agent endpoints. Keep the API reachable only through a trusted reverse proxy that overwrites `X-Real-IP`; the included Caddy configuration does this. Do not expose the API container port directly.

The target API key is encrypted with AES-GCM while a scan is queued/running and removed at completion. Scan reports may contain sensitive target responses; they are workspace-protected and automatically deleted after the configured `AGENTSHIELD_SCAN_RETENTION_DAYS` (30 days by default). Unverified accounts and their workspaces are automatically removed after `AGENTSHIELD_UNVERIFIED_ACCOUNT_RETENTION_DAYS` (7 days by default). Users can also delete completed scans or delete their entire workspace and account. Rotate secrets using a planned maintenance procedure; key rotation is not automated.

## API and worker

- Dashboard: `GET /`
- Liveness: `GET /healthz`
- Register/verify/sign in: `/api/auth/register`, `/api/auth/verify-email`, `/api/auth/login`
- Password reset: `/api/auth/password-reset/request`, `/api/auth/password-reset/confirm`
- Scans: `POST /api/scans`, `GET /api/scans`, `GET /api/scans/{scan_id}`, `DELETE /api/scans/{scan_id}`
- Account: `GET /api/me`, `DELETE /api/account`
- Development-only OpenAPI docs: `/api/docs`

The API queues scans; run `agentshield-worker` as a separate process. The Compose deployment includes it. Authentication uses short-lived signed bearer tokens; a password reset invalidates previously issued tokens.

## Interpreting results

Findings and the aggregate score are heuristic signals, not a guarantee of exploitability or safety. A response that repeats attack text may be flagged even when no action occurred; an unsafe tool action that is not reflected in text/tool-call output may be missed. A scan with failed requests is marked incomplete and has no numeric safety score. The HTML export is a human-readable test report, not an EU AI Act technical file or compliance certificate. Applicable AI Act obligations and dates depend on the system and use case; obtain qualified regulatory advice.

## Development and tests

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

Set `AGENTSHIELD_ENVIRONMENT=test` and `AGENTSHIELD_DATABASE_URL=sqlite://` for isolated API tests. Production should use PostgreSQL, SMTP with STARTTLS, and explicit network egress controls.