# Evidence and Headless Operations

These features improve assessment reliability and auditability. They do not
authorize a target, establish network isolation automatically, or prove that an
application is secure. Use only explicitly authorized lab or staging targets.

## Deployment and Migration

Stop the backend and back up its SQLite database and evidence directory before
upgrading. Database initialization adds JSON payload columns for durable command
attempts and findings. Existing rows remain readable; an old source-based
`confirmed` label does not become evidence-backed verification. Historical reports
are loaded without restoring execution or starting an assessment.

Use a single backend worker. Session ownership, execution budgets, inventory
locking, and focused-job coordination are process-local, not distributed leases.
Do not run multiple schedulers against the same database expecting global limits.

Local execution remains the default and runs on the host. For optional Docker
configuration and its externally enforced egress requirements, see
[Sandbox and Scope Enforcement](sandbox.md). Invalid backend configuration fails
closed; it never falls back from Docker to local execution.

| Setting | Default | Purpose |
| --- | --- | --- |
| `KMN_EXECUTION_BACKEND` | `local` | Select `local` or `docker`. |
| `KMN_DOCKER_IMAGE` | empty | Explicit preprovisioned tool image. |
| `KMN_DOCKER_NETWORK` | `none` | Dedicated operator-managed network. |
| `KMN_DOCKER_NETWORK_POLICY_ATTESTED` | `false` | Operator declaration of external egress enforcement, not a detected guarantee. |
| `KMN_DOCKER_MEMORY_MB` | `512` | Per-container memory cap. |
| `KMN_DOCKER_CPUS` | `1` | Per-container CPU limit. |
| `KMN_DOCKER_PIDS_LIMIT` | `64` | Per-container process cap. |
| `KMN_MAX_EXECUTIONS` | `3` | Active subprocess execution slots per event loop. |
| `KMN_MAX_QUEUED_EXECUTIONS` | `32` | Maximum queued executions; `0` rejects waiting work. |
| `KMN_EVIDENCE_DIR` | database-sibling `evidence` | Restricted raw evidence store. |
| `KMN_EVIDENCE_KEY` | empty | Supplied Fernet key; empty means permission protection only. |
| `KMN_EVIDENCE_MAX_BYTES` | `67108864` | Retained prefix byte cap per subprocess stream. |
| `KMN_ASSESSMENT_DIR` | database-sibling `assessments` | Inventory/coverage snapshots. |

The example environment explicitly selects a 16 MiB evidence cap. The artifact
library's standalone default is also 16 MiB. Configure a cap deliberately for
deployment; truncation is recorded, never presented as complete evidence.

## Findings and Verification

The lifecycle is `observed`, `suspected`, `verified`, `inconclusive`, `remediated`,
or `retested`. Status and confidence are not interchangeable with verification.
The pure `core.finding_verification.assess_finding` checks declared relationships
and transitions. The live operator-review method additionally resolves artifacts
against the session store and reads them to check integrity.

Findings have stable `finding_id` values. Command requests preserve their logical
`command_id`; every execution/credential retry has a separate `attempt_id`.
Reobserving a finding retains corroborating evidence instead of dropping upgrades.
Raw stdout/stderr is captured before decoding and prompt sanitization, while UI
and model previews remain bounded. Exit code zero alone does not validate a
credential; supported protocol-specific proof must match the credential used.

Operator review is an explicit trust boundary. A positive review means an
authenticated operator has inspected the evidence, not that the framework
independently replayed an exploit. No scanner source label or model claim is
automatically converted into a verified vulnerability. Remediation and retest
require the correct prior lifecycle and fresh evidence where applicable.

All routes below require the existing `X-API-Key` authentication:

| Method | Session-Relative Path | Behavior |
| --- | --- | --- |
| GET | `/report.json` | Sanitized schema-versioned summary. |
| GET | `/report.sarif` | SARIF 2.1.0, marking unverified findings for review. |
| GET | `/artifacts` | List committed artifact manifests. |
| GET | `/artifacts/{id}/content?acknowledge_sensitive=true` | Download sensitive raw bytes with explicit acknowledgement. |
| POST | `/vulnerabilities/{finding_id}/verification` | Record an acknowledged operator review/lifecycle event. |
| POST | `/assessment/import` | Import bounded local OpenAPI 3 JSON. |
| GET | `/assessment` | Read inventory and role/category coverage. |
| PATCH | `/assessment/coverage` | Record external check outcomes. |

These paths are relative to `/api/sessions/{session_id}`. Review requests accept
`acknowledge_review: true`, `kind`, `result`, `method`, `artifact_refs`, and optional
`evidence` prose. Verification/retest results are `positive`, `negative`, or
`inconclusive`; remediation requires `applied`. Artifacts must be committed and
belong to that session. Caller-supplied targets, verified flags, and arbitrary
artifact URIs are rejected by the route.

## Headless Client

`cli.py` is an HTTP client; importing it or running `--help` does not initialize
the backend, create a database, or write credentials. The backend must already be
running. Configure `KMN_API_URL` and `API_AUTH_TOKEN` in the calling environment,
or use `--base-url` and `--api-key`. Environment-based keys avoid shell-history
exposure. API errors do not echo response bodies or authentication values.

```bash
python cli.py --help
python cli.py start 192.0.2.1 --authorization-confirmed
python cli.py status SESSION_ID
python cli.py events SESSION_ID
python cli.py jobs SESSION_ID
python cli.py wait SESSION_ID --wait-timeout 300 --fail-on high
python cli.py report SESSION_ID --format json --output report.json
python cli.py report SESSION_ID --format sarif --output report.sarif --fail-on high
python cli.py evidence list SESSION_ID
python cli.py evidence download SESSION_ID ARTIFACT_ID --acknowledge-sensitive --output evidence.bin
python cli.py verify SESSION_ID FINDING_ID --acknowledge-review --kind verification --result positive --method "manual protocol review" --artifact-id ARTIFACT_ID
python cli.py cancel SESSION_ID
```

The start command does not enable full-auto implicitly. Waiting stops for human
approval or operator input instead of silently granting it. Requests have finite
timeouts and HTTP redirects are rejected. CI severity thresholds count only
evidence-backed verified findings, not potential findings or legacy labels.

| Exit | Meaning |
| --- | --- |
| `0` | Request/report succeeded, or completed without a threshold violation. |
| `1` | Client, output-file, or API failure. |
| `2` | Invalid arguments. |
| `3` | Verified severity threshold exceeded. |
| `4` | Human approval required. |
| `5` | Session failed. |
| `6` | Session cancelled. |
| `7` | Wait deadline exceeded. |
| `8` | Operator input required. |

Explicit output files are private (`0600`) and never overwrite an existing path,
including symlinks. Use a fresh destination for each export. JSON/SARIF are
allowlisted and redacted summaries, not a general proof that arbitrary strings
cannot contain secrets. Review before sharing. DOCX/PDF/Markdown and archives may
contain commands, credentials, and output; treat them as restricted deliverables.

## Evidence Protection and Retention

Artifact directories use `0700`, files use `0600`, and generated identifiers avoid
target-controlled filenames. Committed artifacts cannot be overwritten through
the store API. Reads reject invalid paths, links, and retained-content corruption.
Optional Fernet encryption uses an operator-supplied key; encrypted captures do
not stage plaintext on disk. Protect and back up the key separately. Key rotation
and automatic key recovery are not implemented.

The manifest's `sha256` and `size_bytes` describe all observed bytes;
`stored_sha256` and `stored_bytes` describe the retained prefix. A truncated tail
cannot be reconstructed or independently checked from retained bytes. Filesystem
permissions and hashes do not defend against a fully compromised storage account.

Reset/rescan preserves raw evidence. Session deletion invalidates old execution
epochs and purges owned raw artifacts and inventory snapshots. If cleanup is
still running, deletion reports an error for retry rather than claiming success.
There is no automatic retention expiry. Backups, exported reports, application
logs, and externally managed transport storage remain the operator's responsibility.
Default archives include metadata but exclude raw artifact payloads; direct
library callers must explicitly request `include_raw_artifacts=True` to include
them. Managed-shell transports still supply decoded text, not original wire bytes.

## Inventory and Browser Boundaries

OpenAPI import is an inventory operation, not an API penetration test. Local
JSON references are checked without fetching external files or URLs. Coverage
distinguishes pending, attempted, verified, blocked, skipped, and inconclusive.
A verified coverage cell is a reviewed check, not a verified vulnerability.
Inventory evidence references do not themselves authenticate external evidence.

The focused coordinator supports budgets, deduplication, cancellation, and
independent async callbacks. It is not a general LLM agent swarm. Actual scanner
and command execution also share bounded subprocess admission, separate from AI
continuation. Browser observations are an optional library adapter with explicit
authorization, scope and external sandbox attestation; no Playwright dependency
is installed automatically. See [Assessment](assessment.md) and [Browser](browser.md).

Automated business-logic testing, source-code SAST, patch generation, distributed
workers, and automatic exploit replay are not implemented by these changes.

## Validation and CI

Run the offline suite with `python -m pytest -q`. Install the HTTP test dependencies
in the repository workflow to avoid silently skipping FastAPI contract tests.
Tests use temporary databases, fake tools/browsers, local HTTP fixtures, and
harmless subprocesses. No real target assessment is required for CI.

The GitHub workflow runs regression tests on pull requests. It does not launch
autonomous scans against deployments. Use the CLI against an explicitly authorized
staging environment in a separately approved job if deployment assessment is
needed. Never expose API credentials to untrusted pull-request code.

No live Docker network policy, Kali toolchain, browser installation, cloud model,
or real-target effectiveness claim follows from passing offline tests. Validate
those separately in an isolated, authorized acceptance environment before use.
