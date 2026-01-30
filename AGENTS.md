# BeaconWarden (Workers-only) — Agent Guide

This repository is being migrated from a Rocket/Diesel/Vaultwarden-style server into a **Cloudflare Workers-only** deployment.

All repository artifacts (code comments, docs, error messages, logs) must be written in **English**.

---

## Mission

Deliver a Bitwarden-compatible server implementation that:

- Runs entirely on **Cloudflare Workers** (wasm32) for the API.
- Uses **Cloudflare Pages** as the public origin (`https://beaconwarden.pages.dev`) and proxies API routes to the Worker.
- Stores data in **Turso (libSQL)** using **SeaORM** (Summpot fork, `libsql` branch).
- Stores attachments in **Cloudflare R2**, preferring **direct-to-R2 uploads** (presigned URLs) to avoid Worker upload limits.

## Vaultwarden compatibility contract

BeaconWarden MUST remain wire-compatible with **Vaultwarden** for all Bitwarden-facing endpoints.

This means:

- Match endpoint paths, HTTP methods, status codes, and JSON casing/shape.
- Match behavioral edge cases (timing mitigations, error semantics, and conditional flows).
- When uncertain, prefer copying Vaultwarden behavior over inventing new flows.

### Signup email verification (Vaultwarden `SIGNUPS_VERIFY`)

Vaultwarden's registration verification for `SIGNUPS_VERIFY` is **link-based**, not a user-entered numeric code.

- Clients call `POST /identity/accounts/register/send-verification-email`.
  - If email is configured **and** `SIGNUPS_VERIFY=true`, the server sends an email and returns **204 No Content**.
  - If email verification is not required (or email is not configured), the server returns a token in the response body.

- The verification email contains a link to the web-vault flow:
  - `/#/finish-signup/?email=<email>&token=<token>`

- The web-vault flow then calls `POST /identity/accounts/register/finish` with `emailVerificationToken`.

Important: Bitwarden desktop clients typically will **not** show an "enter email verification code" prompt for this flow.
The expected UX is "check your email and click the link".

## Explicit non-goals (do not implement)

- WebSocket notifications and push notifications:
  - `/notifications/*` and `/push/*` should be stubbed/disabled in a way that clients tolerate.
- Long-lived in-process schedulers.
  - If periodic cleanup is required later, use Cloudflare Cron Triggers.

## Reference implementation

Use `BeaconAuth` in this multi-root workspace as the primary reference for:

- Worker crate layout (`crates/beacon-worker`) and routing patterns.
- libSQL/Turso connection strategy via SeaORM ConnectOptions.
- GitHub Actions workflows for Cloudflare deploy + Turso bootstrap.
- The “Pages + Worker with service binding” single-origin proxy design.

## Repository layout (target)

- `crates/beaconwarden-worker`: Cloudflare Worker API runtime (wasm32).
- `crates/entity`: SeaORM entities.
- `crates/migration`: SeaORM migrations (must be wasm-safe).
- `dist/`: Cloudflare Pages output (contains `_worker.js` proxy and optional static assets).
- `wrangler.workers.jsonc`: Worker config.
- `wrangler.jsonc`: Pages config.

## Configuration (Worker)

### Wrangler vars (checked in)

Defined in `wrangler.workers.jsonc` under `vars`:

- `LIBSQL_URL` (required)
- `BASE_URL` (recommended)

### Secrets (NOT checked in)

Set via `wrangler secret put` or via GitHub Actions secrets:

- `LIBSQL_AUTH_TOKEN` (Turso DB token)
- R2 presign credentials (for direct-to-R2 uploads):
  - `R2_ACCESS_KEY_ID`
  - `R2_SECRET_ACCESS_KEY`
  - `R2_ACCOUNT_ID`

- JWT signing secrets MUST be stored in libSQL in the `server_secrets` table (e.g. key `jwt_secret`).
  - Do not introduce `JWT_SECRET` / `REGISTER_VERIFY_JWT_SECRET` environment variables in this repo.

### R2 bucket bindings

Worker should use an R2 binding for server-side operations:

- `ATTACHMENTS` (R2 bucket binding)

## Direct-to-R2 upload design

Workers have request size limits, so uploads should go directly to the R2 S3 endpoint:

- Worker issues **presigned URLs** (single PUT and/or multipart upload).
- Clients upload the bytes directly to R2.
- Worker validates metadata and finalizes attachment records in libSQL.

### Important: CORS

R2 bucket CORS must allow PUT/GET from the required origins (Pages origin and any custom domains).

## DB access design (libSQL/Turso)

- Use `SeaORM` with the Summpot fork (`libsql` branch).
- Use `ConnectOptions` with:
  - `max_connections(1)` and short timeouts (edge runtime friendly)
  - optional `libsql_auth_token`

## Database query budget (Cloudflare Workers subrequests)

Cloudflare Workers enforces strict **subrequest limits** per incoming request.
With Turso/libSQL over Hrana, **each DB roundtrip counts as a subrequest**, so naive “loop + query” code can easily fail with:

- `Error: Too many subrequests`

Project guideline: **Always optimize for fewer DB queries**.

- Prefer set-based operations (single query over many rows) over per-item lookups.
- Batch writes with `insert_many` / bulk `update_many` / `delete_many`.
- Preload reference data once (e.g., existing folder ids) and reuse it in-memory.
- Avoid patterns like `find_one`/`exists` inside loops during bulk endpoints (imports, sync writes, bulk edits).
- When you must chunk, pick conservative chunk sizes to stay below SQLite variable limits and request-size constraints.

## Error handling

Never let unhandled errors bubble to the Worker runtime.
Always return a response (JSON with a stable error shape) so clients don’t see “script will never generate a response”.

## Migration rules

- Schema changes must be **additive**.
- New columns should be nullable or have safe defaults.
- Handle missing/legacy fields in application code.

## Verification requirements

After any Rust change:

- `cargo check -p beaconwarden-worker --target wasm32-unknown-unknown`
- `worker-build --release crates/beaconwarden-worker` (ensures Wrangler bundle exists)

## Migration tracker discipline

- `MIGRATION_TRACKER.md` is the single source of truth for migration progress.
- Whenever you start/finish work that changes progress, you MUST update the corresponding **Status** cells in `MIGRATION_TRACKER.md` in the same change.
- Do **not** add narrative progress entries. We intentionally do **not** maintain a progress log in the tracker; only keep the structured status tables up to date.

## Deliverables to keep in the repo root

- `MIGRATION_TRACKER.md` must stay updated (status tables only; no progress log).
- Any “misc notes” should live in the repo root for easy review.
