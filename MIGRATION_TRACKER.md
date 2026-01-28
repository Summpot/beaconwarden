# BeaconWarden → Cloudflare Workers migration tracker

> Goal: run **BeaconWarden** (Vaultwarden fork) entirely on **Cloudflare Workers**, using:
>
> - **Turso/libSQL** as the database
> - **SeaORM (Summpot fork, `libsql` branch)** as the ORM layer
> - **Cloudflare R2** for attachments (prefer **direct-to-R2 uploads** via presigned URLs)
> - **Cloudflare Pages** as the public origin (`https://beaconwarden.pages.dev`) and reverse-proxy to the API Worker
>
> Non-goals / dropped features (by design):
>
> - WebSocket notifications (`/notifications/*`) and other stateful push-style features.
> - Long-lived background schedulers running inside the request runtime.
>   (If needed later, use Cron Triggers.)

---

## Status legend

- **NS**: not started
- **IP**: in progress
- **BLK**: blocked
- **DONE**: done

## High-level phases

| Phase | Scope | Exit criteria | Status |
|---|---|---:|:---:|
| 0 | Architecture decisions + repo scaffolding | Worker+Pages deploy pipeline green; health endpoint works | IP |
| 1 | DB + migrations baseline | Migrator runs in Worker; schema versioning works | IP |
| 2 | Auth primitives | Password hashing, sessions, device model, key derivation parity tests | NS |
| 3 | Core Bitwarden API compatibility | Desktop/mobile/CLI can login + sync + CRUD ciphers | NS |
| 4 | Orgs/collections/policies | Org sharing works; policies enforced | NS |
| 5 | Attachments (R2 direct upload) | Upload/download/delete compatible; quotas | NS |
| 6 | Sends | Create/send/delete works; optional | NS |
| 7 | Admin + maintenance | Admin endpoints needed for ops; cron jobs (optional) | NS |
| 8 | Hardening + observability | Rate limits, audit logs, error mapping, security headers | NS |
| 9 | Cutover + legacy migration tooling | Import from legacy SQLite/Postgres/MySQL into libSQL | NS |

---

## Detailed work items (checklist)

### 0. Repo & deployment scaffolding

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 0.1 | Add `wrangler.workers.jsonc` (API Worker) |  | `wrangler deploy --config wrangler.workers.jsonc` works | IP |
| 0.2 | Add `wrangler.jsonc` (Pages proxy) |  | Pages deploy works; requests proxy to Worker | IP |
| 0.3 | Create `crates/beaconwarden-worker` (wasm runtime) | 0.1 | `/health` returns JSON 200 | DONE |
| 0.4 | Create `crates/entity` + `crates/migration` | 0.3 | Worker can run `Migrator::up` | DONE |
| 0.5 | Add `.github/workflows/deploy-cloudflare-worker.yml` | 0.1–0.4 | API deploy + migrations in CI | NS |
| 0.6 | Add `.github/workflows/deploy-cloudflare-pages.yml` | 0.2 | Pages deploy in CI | NS |
| 0.7 | Add `AGENTS.md` guidance for agents |  | Clear conventions + Do/Don’t list | IP |

### 1. Database model & migrations

> Target DB: **libSQL/Turso**. Schema changes must be **additive**. Handle missing legacy fields safely.

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 1.1 | Decide schema strategy (match Vaultwarden tables vs new schema) |  | Documented mapping rules | NS |
| 1.2 | Implement core tables: users, devices, ciphers, folders | 1.1 | Sync can persist + read back | IP |
| 1.3 | Implement org tables: organizations, collections, memberships | 1.2 | Org sharing works | NS |
| 1.4 | Implement sends tables | 1.2 | Send create/read/delete works | NS |
| 1.5 | Implement attachments tables | 1.2 | Attachment metadata persisted | NS |
| 1.6 | Add indexes for sync performance | 1.2–1.5 | Acceptable sync latency | NS |

### 2. Request/response compatibility layer

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 2.1 | Define routing map for Bitwarden endpoints | 0.3 | Document lists all routes | NS |
| 2.2 | Implement common error format mapping | 0.3 | Clients understand failures (no generic 500) | IP |
| 2.3 | Implement CORS + security headers parity | 0.3 | Web clients + extensions function | IP |

### 3. Identity & auth

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 3.1 | Implement `/identity/connect/token` (password grant) | 1.2 | Desktop/mobile can login | NS |
| 3.2 | Implement refresh token flow | 3.1 | Refresh works across restarts | NS |
| 3.3 | Implement device registration & push token ignore | 3.1 | Devices show in clients | NS |
| 3.4 | Implement 2FA baseline (TOTP) | 3.1 | TOTP login works | NS |
| 3.5 | Disable/omit websocket notifications explicitly | 0.3 | Clients do not hang on notifications | DONE |

### 4. Core API surface (Bitwarden)

> This list mirrors `src/api/*` modules from the current codebase. Implement in Worker routing.

| Module | Key endpoints | Notes | Status |
|---|---|---|:---:|
| `api/web` | `/`, `/app-id.json` | Optional static/web vault | NS |
| `api/identity` | `/identity/*` | Critical | NS |
| `api/core/accounts` | `/api/accounts/*` | Signup, profile, keys | NS |
| `api/core/ciphers` | `/api/ciphers/*`, `/api/sync` | Critical | NS |
| `api/core/folders` | `/api/folders/*` |  | NS |
| `api/core/organizations` | `/api/organizations/*` |  | NS |
| `api/core/events` | `/api/events/*` | Optional; can be stubbed | NS |
| `api/core/emergency_access` | `/api/emergency-access/*` | Likely stateful; may be reduced | NS |
| `api/core/sends` | `/api/sends/*` | Optional but commonly used | NS |
| `api/admin` | `/admin/*` | Replace with minimal ops endpoints | NS |
| `api/icons` | `/icons/*` | Optional; may be simplified | NS |
| `api/notifications` | `/notifications/*` | **Dropped** (no websockets) | DONE |
| `api/push` | `/push/*` | **Dropped** | DONE |

### 5. Attachments via R2 (direct upload)

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 5.1 | Define R2 object key strategy (cipher_id/attachment_id) | 1.5 | Deterministic + reversible mapping | NS |
| 5.2 | Implement presigned PUT (single-part) | 5.1 | Client can upload > worker limit | NS |
| 5.3 | Implement multipart upload (large files) | 5.2 | Very large attachments supported | NS |
| 5.4 | Implement download (signed GET) | 5.1 | Bitwarden clients can download | NS |
| 5.5 | Implement delete + quota enforcement | 1.5 | Limits enforced consistently | NS |

### 6. Pages proxy (single origin)

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 6.1 | Proxy API paths to Worker service binding | 0.2 | `/api/*` reaches Worker | IP |
| 6.2 | Serve static landing page / web vault (optional) | 6.1 | `/` loads | NS |

### 7. CI/CD + operations

| ID | Task | Depends on | Acceptance criteria | Status |
|---:|---|---|---|:---:|
| 7.1 | CI: deploy worker + ensure Turso DB exists | 0.5 | Green deploy job | NS |
| 7.2 | CI: apply migrations via Worker endpoint | 7.1 | DB schema up-to-date | NS |
| 7.3 | CI: deploy pages proxy | 0.6 | Green pages deploy job | NS |
| 7.4 | Add runbooks (secrets, rollback, migrations) | 7.1–7.3 | Docs exist | NS |

### 8. Compatibility test matrix

| ID | Scenario | Acceptance criteria | Status |
|---:|---|---|:---:|
| 8.1 | Desktop login + sync | No errors; vault list correct | NS |
| 8.2 | Mobile login + sync | No errors; vault list correct | NS |
| 8.3 | Create/edit/delete cipher | Persists; sync reflects changes | NS |
| 8.4 | Organization share | Member sees shared items | NS |
| 8.5 | Upload/download attachment (big file) | Succeeds via direct R2 | NS |
| 8.6 | Send flow | Receiver can fetch; expiry enforced | NS |

---

## Notes / open questions

1. **DB schema choice**: The safest compatibility strategy is to keep API contracts identical and migrate data from existing Vaultwarden schema into a new libSQL schema that preserves the semantics.
2. **Workers limitations**: no raw TCP, limited request body sizes, limited per-request CPU. Prefer streaming + direct-to-R2 uploads.
3. **Crypto parity**: some vault operations are client-side, but server must preserve the exact fields and semantics.
