# DB schema strategy (libSQL + SeaORM)

This repo is being migrated from the legacy Rocket/Diesel Vaultwarden-style server into a **Cloudflare Workers-only** deployment backed by **Turso/libSQL**.

The guiding principle is:

- **API wire compatibility first** (endpoints, JSON shapes/casing, behavior).
- **Schema compatibility where it helps**, but with pragmatic adjustments for Workers/libSQL.

## Goals

- Keep the Worker runtime simple and deterministic.
- Prefer **additive** schema evolution only.
- Make it straightforward to write a future import tool from the legacy Vaultwarden schema into this schema.

## Table naming

- Table names generally follow Vaultwarden conventions (e.g. `users`, `ciphers`, `folders`).
- Column names use a **normalized naming style** used throughout the Worker code:
  - Primary keys are `id` (string UUID)
  - Foreign keys are `<entity>_id` (e.g. `user_id`, `organization_id`, `cipher_id`)

This differs from the legacy Diesel schema where many columns are `uuid` / `*_uuid`.

## Identifiers

- IDs are stored as `TEXT` and treated as opaque UUID strings.
- We do not rely on DB-native UUID types.

## Timestamps

To avoid cross-platform timestamp quirks and keep the Worker implementation minimal:

- Most timestamps are stored as **Unix seconds** (`INTEGER` / `i64`).
- API responses are formatted as RFC3339 strings where required (e.g. `revisionDate`, `creationDate`).

This differs from the legacy schema which uses SQL `Timestamp`.

## Encrypted payloads and canonical fields

For Bitwarden/Vaultwarden compatibility, the server must preserve client-encrypted fields.

- `ciphers.data` stores the **opaque encrypted JSON payload** (string).
- The server may overwrite canonical fields in responses (and/or stored rows) such as:
  - `id`
  - `creationDate` / `revisionDate`
  - `deletedDate`
  - `folderId`
  - `favorite`

### Favorites

Favorites are modeled as a per-user mapping table:

- `favorites (user_id, cipher_id)`

This intentionally avoids encoding a shared "favorite" flag inside a cipher record.

### Folder assignment

Folder assignment is modeled via a mapping table:

- `folders_ciphers (cipher_id, folder_id)`

A cipher can have at most one folder mapping (first mapping wins); clients treat `folderId` as singular.

### Equivalent domains settings

Domain settings are stored per-user:

- `users.equivalent_domains` (JSON string)
- `users.excluded_globals` (JSON string)

The Worker serves `/api/settings/domains` and can embed domains in `/api/sync` unless `excludeDomains=true`.

## Migrations (libSQL constraints)

- All schema changes must be **additive**.
- Prefer nullable columns or safe defaults.
- For SQLite/libSQL compatibility:
  - Prefer **one column per `ALTER TABLE`** statement.
  - Down migrations are best-effort; dropping columns is not supported.

## Legacy import mapping (future work)

A future import tool should translate:

- `uuid` / `*_uuid` → `id` / `*_id`
- SQL timestamps → Unix seconds
- JSON/text fields are generally 1:1

The primary risk is semantic mismatch, not type mismatch; when in doubt, match Vaultwarden behavior rather than inventing new semantics.
