# Developer notes

This document is for contributors. End users should follow the fork + GitHub Actions deploy instructions in `README.md`.

## Architecture (high level)

- API runtime: Cloudflare Workers (Rust `wasm32-unknown-unknown`)
- Public origin: Cloudflare Pages (reverse proxy to the Worker via service binding)
- Database: Turso/libSQL via SeaORM (Summpot fork, `libsql` branch)

## Useful local checks

- `cargo check -p beaconwarden-worker --target wasm32-unknown-unknown`
- `worker-build --release crates/beaconwarden-worker`

## Admin / operations endpoints

- `POST /v1/admin/migrations/up` applies SeaORM migrations.
- `GET /v1/admin/db/ping` checks database connectivity.

Authorization:

- If `MIGRATIONS_TOKEN` is set, admin endpoints require `Authorization: Bearer <MIGRATIONS_TOKEN>`.
- Otherwise, the Worker verifies Cloudflare API tokens.

## Repository status

This repo is derived from Vaultwarden and is being migrated to a Workers-only deployment.

Progress tracking lives in `MIGRATION_TRACKER.md`.
