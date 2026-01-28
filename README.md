## BeaconWarden

BeaconWarden is a **Cloudflare Workers + Pages** deployment of a Bitwarden-compatible server API.

**This repository is derived from [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and is licensed under AGPL-3.0-only.**
See `LICENSE.txt` and the [Disclaimer](#disclaimer) section below.

> [!IMPORTANT]
> If you are looking for the standard Docker/VM deployment of Vaultwarden, this repo is not that.
> BeaconWarden targets a fork-and-deploy workflow using GitHub Actions.

## Deploy (recommended): fork + GitHub Actions

You do **not** need to install Wrangler locally.

1) Fork this repository.
2) In your fork, add the required GitHub repository secrets (Settings → Secrets and variables → Actions).
3) Push to `main`.

The included workflows will:

- build the Worker (Rust → wasm)
- deploy the Worker to Cloudflare
- deploy the Pages proxy
- apply DB migrations automatically

### Required GitHub Secrets

| Secret | Purpose |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with permission to deploy Workers + Pages |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account id |

### Database secrets (choose one path)

**Option A (recommended): auto-provision Turso/libSQL via Turso Platform API**

| Secret | Purpose |
|---|---|
| `TURSO_PLATFORM_API_TOKEN` | Turso platform API token |
| `TURSO_ORG_SLUG` | Turso org slug |
| `TURSO_DB_NAME` | Database name to create/use |
| `TURSO_GROUP` | Group name (optional; defaults to `default`) |

**Option B: bring your own libSQL URL + auth token**

| Secret | Purpose |
|---|---|
| `CLOUDFLARE_WORKER_LIBSQL_URL` | libSQL URL, e.g. `libsql://...` |
| `CLOUDFLARE_WORKER_LIBSQL_AUTH_TOKEN` | libSQL auth token |

### Optional secrets

| Secret | Purpose |
|---|---|
| `CLOUDFLARE_WORKER_BASE_URL` | External base URL (defaults to `https://<project>.pages.dev`) |
| `CLOUDFLARE_MIGRATIONS_API_TOKEN` | Separate Cloudflare token for running migrations (if your main token is IP-restricted) |
| `CLOUDFLARE_WORKER_MIGRATIONS_TOKEN` | Static token for the migration endpoint (optional) |

## Notes

- This project is **experimental** and under active migration. For engineering progress, see `MIGRATION_TRACKER.md`.
- Developer notes live in `docs/DEVELOPMENT.md`.

## Contributors

Thanks for your contribution to the project!

## Disclaimer

**This project is not associated with [Bitwarden](https://bitwarden.com/) or Bitwarden, Inc.**

However, one of the active maintainers for Vaultwarden is employed by Bitwarden and is allowed to contribute to the project on their own time. These contributions are independent of Bitwarden and are reviewed by other maintainers.

The maintainers work together to set the direction for the project, focusing on serving the self-hosting community, including individuals, families, and small organizations, while ensuring the project's sustainability.

**Please note:** We cannot be held liable for any data loss that may occur while using Vaultwarden. This includes passwords, attachments, and other information handled by the application. We highly recommend performing regular backups of your files and database. However, should you experience data loss, we encourage you to contact us immediately.

<br>

## Bitwarden_RS

This project was known as Bitwarden_RS and has been renamed to separate itself from the official Bitwarden server in the hopes of avoiding confusion and trademark/branding issues.<br>
Please see [#1642 - v1.21.0 release and project rename to Vaultwarden](https://github.com/dani-garcia/vaultwarden/discussions/1642) for more explanation.

---

## License

BeaconWarden is licensed under **AGPL-3.0-only**. See `LICENSE.txt`.

This repository contains derived work from the Vaultwarden project and must retain applicable upstream notices.
