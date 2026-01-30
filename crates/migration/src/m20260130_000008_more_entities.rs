use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // NOTE (2026-01-30): This migration was originally a large "grab bag"
        // of schema additions. On Cloudflare Workers + Turso/libSQL, each SQL
        // statement becomes an outgoing Hrana subrequest, and Workers enforce
        // a strict per-request subrequest limit.
        //
        // The original version could exceed that limit and fail with:
        // "Too many subrequests".
        //
        // The actual schema changes were split into multiple smaller migrations
        // (m20260130_000009+). This migration is kept as a no-op for safety and
        // compatibility with any existing databases that may already have it recorded.
        let _ = manager;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let _ = manager;
        Ok(())
    }
}
