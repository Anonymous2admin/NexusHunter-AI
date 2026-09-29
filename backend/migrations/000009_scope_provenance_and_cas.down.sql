-- Migration 000009: Down
DROP INDEX IF EXISTS idx_targets_scope_import_id_unique;
ALTER TABLE targets DROP COLUMN IF EXISTS confirmed_by;
ALTER TABLE targets DROP COLUMN IF EXISTS authorization_snapshot_sha256;
ALTER TABLE targets DROP COLUMN IF EXISTS canonical_scope_sha256;
ALTER TABLE targets DROP COLUMN IF EXISTS primary_root_domain;
