-- Migration 000009: Scope Provenance & CAS Invariants
-- Phase 8.2R-FINAL.5

ALTER TABLE targets ADD COLUMN IF NOT EXISTS primary_root_domain VARCHAR(255);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS canonical_scope_sha256 VARCHAR(64);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS authorization_snapshot_sha256 VARCHAR(64);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS confirmed_by VARCHAR(128);

-- Ensure a scope import can produce at most one target (one-to-one scope confirmation invariant)
CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_scope_import_id_unique ON targets(scope_import_id) WHERE scope_import_id IS NOT NULL AND scope_import_id != '';
