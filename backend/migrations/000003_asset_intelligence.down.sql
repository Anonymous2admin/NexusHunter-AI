-- Rollback Phase 3 Schema

DROP TABLE IF EXISTS page_assets CASCADE;
DROP TABLE IF EXISTS asset_changes CASCADE;
DROP TABLE IF EXISTS asset_tags CASCADE;
DROP TABLE IF EXISTS security_observations CASCADE;
DROP TABLE IF EXISTS service_observations CASCADE;
DROP TABLE IF EXISTS technology_observations CASCADE;
