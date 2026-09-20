-- Revert Phase 7 Security Reasoning Schema

DROP TABLE IF EXISTS reasoning_runs CASCADE;
DROP TABLE IF EXISTS security_control_records CASCADE;
DROP TABLE IF EXISTS permission_matrix_entries CASCADE;
DROP TABLE IF EXISTS auth_contexts CASCADE;
DROP TABLE IF EXISTS trust_boundaries CASCADE;
DROP TABLE IF EXISTS investigations CASCADE;
DROP TABLE IF EXISTS evidence_requirements CASCADE;
DROP TABLE IF EXISTS falsification_conditions CASCADE;
DROP TABLE IF EXISTS hypotheses CASCADE;
DROP TABLE IF EXISTS hypothesis_groups CASCADE;
DROP TABLE IF EXISTS reasoning_signals CASCADE;
