package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// PostgresPhase8Storage implements PostgreSQL storage for Phase 8 data models.
type PostgresPhase8Storage struct {
	db *sql.DB
}

// NewPostgresPhase8Storage creates an initialized PostgreSQL storage driver for Phase 8.
func NewPostgresPhase8Storage(db *sql.DB) *PostgresPhase8Storage {
	return &PostgresPhase8Storage{db: db}
}

// ==========================================
// 1. Scope Import Repository (PostgreSQL)
// ==========================================

func (s *PostgresPhase8Storage) SaveImportReview(ctx context.Context, review *models.ScopeImportReview) error {
	query := `
		INSERT INTO scope_imports (
			id, file_name, status, selected_root_domain, target_id,
			rules_discovered, include_hosts_count, exclude_hosts_count,
			regex_rules_count, path_rules_count, warnings_count, ambiguous_count,
			root_domains, normalizations, canonical_scope,
			original_file_sha256, canonical_scope_sha256, normalization_manifest_sha256, selection_reason,
			created_at, confirmed_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11, $12,
			$13, $14, $15,
			$16, $17, $18, $19,
			$20, $21
		)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			selected_root_domain = EXCLUDED.selected_root_domain,
			target_id = EXCLUDED.target_id,
			confirmed_at = EXCLUDED.confirmed_at,
			selection_reason = EXCLUDED.selection_reason;
	`
	rootJSON, _ := json.Marshal(review.RootDomains)
	normJSON, _ := json.Marshal(review.Normalizations)
	canonJSON, _ := json.Marshal(review.CanonicalScope)

	var targetIDVal *string
	if review.TargetID != "" {
		targetIDVal = &review.TargetID
	}

	_, err := s.db.ExecContext(ctx, query,
		review.ID, review.FileName, review.Status, review.SelectedRootDomain, targetIDVal,
		review.RulesDiscovered, review.IncludeHostsCount, review.ExcludeHostsCount,
		review.RegexRulesCount, review.PathRulesCount, review.WarningsCount, review.AmbiguousCount,
		rootJSON, normJSON, canonJSON,
		review.OriginalFileSHA256, review.CanonicalScopeSHA256, review.NormalizationManifestSHA256, review.SelectionReason,
		review.CreatedAt, review.ConfirmedAt,
	)
	return err
}

func (s *PostgresPhase8Storage) GetImportReview(ctx context.Context, id string) (*models.ScopeImportReview, error) {
	query := `
		SELECT id, file_name, status, selected_root_domain, COALESCE(target_id, ''),
		       rules_discovered, include_hosts_count, exclude_hosts_count,
		       regex_rules_count, path_rules_count, warnings_count, ambiguous_count,
		       root_domains, normalizations, canonical_scope,
		       COALESCE(original_file_sha256, ''), COALESCE(canonical_scope_sha256, ''),
		       COALESCE(normalization_manifest_sha256, ''), COALESCE(selection_reason, ''),
		       created_at, confirmed_at
		FROM scope_imports
		WHERE id = $1;
	`
	row := s.db.QueryRowContext(ctx, query, id)
	var rev models.ScopeImportReview
	var rootJSON, normJSON, canonJSON []byte
	var targetID string

	err := row.Scan(
		&rev.ID, &rev.FileName, &rev.Status, &rev.SelectedRootDomain, &targetID,
		&rev.RulesDiscovered, &rev.IncludeHostsCount, &rev.ExcludeHostsCount,
		&rev.RegexRulesCount, &rev.PathRulesCount, &rev.WarningsCount, &rev.AmbiguousCount,
		&rootJSON, &normJSON, &canonJSON,
		&rev.OriginalFileSHA256, &rev.CanonicalScopeSHA256,
		&rev.NormalizationManifestSHA256, &rev.SelectionReason,
		&rev.CreatedAt, &rev.ConfirmedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	rev.TargetID = targetID
	_ = json.Unmarshal(rootJSON, &rev.RootDomains)
	_ = json.Unmarshal(normJSON, &rev.Normalizations)
	rev.CanonicalScope = &models.CanonicalScope{}
	_ = json.Unmarshal(canonJSON, rev.CanonicalScope)

	return &rev, nil
}

func (s *PostgresPhase8Storage) ListImportReviews(ctx context.Context) ([]*models.ScopeImportReview, error) {
	query := `
		SELECT id, file_name, status, selected_root_domain, COALESCE(target_id, ''),
		       rules_discovered, include_hosts_count, exclude_hosts_count,
		       regex_rules_count, path_rules_count, warnings_count, ambiguous_count,
		       root_domains, normalizations, canonical_scope,
		       COALESCE(original_file_sha256, ''), COALESCE(canonical_scope_sha256, ''),
		       COALESCE(normalization_manifest_sha256, ''), COALESCE(selection_reason, ''),
		       created_at, confirmed_at
		FROM scope_imports
		ORDER BY created_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.ScopeImportReview
	for rows.Next() {
		var rev models.ScopeImportReview
		var rootJSON, normJSON, canonJSON []byte
		var targetID string
		if err := rows.Scan(
			&rev.ID, &rev.FileName, &rev.Status, &rev.SelectedRootDomain, &targetID,
			&rev.RulesDiscovered, &rev.IncludeHostsCount, &rev.ExcludeHostsCount,
			&rev.RegexRulesCount, &rev.PathRulesCount, &rev.WarningsCount, &rev.AmbiguousCount,
			&rootJSON, &normJSON, &canonJSON,
			&rev.OriginalFileSHA256, &rev.CanonicalScopeSHA256,
			&rev.NormalizationManifestSHA256, &rev.SelectionReason,
			&rev.CreatedAt, &rev.ConfirmedAt,
		); err != nil {
			return nil, err
		}
		rev.TargetID = targetID
		_ = json.Unmarshal(rootJSON, &rev.RootDomains)
		_ = json.Unmarshal(normJSON, &rev.Normalizations)
		rev.CanonicalScope = &models.CanonicalScope{}
		_ = json.Unmarshal(canonJSON, rev.CanonicalScope)
		list = append(list, &rev)
	}
	return list, nil
}

func (s *PostgresPhase8Storage) ConfirmImportReview(ctx context.Context, id string, selectedRootDomain string, targetID string) error {
	query := `
		UPDATE scope_imports
		SET status = 'CONFIRMED', selected_root_domain = $2, target_id = $3, confirmed_at = $4
		WHERE id = $1;
	`
	res, err := s.db.ExecContext(ctx, query, id, selectedRootDomain, targetID, time.Now().UTC())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ==========================================
// 2. JavaScript Intelligence Repository (PostgreSQL)
// ==========================================

func (s *PostgresPhase8Storage) SaveJSAsset(ctx context.Context, asset *models.JSAsset) error {
	query := `
		INSERT INTO js_assets (
			id, target_id, asset_id, url, parent_url, discovered_at,
			scope_in_scope, scope_reason, content_sha256, byte_size,
			is_third_party, fetch_status, line_count, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14
		)
		ON CONFLICT (id) DO UPDATE SET
			fetch_status = EXCLUDED.fetch_status,
			content_sha256 = EXCLUDED.content_sha256,
			byte_size = EXCLUDED.byte_size,
			line_count = EXCLUDED.line_count;
	`
	_, err := s.db.ExecContext(ctx, query,
		asset.ID, asset.TargetID, asset.AssetID, asset.URL, asset.ParentURL, asset.DiscoveredAt,
		asset.ScopeDecision.InScope, asset.ScopeDecision.Reason, asset.ContentSHA256, asset.ByteSize,
		asset.IsThirdParty, asset.FetchStatus, asset.LineCount, asset.CreatedAt,
	)
	return err
}

func (s *PostgresPhase8Storage) GetJSAsset(ctx context.Context, id string) (*models.JSAsset, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), url, parent_url, discovered_at,
		       scope_in_scope, COALESCE(scope_reason, ''), COALESCE(content_sha256, ''),
		       byte_size, is_third_party, fetch_status, line_count, created_at
		FROM js_assets
		WHERE id = $1;
	`
	row := s.db.QueryRowContext(ctx, query, id)
	var a models.JSAsset
	err := row.Scan(
		&a.ID, &a.TargetID, &a.AssetID, &a.URL, &a.ParentURL, &a.DiscoveredAt,
		&a.ScopeDecision.InScope, &a.ScopeDecision.Reason, &a.ContentSHA256,
		&a.ByteSize, &a.IsThirdParty, &a.FetchStatus, &a.LineCount, &a.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (s *PostgresPhase8Storage) ListJSAssets(ctx context.Context, targetID, assetID string) ([]*models.JSAsset, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), url, parent_url, discovered_at,
		       scope_in_scope, COALESCE(scope_reason, ''), COALESCE(content_sha256, ''),
		       byte_size, is_third_party, fetch_status, line_count, created_at
		FROM js_assets
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY discovered_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.JSAsset
	for rows.Next() {
		var a models.JSAsset
		if err := rows.Scan(
			&a.ID, &a.TargetID, &a.AssetID, &a.URL, &a.ParentURL, &a.DiscoveredAt,
			&a.ScopeDecision.InScope, &a.ScopeDecision.Reason, &a.ContentSHA256,
			&a.ByteSize, &a.IsThirdParty, &a.FetchStatus, &a.LineCount, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, &a)
	}
	return list, nil
}

func (s *PostgresPhase8Storage) SaveJSReference(ctx context.Context, ref *models.JSReference) error {
	query := `
		INSERT INTO js_references (
			id, target_id, asset_id, js_asset_id, source_url,
			category, extracted_value, normalized_value, line_number,
			byte_offset, source_fragment, scope_status, confidence,
			evidence_id, provenance_sha, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13,
			NULLIF($14, ''), $15, $16
		)
		ON CONFLICT (id) DO NOTHING;
	`
	_, err := s.db.ExecContext(ctx, query,
		ref.ID, ref.TargetID, ref.AssetID, ref.JSAssetID, ref.SourceURL,
		ref.Category, ref.ExtractedValue, ref.NormalizedValue, ref.LineNumber,
		ref.ByteOffset, ref.SourceFragment, ref.ScopeStatus, ref.Confidence,
		ref.EvidenceID, ref.ProvenanceSHA, ref.CreatedAt,
	)
	return err
}

func (s *PostgresPhase8Storage) ListJSReferences(ctx context.Context, targetID, jsAssetID string) ([]*models.JSReference, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), js_asset_id, source_url,
		       category, extracted_value, normalized_value, COALESCE(line_number, 0),
		       COALESCE(byte_offset, 0), COALESCE(source_fragment, ''), scope_status, confidence,
		       COALESCE(evidence_id, ''), COALESCE(provenance_sha, ''), created_at
		FROM js_references
		WHERE target_id = $1 AND ($2 = '' OR js_asset_id = $2)
		ORDER BY created_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query, targetID, jsAssetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.JSReference
	for rows.Next() {
		var ref models.JSReference
		if err := rows.Scan(
			&ref.ID, &ref.TargetID, &ref.AssetID, &ref.JSAssetID, &ref.SourceURL,
			&ref.Category, &ref.ExtractedValue, &ref.NormalizedValue, &ref.LineNumber,
			&ref.ByteOffset, &ref.SourceFragment, &ref.ScopeStatus, &ref.Confidence,
			&ref.EvidenceID, &ref.ProvenanceSHA, &ref.CreatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, &ref)
	}
	return list, nil
}

func (s *PostgresPhase8Storage) SaveSecretIndicator(ctx context.Context, sec *models.JSSecretIndicator) error {
	query := `
		INSERT INTO js_secret_indicators (
			id, target_id, asset_id, js_asset_id, secret_type,
			location, masked_preview, sha256, confidence,
			source_js_asset, evidence_id, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5,
			$6, $7, $8, $9,
			$10, NULLIF($11, ''), $12
		)
		ON CONFLICT (id) DO NOTHING;
	`
	_, err := s.db.ExecContext(ctx, query,
		sec.ID, sec.TargetID, sec.AssetID, sec.JSAssetID, sec.SecretType,
		sec.Location, sec.MaskedPreview, sec.SHA256, sec.Confidence,
		sec.SourceJSAsset, sec.EvidenceID, sec.CreatedAt,
	)
	return err
}

func (s *PostgresPhase8Storage) ListSecretIndicators(ctx context.Context, targetID, assetID string) ([]*models.JSSecretIndicator, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), js_asset_id, secret_type,
		       location, masked_preview, sha256, confidence,
		       source_js_asset, COALESCE(evidence_id, ''), created_at
		FROM js_secret_indicators
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.JSSecretIndicator
	for rows.Next() {
		var sec models.JSSecretIndicator
		if err := rows.Scan(
			&sec.ID, &sec.TargetID, &sec.AssetID, &sec.JSAssetID, &sec.SecretType,
			&sec.Location, &sec.MaskedPreview, &sec.SHA256, &sec.Confidence,
			&sec.SourceJSAsset, &sec.EvidenceID, &sec.CreatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, &sec)
	}
	return list, nil
}

// ==========================================
// 3. Cloud Reference Intelligence Repository (PostgreSQL)
// ==========================================

func (s *PostgresPhase8Storage) SaveCloudReference(ctx context.Context, ref *models.CloudReference) error {
	query := `
		INSERT INTO cloud_references (
			id, target_id, asset_id, provider, resource_type,
			raw_reference, normalized_target, source_origin, source_location,
			scope_status, validation_status, status_code, public_accessible,
			evidence_id, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13,
			NULLIF($14, ''), $15
		)
		ON CONFLICT (id) DO UPDATE SET
			validation_status = EXCLUDED.validation_status,
			status_code = EXCLUDED.status_code,
			public_accessible = EXCLUDED.public_accessible;
	`
	_, err := s.db.ExecContext(ctx, query,
		ref.ID, ref.TargetID, ref.AssetID, ref.Provider, ref.ResourceType,
		ref.RawReference, ref.NormalizedTarget, ref.SourceOrigin, ref.SourceLocation,
		ref.ScopeStatus, ref.ValidationStatus, ref.StatusCode, ref.PublicAccessible,
		ref.EvidenceID, ref.CreatedAt,
	)
	return err
}

func (s *PostgresPhase8Storage) GetCloudReference(ctx context.Context, id string) (*models.CloudReference, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), provider, resource_type,
		       raw_reference, normalized_target, source_origin, source_location,
		       scope_status, validation_status, COALESCE(status_code, 0), public_accessible,
		       COALESCE(evidence_id, ''), created_at
		FROM cloud_references
		WHERE id = $1;
	`
	row := s.db.QueryRowContext(ctx, query, id)
	var ref models.CloudReference
	err := row.Scan(
		&ref.ID, &ref.TargetID, &ref.AssetID, &ref.Provider, &ref.ResourceType,
		&ref.RawReference, &ref.NormalizedTarget, &ref.SourceOrigin, &ref.SourceLocation,
		&ref.ScopeStatus, &ref.ValidationStatus, &ref.StatusCode, &ref.PublicAccessible,
		&ref.EvidenceID, &ref.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &ref, nil
}

func (s *PostgresPhase8Storage) ListCloudReferences(ctx context.Context, targetID, assetID string) ([]*models.CloudReference, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), provider, resource_type,
		       raw_reference, normalized_target, source_origin, source_location,
		       scope_status, validation_status, COALESCE(status_code, 0), public_accessible,
		       COALESCE(evidence_id, ''), created_at
		FROM cloud_references
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.CloudReference
	for rows.Next() {
		var ref models.CloudReference
		if err := rows.Scan(
			&ref.ID, &ref.TargetID, &ref.AssetID, &ref.Provider, &ref.ResourceType,
			&ref.RawReference, &ref.NormalizedTarget, &ref.SourceOrigin, &ref.SourceLocation,
			&ref.ScopeStatus, &ref.ValidationStatus, &ref.StatusCode, &ref.PublicAccessible,
			&ref.EvidenceID, &ref.CreatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, &ref)
	}
	return list, nil
}

func (s *PostgresPhase8Storage) UpdateCloudValidation(ctx context.Context, id string, status string, statusCode int, publicAccessible bool) error {
	query := `
		UPDATE cloud_references
		SET validation_status = $2, status_code = $3, public_accessible = $4
		WHERE id = $1;
	`
	res, err := s.db.ExecContext(ctx, query, id, status, statusCode, publicAccessible)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ==========================================
// 4. WAF Intelligence Repository (PostgreSQL)
// ==========================================

func (s *PostgresPhase8Storage) SaveWAFObservation(ctx context.Context, obs *models.WAFObservation) error {
	query := `
		INSERT INTO waf_observations (
			id, target_id, asset_id, provider, confidence,
			evidence_ids, matched_indicators, observed_headers, throttling_state,
			current_rate_limit_rps, retry_after_seconds, circuit_breaker_open,
			throttle_reason, created_at, updated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15
		)
		ON CONFLICT (id) DO UPDATE SET
			provider = EXCLUDED.provider,
			confidence = EXCLUDED.confidence,
			throttling_state = EXCLUDED.throttling_state,
			current_rate_limit_rps = EXCLUDED.current_rate_limit_rps,
			retry_after_seconds = EXCLUDED.retry_after_seconds,
			circuit_breaker_open = EXCLUDED.circuit_breaker_open,
			throttle_reason = EXCLUDED.throttle_reason,
			updated_at = EXCLUDED.updated_at;
	`
	evJSON, _ := json.Marshal(obs.EvidenceIDs)
	matchJSON, _ := json.Marshal(obs.MatchedIndicators)
	hdrJSON, _ := json.Marshal(obs.ObservedHeaders)

	_, err := s.db.ExecContext(ctx, query,
		obs.ID, obs.TargetID, obs.AssetID, obs.Provider, obs.Confidence,
		evJSON, matchJSON, hdrJSON, obs.ThrottlingState,
		obs.CurrentRateLimitRPS, obs.RetryAfterSeconds, obs.CircuitBreakerOpen,
		obs.ThrottleReason, obs.CreatedAt, obs.UpdatedAt,
	)
	return err
}

func (s *PostgresPhase8Storage) GetWAFObservation(ctx context.Context, targetID, assetID string) (*models.WAFObservation, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), provider, confidence,
		       evidence_ids, matched_indicators, observed_headers, throttling_state,
		       current_rate_limit_rps, COALESCE(retry_after_seconds, 0), circuit_breaker_open,
		       COALESCE(throttle_reason, ''), created_at, updated_at
		FROM waf_observations
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		LIMIT 1;
	`
	row := s.db.QueryRowContext(ctx, query, targetID, assetID)
	var obs models.WAFObservation
	var evJSON, matchJSON, hdrJSON []byte

	err := row.Scan(
		&obs.ID, &obs.TargetID, &obs.AssetID, &obs.Provider, &obs.Confidence,
		&evJSON, &matchJSON, &hdrJSON, &obs.ThrottlingState,
		&obs.CurrentRateLimitRPS, &obs.RetryAfterSeconds, &obs.CircuitBreakerOpen,
		&obs.ThrottleReason, &obs.CreatedAt, &obs.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(evJSON, &obs.EvidenceIDs)
	_ = json.Unmarshal(matchJSON, &obs.MatchedIndicators)
	_ = json.Unmarshal(hdrJSON, &obs.ObservedHeaders)

	return &obs, nil
}

func (s *PostgresPhase8Storage) ListWAFObservations(ctx context.Context, targetID string) ([]*models.WAFObservation, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), provider, confidence,
		       evidence_ids, matched_indicators, observed_headers, throttling_state,
		       current_rate_limit_rps, COALESCE(retry_after_seconds, 0), circuit_breaker_open,
		       COALESCE(throttle_reason, ''), created_at, updated_at
		FROM waf_observations
		WHERE target_id = $1
		ORDER BY updated_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.WAFObservation
	for rows.Next() {
		var obs models.WAFObservation
		var evJSON, matchJSON, hdrJSON []byte
		if err := rows.Scan(
			&obs.ID, &obs.TargetID, &obs.AssetID, &obs.Provider, &obs.Confidence,
			&evJSON, &matchJSON, &hdrJSON, &obs.ThrottlingState,
			&obs.CurrentRateLimitRPS, &obs.RetryAfterSeconds, &obs.CircuitBreakerOpen,
			&obs.ThrottleReason, &obs.CreatedAt, &obs.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evJSON, &obs.EvidenceIDs)
		_ = json.Unmarshal(matchJSON, &obs.MatchedIndicators)
		_ = json.Unmarshal(hdrJSON, &obs.ObservedHeaders)
		list = append(list, &obs)
	}
	return list, nil
}

// ==========================================
// 5. Hunting Planner Repository (PostgreSQL)
// ==========================================

func (s *PostgresPhase8Storage) SaveInvestigationPlan(ctx context.Context, plan *models.InvestigationPlan) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO investigation_plans (
			id, target_id, asset_id, hypothesis_id, title,
			reason, hypothesis, why_interesting, required_evidence,
			evidence_required_count, evidence_satisfied_count, safe_validation,
			expected_observation, alternative_explanation, stop_condition,
			scope_requirements, risk, confidence, epistemic_status, status,
			source_evidence_ids, created_at, updated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, ''), $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22, $23
		)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			evidence_satisfied_count = EXCLUDED.evidence_satisfied_count,
			updated_at = EXCLUDED.updated_at;
	`
	whyJSON, _ := json.Marshal(plan.WhyInteresting)
	reqEvJSON, _ := json.Marshal(plan.RequiredEvidence)
	scopeReqJSON, _ := json.Marshal(plan.ScopeRequirements)
	sourceEvJSON, _ := json.Marshal(plan.SourceEvidenceIDs)

	_, err = tx.ExecContext(ctx, query,
		plan.ID, plan.TargetID, plan.AssetID, plan.HypothesisID, plan.Title,
		plan.Reason, plan.Hypothesis, whyJSON, reqEvJSON,
		plan.EvidenceRequiredCount, plan.EvidenceSatisfiedCount, plan.SafeValidation,
		plan.ExpectedObservation, plan.AlternativeExplanation, plan.StopCondition,
		scopeReqJSON, plan.Risk, plan.Confidence, plan.EpistemicStatus, plan.Status,
		sourceEvJSON, plan.CreatedAt, plan.UpdatedAt,
	)
	if err != nil {
		return err
	}

	// Save or replace steps
	_, err = tx.ExecContext(ctx, `DELETE FROM investigation_plan_steps WHERE plan_id = $1`, plan.ID)
	if err != nil {
		return err
	}

	stepQuery := `
		INSERT INTO investigation_plan_steps (
			plan_id, step_number, action_type, description, target_url,
			status, approved_by_human, approved_at, result_evidence_id, result_observation, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11);
	`
	for _, step := range plan.Steps {
		_, err = tx.ExecContext(ctx, stepQuery,
			plan.ID, step.StepNumber, step.ActionType, step.Description, step.TargetURL,
			step.Status, step.ApprovedByHuman, step.ApprovedAt, step.ResultEvidenceID,
			step.ResultObservation, plan.CreatedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *PostgresPhase8Storage) GetInvestigationPlan(ctx context.Context, id string) (*models.InvestigationPlan, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(hypothesis_id, ''), title,
		       reason, hypothesis, why_interesting, required_evidence,
		       evidence_required_count, evidence_satisfied_count, safe_validation,
		       expected_observation, alternative_explanation, stop_condition,
		       scope_requirements, risk, confidence, epistemic_status, status,
		       source_evidence_ids, created_at, updated_at
		FROM investigation_plans
		WHERE id = $1;
	`
	row := s.db.QueryRowContext(ctx, query, id)
	var p models.InvestigationPlan
	var whyJSON, reqEvJSON, scopeReqJSON, sourceEvJSON []byte

	err := row.Scan(
		&p.ID, &p.TargetID, &p.AssetID, &p.HypothesisID, &p.Title,
		&p.Reason, &p.Hypothesis, &whyJSON, &reqEvJSON,
		&p.EvidenceRequiredCount, &p.EvidenceSatisfiedCount, &p.SafeValidation,
		&p.ExpectedObservation, &p.AlternativeExplanation, &p.StopCondition,
		&scopeReqJSON, &p.Risk, &p.Confidence, &p.EpistemicStatus, &p.Status,
		&sourceEvJSON, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(whyJSON, &p.WhyInteresting)
	_ = json.Unmarshal(reqEvJSON, &p.RequiredEvidence)
	_ = json.Unmarshal(scopeReqJSON, &p.ScopeRequirements)
	_ = json.Unmarshal(sourceEvJSON, &p.SourceEvidenceIDs)

	// Fetch steps
	stepRows, err := s.db.QueryContext(ctx, `
		SELECT step_number, action_type, description, target_url, status,
		       approved_by_human, approved_at, COALESCE(result_evidence_id, ''), COALESCE(result_observation, '')
		FROM investigation_plan_steps
		WHERE plan_id = $1
		ORDER BY step_number ASC;
	`, id)
	if err == nil {
		defer stepRows.Close()
		for stepRows.Next() {
			var st models.InvestigationPlanStep
			_ = stepRows.Scan(
				&st.StepNumber, &st.ActionType, &st.Description, &st.TargetURL, &st.Status,
				&st.ApprovedByHuman, &st.ApprovedAt, &st.ResultEvidenceID, &st.ResultObservation,
			)
			p.Steps = append(p.Steps, st)
		}
	}

	return &p, nil
}

func (s *PostgresPhase8Storage) ListInvestigationPlans(ctx context.Context, targetID, assetID string) ([]*models.InvestigationPlan, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(hypothesis_id, ''), title,
		       reason, hypothesis, why_interesting, required_evidence,
		       evidence_required_count, evidence_satisfied_count, safe_validation,
		       expected_observation, alternative_explanation, stop_condition,
		       scope_requirements, risk, confidence, epistemic_status, status,
		       source_evidence_ids, created_at, updated_at
		FROM investigation_plans
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at DESC;
	`
	rows, err := s.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.InvestigationPlan
	for rows.Next() {
		var p models.InvestigationPlan
		var whyJSON, reqEvJSON, scopeReqJSON, sourceEvJSON []byte
		if err := rows.Scan(
			&p.ID, &p.TargetID, &p.AssetID, &p.HypothesisID, &p.Title,
			&p.Reason, &p.Hypothesis, &whyJSON, &reqEvJSON,
			&p.EvidenceRequiredCount, &p.EvidenceSatisfiedCount, &p.SafeValidation,
			&p.ExpectedObservation, &p.AlternativeExplanation, &p.StopCondition,
			&scopeReqJSON, &p.Risk, &p.Confidence, &p.EpistemicStatus, &p.Status,
			&sourceEvJSON, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(whyJSON, &p.WhyInteresting)
		_ = json.Unmarshal(reqEvJSON, &p.RequiredEvidence)
		_ = json.Unmarshal(scopeReqJSON, &p.ScopeRequirements)
		_ = json.Unmarshal(sourceEvJSON, &p.SourceEvidenceIDs)
		list = append(list, &p)
	}
	return list, nil
}

func (s *PostgresPhase8Storage) ApprovePlanStep(ctx context.Context, planID string, stepNumber int) error {
	now := time.Now().UTC()
	query := `
		UPDATE investigation_plan_steps
		SET status = 'APPROVED', approved_by_human = true, approved_at = $3
		WHERE plan_id = $1 AND step_number = $2;
	`
	res, err := s.db.ExecContext(ctx, query, planID, stepNumber, now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}

	_, _ = s.db.ExecContext(ctx, `UPDATE investigation_plans SET status = 'APPROVED', updated_at = $2 WHERE id = $1`, planID, now)
	return nil
}

func (s *PostgresPhase8Storage) UpdatePlanStatus(ctx context.Context, planID string, status string) error {
	query := `
		UPDATE investigation_plans
		SET status = $2, updated_at = $3
		WHERE id = $1;
	`
	res, err := s.db.ExecContext(ctx, query, planID, status, time.Now().UTC())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
