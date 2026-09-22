package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// PostgresStorage implements TargetRepository using PostgreSQL.
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage wraps an initialized sql.DB connection pool.
func NewPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

// Create inserts a new authorized target into PostgreSQL.
func (p *PostgresStorage) Create(ctx context.Context, target *models.Target) error {
	query := `
		INSERT INTO targets (
			id, name, root_domain, allowed_domains, allowed_url_patterns, excluded_patterns, status,
			scope_import_id, canonical_scope_hash, confirmation_timestamp,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := p.db.ExecContext(ctx, query,
		target.ID,
		target.Name,
		target.RootDomain,
		strings.Join(target.AllowedDomains, ","),
		strings.Join(target.AllowedURLPatterns, ","),
		strings.Join(target.ExcludedPatterns, ","),
		string(target.Status),
		target.ScopeImportID,
		target.CanonicalScopeHash,
		target.ConfirmationTimestamp,
		target.CreatedAt,
		target.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert target: %w", err)
	}
	return nil
}

// GetByID fetches a target by its ID.
func (p *PostgresStorage) GetByID(ctx context.Context, id string) (*models.Target, error) {
	query := `
		SELECT id, name, root_domain, allowed_domains, allowed_url_patterns, excluded_patterns, status,
		       COALESCE(scope_import_id, ''), COALESCE(canonical_scope_hash, ''), confirmation_timestamp,
		       created_at, updated_at
		FROM targets WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)

	var t models.Target
	var allowedDomainsStr, allowedURLsStr, excludedStr, statusStr string

	err := row.Scan(
		&t.ID, &t.Name, &t.RootDomain, &allowedDomainsStr, &allowedURLsStr, &excludedStr, &statusStr,
		&t.ScopeImportID, &t.CanonicalScopeHash, &t.ConfirmationTimestamp,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("failed to query target: %w", err)
	}

	t.Status = models.TargetStatus(statusStr)
	t.AllowedDomains = splitNonEmpty(allowedDomainsStr)
	t.AllowedURLPatterns = splitNonEmpty(allowedURLsStr)
	t.ExcludedPatterns = splitNonEmpty(excludedStr)

	return &t, nil
}

// List returns all configured targets.
func (p *PostgresStorage) List(ctx context.Context) ([]*models.Target, error) {
	query := `
		SELECT id, name, root_domain, allowed_domains, allowed_url_patterns, excluded_patterns, status,
		       COALESCE(scope_import_id, ''), COALESCE(canonical_scope_hash, ''), confirmation_timestamp,
		       created_at, updated_at
		FROM targets ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query targets: %w", err)
	}
	defer rows.Close()

	var targets []*models.Target
	for rows.Next() {
		var t models.Target
		var allowedDomainsStr, allowedURLsStr, excludedStr, statusStr string

		if err := rows.Scan(
			&t.ID, &t.Name, &t.RootDomain, &allowedDomainsStr, &allowedURLsStr, &excludedStr, &statusStr,
			&t.ScopeImportID, &t.CanonicalScopeHash, &t.ConfirmationTimestamp,
			&t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		t.Status = models.TargetStatus(statusStr)
		t.AllowedDomains = splitNonEmpty(allowedDomainsStr)
		t.AllowedURLPatterns = splitNonEmpty(allowedURLsStr)
		t.ExcludedPatterns = splitNonEmpty(excludedStr)
		targets = append(targets, &t)
	}
	return targets, nil
}

// Delete removes a target by ID.
func (p *PostgresStorage) Delete(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, `DELETE FROM targets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Update modifies an existing target in PostgreSQL.
func (p *PostgresStorage) Update(ctx context.Context, target *models.Target) error {
	query := `
		UPDATE targets
		SET name = $2, root_domain = $3, allowed_domains = $4, allowed_url_patterns = $5, excluded_patterns = $6, status = $7, updated_at = $8
		WHERE id = $1
	`
	res, err := p.db.ExecContext(ctx, query,
		target.ID,
		target.Name,
		target.RootDomain,
		strings.Join(target.AllowedDomains, ","),
		strings.Join(target.AllowedURLPatterns, ","),
		strings.Join(target.ExcludedPatterns, ","),
		string(target.Status),
		target.UpdatedAt,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateJob persists a scan job to PostgreSQL.
func (p *PostgresStorage) CreateJob(ctx context.Context, job *models.ScanJob) error {
	metaJSON, err := json.Marshal(job.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO scan_jobs (id, target_id, type, status, created_at, started_at, completed_at, error, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = p.db.ExecContext(ctx, query,
		job.ID,
		job.TargetID,
		job.Type,
		string(job.Status),
		job.CreatedAt,
		job.StartedAt,
		job.CompletedAt,
		job.Error,
		string(metaJSON),
	)
	return err
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Recon Operations for PostgreSQL
func (p *PostgresStorage) SaveAsset(ctx context.Context, asset *models.Asset) error {
	query := `
		INSERT INTO assets (id, target_id, hostname, asset_type, status, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (target_id, hostname)
		DO UPDATE SET last_seen = EXCLUDED.last_seen, status = EXCLUDED.status
	`
	_, err := p.db.ExecContext(ctx, query, asset.ID, asset.TargetID, asset.Hostname, asset.AssetType, asset.Status, asset.FirstSeen, asset.LastSeen)
	return err
}

func (p *PostgresStorage) GetAssetByHostname(ctx context.Context, targetID, hostname string) (*models.Asset, error) {
	query := `
		SELECT id, target_id, hostname, asset_type, status, first_seen, last_seen
		FROM assets WHERE target_id = $1 AND hostname = $2
	`
	row := p.db.QueryRowContext(ctx, query, targetID, hostname)
	var a models.Asset
	if err := row.Scan(&a.ID, &a.TargetID, &a.Hostname, &a.AssetType, &a.Status, &a.FirstSeen, &a.LastSeen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (p *PostgresStorage) ListAssets(ctx context.Context, targetID string) ([]*models.Asset, error) {
	query := `
		SELECT id, target_id, hostname, asset_type, status, first_seen, last_seen
		FROM assets WHERE ($1 = '' OR target_id = $1)
		ORDER BY last_seen DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.Asset
	for rows.Next() {
		var a models.Asset
		if err := rows.Scan(&a.ID, &a.TargetID, &a.Hostname, &a.AssetType, &a.Status, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		result = append(result, &a)
	}
	return result, nil
}

func (p *PostgresStorage) UpdateAssetStatus(ctx context.Context, id string, status string) error {
	query := `UPDATE assets SET status = $2, last_seen = NOW() WHERE id = $1`
	_, err := p.db.ExecContext(ctx, query, id, status)
	return err
}

func (p *PostgresStorage) SaveDNSRecord(ctx context.Context, record *models.DNSRecord) error {
	query := `
		INSERT INTO dns_records (id, asset_id, record_type, value, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (asset_id, record_type, value)
		DO UPDATE SET last_seen = EXCLUDED.last_seen
	`
	_, err := p.db.ExecContext(ctx, query, record.ID, record.AssetID, record.RecordType, record.Value, record.FirstSeen, record.LastSeen)
	return err
}

func (p *PostgresStorage) ListDNSRecords(ctx context.Context, assetID string) ([]*models.DNSRecord, error) {
	query := `
		SELECT id, asset_id, record_type, value, first_seen, last_seen
		FROM dns_records WHERE asset_id = $1
		ORDER BY first_seen ASC
	`
	rows, err := p.db.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.DNSRecord
	for rows.Next() {
		var r models.DNSRecord
		if err := rows.Scan(&r.ID, &r.AssetID, &r.RecordType, &r.Value, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		result = append(result, &r)
	}
	return result, nil
}

func (p *PostgresStorage) SaveHTTPService(ctx context.Context, svc *models.HTTPService) error {
	query := `
		INSERT INTO http_services (id, asset_id, url, status_code, content_type, response_time, final_url, server_header, tls_version, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (asset_id, url)
		DO UPDATE SET status_code = EXCLUDED.status_code, content_type = EXCLUDED.content_type, response_time = EXCLUDED.response_time, final_url = EXCLUDED.final_url, server_header = EXCLUDED.server_header, tls_version = EXCLUDED.tls_version, last_seen = EXCLUDED.last_seen
	`
	_, err := p.db.ExecContext(ctx, query, svc.ID, svc.AssetID, svc.URL, svc.StatusCode, svc.ContentType, svc.ResponseTime, svc.FinalURL, svc.ServerHeader, svc.TLSVersion, svc.FirstSeen, svc.LastSeen)
	return err
}

func (p *PostgresStorage) ListHTTPServices(ctx context.Context, targetID string) ([]*models.HTTPService, error) {
	query := `
		SELECT hs.id, hs.asset_id, hs.url, hs.status_code, hs.content_type, hs.response_time, hs.final_url, hs.server_header, hs.tls_version, hs.first_seen, hs.last_seen
		FROM http_services hs
		JOIN assets a ON hs.asset_id = a.id
		WHERE ($1 = '' OR a.target_id = $1)
		ORDER BY hs.last_seen DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.HTTPService
	for rows.Next() {
		var s models.HTTPService
		var ct, fu, sh, tv sql.NullString
		if err := rows.Scan(&s.ID, &s.AssetID, &s.URL, &s.StatusCode, &ct, &s.ResponseTime, &fu, &sh, &tv, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, err
		}
		s.ContentType = ct.String
		s.FinalURL = fu.String
		s.ServerHeader = sh.String
		s.TLSVersion = tv.String
		result = append(result, &s)
	}
	return result, nil
}

func (p *PostgresStorage) SaveURL(ctx context.Context, u *models.URLRecord) error {
	query := `
		INSERT INTO urls (id, asset_id, url, source, depth, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (asset_id, url)
		DO UPDATE SET last_seen = EXCLUDED.last_seen
	`
	_, err := p.db.ExecContext(ctx, query, u.ID, u.AssetID, u.URL, u.Source, u.Depth, u.FirstSeen, u.LastSeen)
	return err
}

func (p *PostgresStorage) ListURLs(ctx context.Context, targetID string) ([]*models.URLRecord, error) {
	query := `
		SELECT u.id, u.asset_id, u.url, u.source, u.depth, u.first_seen, u.last_seen
		FROM urls u
		JOIN assets a ON u.asset_id = a.id
		WHERE ($1 = '' OR a.target_id = $1)
		ORDER BY u.depth ASC, u.last_seen DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*models.URLRecord
	for rows.Next() {
		var u models.URLRecord
		if err := rows.Scan(&u.ID, &u.AssetID, &u.URL, &u.Source, &u.Depth, &u.FirstSeen, &u.LastSeen); err != nil {
			return nil, err
		}
		result = append(result, &u)
	}
	return result, nil
}

func (p *PostgresStorage) SaveReconRun(ctx context.Context, run *models.ReconRun) error {
	query := `
		INSERT INTO recon_runs (id, job_id, target_id, status, hosts_discovered, hosts_resolved, http_probed, urls_discovered, urls_crawled, errors, skipped_out_of_scope, started_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := p.db.ExecContext(ctx, query, run.ID, run.JobID, run.TargetID, string(run.Status), run.HostsDiscovered, run.HostsResolved, run.HTTPProbed, run.URLsDiscovered, run.URLsCrawled, run.Errors, run.SkippedOutOfScope, run.StartedAt, run.CompletedAt)
	return err
}

func (p *PostgresStorage) GetReconRunByJobID(ctx context.Context, jobID string) (*models.ReconRun, error) {
	query := `
		SELECT id, job_id, target_id, status, hosts_discovered, hosts_resolved, http_probed, urls_discovered, urls_crawled, errors, skipped_out_of_scope, started_at, completed_at
		FROM recon_runs WHERE job_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, jobID)
	var r models.ReconRun
	var statusStr string
	if err := row.Scan(&r.ID, &r.JobID, &r.TargetID, &statusStr, &r.HostsDiscovered, &r.HostsResolved, &r.HTTPProbed, &r.URLsDiscovered, &r.URLsCrawled, &r.Errors, &r.SkippedOutOfScope, &r.StartedAt, &r.CompletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.Status = models.JobStatus(statusStr)
	return &r, nil
}

func (p *PostgresStorage) UpdateReconRun(ctx context.Context, run *models.ReconRun) error {
	query := `
		UPDATE recon_runs
		SET status = $2, hosts_discovered = $3, hosts_resolved = $4, http_probed = $5, urls_discovered = $6, urls_crawled = $7, errors = $8, skipped_out_of_scope = $9, completed_at = $10
		WHERE job_id = $1
	`
	_, err := p.db.ExecContext(ctx, query, run.JobID, string(run.Status), run.HostsDiscovered, run.HostsResolved, run.HTTPProbed, run.URLsDiscovered, run.URLsCrawled, run.Errors, run.SkippedOutOfScope, run.CompletedAt)
	return err
}

// -----------------------------------------------------------------------------
// Phase 3 Asset Intelligence Operations (PostgreSQL)
// -----------------------------------------------------------------------------

func (p *PostgresStorage) SaveTechnologyObservation(ctx context.Context, obs *models.TechnologyObservation) error {
	query := `
		INSERT INTO technology_observations (id, asset_id, target_id, service_id, technology_name, category, version, confidence, detection_source, evidence, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (asset_id, technology_name, version)
		DO UPDATE SET last_seen = EXCLUDED.last_seen, evidence = EXCLUDED.evidence,
		              confidence = CASE WHEN EXCLUDED.confidence = 'HIGH' THEN 'HIGH' ELSE technology_observations.confidence END
	`
	_, err := p.db.ExecContext(ctx, query,
		obs.ID, obs.AssetID, obs.TargetID, obs.ServiceID, obs.TechnologyName, obs.Category, obs.Version,
		string(obs.Confidence), obs.DetectionSource, obs.Evidence, obs.FirstSeen, obs.LastSeen,
	)
	return err
}

func (p *PostgresStorage) ListTechnologyObservations(ctx context.Context, filter models.TechnologyFilter) ([]*models.TechnologyObservation, int, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	conditions = append(conditions, fmt.Sprintf("target_id = $%d", idx))
	args = append(args, filter.TargetID)
	idx++

	if filter.AssetID != "" {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", idx))
		args = append(args, filter.AssetID)
		idx++
	}
	if filter.Category != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(category) = LOWER($%d)", idx))
		args = append(args, filter.Category)
		idx++
	}
	if filter.Confidence != "" {
		conditions = append(conditions, fmt.Sprintf("confidence = $%d", idx))
		args = append(args, string(filter.Confidence))
		idx++
	}
	if filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("technology_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Name+"%")
		idx++
	}

	whereClause := strings.Join(conditions, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM technology_observations WHERE %s", whereClause)
	var total int
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, asset_id, target_id, service_id, technology_name, category, version, confidence, detection_source, evidence, first_seen, last_seen
		FROM technology_observations
		WHERE %s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*models.TechnologyObservation
	for rows.Next() {
		var o models.TechnologyObservation
		var conf string
		var sID, ver sql.NullString
		if err := rows.Scan(&o.ID, &o.AssetID, &o.TargetID, &sID, &o.TechnologyName, &o.Category, &ver, &conf, &o.DetectionSource, &o.Evidence, &o.FirstSeen, &o.LastSeen); err != nil {
			return nil, 0, err
		}
		if sID.Valid {
			o.ServiceID = sID.String
		}
		if ver.Valid {
			v := ver.String
			o.Version = &v
		}
		o.Confidence = models.ConfidenceLevel(conf)
		results = append(results, &o)
	}
	return results, total, nil
}

func (p *PostgresStorage) SaveServiceObservation(ctx context.Context, obs *models.ServiceObservation) error {
	headersJSON, _ := json.Marshal(obs.Headers)
	query := `
		INSERT INTO service_observations (id, asset_id, target_id, service_identity, scheme, port, status_code, page_title, web_server, content_type, content_length, response_time_ms, tls_version, headers_snapshot, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (asset_id, service_identity)
		DO UPDATE SET status_code = EXCLUDED.status_code, page_title = EXCLUDED.page_title, web_server = EXCLUDED.web_server, content_type = EXCLUDED.content_type, content_length = EXCLUDED.content_length, response_time_ms = EXCLUDED.response_time_ms, tls_version = EXCLUDED.tls_version, headers_snapshot = EXCLUDED.headers_snapshot, last_seen = EXCLUDED.last_seen
	`
	_, err := p.db.ExecContext(ctx, query,
		obs.ID, obs.AssetID, obs.TargetID, obs.ServiceIdentity, obs.Scheme, obs.Port, obs.StatusCode,
		obs.PageTitle, obs.WebServer, obs.ContentType, obs.ContentLength, obs.ResponseTimeMS,
		obs.TLSVersion, string(headersJSON), obs.FirstSeen, obs.LastSeen,
	)
	return err
}

func (p *PostgresStorage) ListServiceObservations(ctx context.Context, filter models.ServiceFilter) ([]*models.ServiceObservation, int, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	conditions = append(conditions, fmt.Sprintf("target_id = $%d", idx))
	args = append(args, filter.TargetID)
	idx++

	if filter.AssetID != "" {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", idx))
		args = append(args, filter.AssetID)
		idx++
	}
	if filter.Scheme != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(scheme) = LOWER($%d)", idx))
		args = append(args, filter.Scheme)
		idx++
	}
	if filter.Port > 0 {
		conditions = append(conditions, fmt.Sprintf("port = $%d", idx))
		args = append(args, filter.Port)
		idx++
	}
	if filter.StatusCode > 0 {
		conditions = append(conditions, fmt.Sprintf("status_code = $%d", idx))
		args = append(args, filter.StatusCode)
		idx++
	}

	whereClause := strings.Join(conditions, " AND ")

	var total int
	if err := p.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM service_observations WHERE %s", whereClause), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, asset_id, target_id, service_identity, scheme, port, status_code, page_title, web_server, content_type, content_length, response_time_ms, tls_version, headers_snapshot, first_seen, last_seen
		FROM service_observations
		WHERE %s
		ORDER BY last_seen DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*models.ServiceObservation
	for rows.Next() {
		var s models.ServiceObservation
		var pageTitle, webServer, contentType, tlsVer sql.NullString
		var headersRaw []byte
		if err := rows.Scan(&s.ID, &s.AssetID, &s.TargetID, &s.ServiceIdentity, &s.Scheme, &s.Port, &s.StatusCode, &pageTitle, &webServer, &contentType, &s.ContentLength, &s.ResponseTimeMS, &tlsVer, &headersRaw, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, 0, err
		}
		if pageTitle.Valid {
			s.PageTitle = pageTitle.String
		}
		if webServer.Valid {
			s.WebServer = webServer.String
		}
		if contentType.Valid {
			s.ContentType = contentType.String
		}
		if tlsVer.Valid {
			s.TLSVersion = tlsVer.String
		}
		if len(headersRaw) > 0 {
			var h map[string]string
			_ = json.Unmarshal(headersRaw, &h)
			s.Headers = h
		}
		results = append(results, &s)
	}
	return results, total, nil
}

func (p *PostgresStorage) SaveSecurityObservation(ctx context.Context, obs *models.SecurityObservation) error {
	query := `
		INSERT INTO security_observations (id, asset_id, target_id, service_id, property_name, is_present, details, raw_value, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (asset_id, property_name)
		DO UPDATE SET is_present = EXCLUDED.is_present, details = EXCLUDED.details, raw_value = EXCLUDED.raw_value, observed_at = EXCLUDED.observed_at
	`
	_, err := p.db.ExecContext(ctx, query,
		obs.ID, obs.AssetID, obs.TargetID, obs.ServiceID, obs.PropertyName, obs.IsPresent, obs.Details, obs.RawValue, obs.ObservedAt,
	)
	return err
}

func (p *PostgresStorage) ListSecurityObservations(ctx context.Context, targetID, assetID string) ([]*models.SecurityObservation, error) {
	var query string
	var args []interface{}
	if assetID != "" {
		query = `SELECT id, asset_id, target_id, service_id, property_name, is_present, details, raw_value, observed_at
		         FROM security_observations WHERE asset_id = $1 ORDER BY property_name ASC`
		args = append(args, assetID)
	} else {
		query = `SELECT id, asset_id, target_id, service_id, property_name, is_present, details, raw_value, observed_at
		         FROM security_observations WHERE target_id = $1 ORDER BY property_name ASC`
		args = append(args, targetID)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.SecurityObservation
	for rows.Next() {
		var o models.SecurityObservation
		var sID, det, raw sql.NullString
		if err := rows.Scan(&o.ID, &o.AssetID, &o.TargetID, &sID, &o.PropertyName, &o.IsPresent, &det, &raw, &o.ObservedAt); err != nil {
			return nil, err
		}
		if sID.Valid {
			o.ServiceID = sID.String
		}
		if det.Valid {
			o.Details = det.String
		}
		if raw.Valid {
			o.RawValue = raw.String
		}
		results = append(results, &o)
	}
	return results, nil
}

func (p *PostgresStorage) AddAssetTag(ctx context.Context, tag *models.AssetTag) error {
	query := `
		INSERT INTO asset_tags (id, asset_id, target_id, tag, is_inferred, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (asset_id, tag) DO NOTHING
	`
	_, err := p.db.ExecContext(ctx, query, tag.ID, tag.AssetID, tag.TargetID, tag.Tag, tag.IsInferred, tag.CreatedAt, tag.CreatedBy)
	return err
}

func (p *PostgresStorage) RemoveAssetTag(ctx context.Context, assetID, tag string) error {
	query := `DELETE FROM asset_tags WHERE asset_id = $1 AND LOWER(tag) = LOWER($2)`
	res, err := p.db.ExecContext(ctx, query, assetID, tag)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStorage) ListAssetTags(ctx context.Context, assetID string) ([]*models.AssetTag, error) {
	query := `SELECT id, asset_id, target_id, tag, is_inferred, created_at, created_by FROM asset_tags WHERE asset_id = $1 ORDER BY tag ASC`
	rows, err := p.db.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.AssetTag
	for rows.Next() {
		var t models.AssetTag
		if err := rows.Scan(&t.ID, &t.AssetID, &t.TargetID, &t.Tag, &t.IsInferred, &t.CreatedAt, &t.CreatedBy); err != nil {
			return nil, err
		}
		results = append(results, &t)
	}
	return results, nil
}

func (p *PostgresStorage) ListTagsForTarget(ctx context.Context, targetID string) ([]*models.AssetTag, error) {
	query := `SELECT id, asset_id, target_id, tag, is_inferred, created_at, created_by FROM asset_tags WHERE target_id = $1 ORDER BY tag ASC`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.AssetTag
	for rows.Next() {
		var t models.AssetTag
		if err := rows.Scan(&t.ID, &t.AssetID, &t.TargetID, &t.Tag, &t.IsInferred, &t.CreatedAt, &t.CreatedBy); err != nil {
			return nil, err
		}
		results = append(results, &t)
	}
	return results, nil
}

func (p *PostgresStorage) RecordAssetChange(ctx context.Context, change *models.AssetChange) error {
	prevJSON, _ := json.Marshal(change.PreviousState)
	currJSON, _ := json.Marshal(change.CurrentState)
	query := `
		INSERT INTO asset_changes (id, target_id, asset_id, change_type, entity_type, entity_id, previous_state, current_state, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := p.db.ExecContext(ctx, query, change.ID, change.TargetID, change.AssetID, string(change.ChangeType), change.EntityType, change.EntityID, string(prevJSON), string(currJSON), change.DetectedAt)
	return err
}

func (p *PostgresStorage) ListAssetChanges(ctx context.Context, filter models.ChangeFilter) ([]*models.AssetChange, int, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	conditions = append(conditions, fmt.Sprintf("target_id = $%d", idx))
	args = append(args, filter.TargetID)
	idx++

	if filter.AssetID != "" {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", idx))
		args = append(args, filter.AssetID)
		idx++
	}
	if filter.ChangeType != "" {
		conditions = append(conditions, fmt.Sprintf("change_type = $%d", idx))
		args = append(args, string(filter.ChangeType))
		idx++
	}
	if filter.EntityType != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(entity_type) = LOWER($%d)", idx))
		args = append(args, filter.EntityType)
		idx++
	}

	whereClause := strings.Join(conditions, " AND ")
	var total int
	if err := p.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM asset_changes WHERE %s", whereClause), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, target_id, asset_id, change_type, entity_type, entity_id, previous_state, current_state, detected_at
		FROM asset_changes
		WHERE %s
		ORDER BY detected_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*models.AssetChange
	for rows.Next() {
		var c models.AssetChange
		var ct string
		var prevRaw, currRaw []byte
		if err := rows.Scan(&c.ID, &c.TargetID, &c.AssetID, &ct, &c.EntityType, &c.EntityID, &prevRaw, &currRaw, &c.DetectedAt); err != nil {
			return nil, 0, err
		}
		c.ChangeType = models.AssetChangeType(ct)
		if len(prevRaw) > 0 {
			_ = json.Unmarshal(prevRaw, &c.PreviousState)
		}
		if len(currRaw) > 0 {
			_ = json.Unmarshal(currRaw, &c.CurrentState)
		}
		results = append(results, &c)
	}
	return results, total, nil
}

func (p *PostgresStorage) SavePageAsset(ctx context.Context, pa *models.PageAsset) error {
	query := `
		INSERT INTO page_assets (id, asset_id, target_id, url, asset_type, source_page, is_in_scope, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (asset_id, url)
		DO UPDATE SET last_seen = EXCLUDED.last_seen
	`
	_, err := p.db.ExecContext(ctx, query, pa.ID, pa.AssetID, pa.TargetID, pa.URL, pa.AssetType, pa.SourcePage, pa.IsInScope, pa.FirstSeen, pa.LastSeen)
	return err
}

func (p *PostgresStorage) ListPageAssets(ctx context.Context, assetID string) ([]*models.PageAsset, error) {
	query := `SELECT id, asset_id, target_id, url, asset_type, source_page, is_in_scope, first_seen, last_seen FROM page_assets WHERE asset_id = $1 ORDER BY last_seen DESC`
	rows, err := p.db.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.PageAsset
	for rows.Next() {
		var a models.PageAsset
		if err := rows.Scan(&a.ID, &a.AssetID, &a.TargetID, &a.URL, &a.AssetType, &a.SourcePage, &a.IsInScope, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		results = append(results, &a)
	}
	return results, nil
}

func (p *PostgresStorage) GetTargetIntelligence(ctx context.Context, targetID string) (*models.TargetIntelligenceSummary, error) {
	summary := &models.TargetIntelligenceSummary{
		TargetID:          targetID,
		TopCategories:     make(map[string]int),
		TopTechnologies:   make(map[string]int),
		SecurityPosture:   make(map[string]int),
		InferredTagsCount: make(map[string]int),
		RecentChanges:     []*models.AssetChange{},
	}

	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE target_id = $1`, targetID).Scan(&summary.TotalAssets)
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE target_id = $1 AND status IN ('LIVE', 'RESOLVED')`, targetID).Scan(&summary.ActiveAssets)
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_observations WHERE target_id = $1`, targetID).Scan(&summary.TotalServices)
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM technology_observations WHERE target_id = $1`, targetID).Scan(&summary.TotalTechnologies)
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM urls u JOIN assets a ON u.asset_id = a.id WHERE a.target_id = $1`, targetID).Scan(&summary.TotalURLs)
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_changes WHERE target_id = $1`, targetID).Scan(&summary.TotalChanges)

	// Top Categories
	catRows, err := p.db.QueryContext(ctx, `SELECT category, COUNT(*) FROM technology_observations WHERE target_id = $1 GROUP BY category ORDER BY count DESC LIMIT 10`, targetID)
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cat string
			var cnt int
			if catRows.Scan(&cat, &cnt) == nil {
				summary.TopCategories[cat] = cnt
			}
		}
	}

	// Top Technologies
	techRows, err := p.db.QueryContext(ctx, `SELECT technology_name, COUNT(*) FROM technology_observations WHERE target_id = $1 GROUP BY technology_name ORDER BY count DESC LIMIT 10`, targetID)
	if err == nil {
		defer techRows.Close()
		for techRows.Next() {
			var name string
			var cnt int
			if techRows.Scan(&name, &cnt) == nil {
				summary.TopTechnologies[name] = cnt
			}
		}
	}

	// Security Posture
	secRows, err := p.db.QueryContext(ctx, `SELECT property_name, is_present, COUNT(*) FROM security_observations WHERE target_id = $1 GROUP BY property_name, is_present`, targetID)
	if err == nil {
		defer secRows.Close()
		for secRows.Next() {
			var prop string
			var present bool
			var cnt int
			if secRows.Scan(&prop, &present, &cnt) == nil {
				if present {
					summary.SecurityPosture["present_"+prop] = cnt
				} else {
					summary.SecurityPosture["absent_"+prop] = cnt
				}
			}
		}
	}

	// Inferred Tags Count
	tagRows, err := p.db.QueryContext(ctx, `SELECT tag, COUNT(*) FROM asset_tags WHERE target_id = $1 AND is_inferred = true GROUP BY tag`, targetID)
	if err == nil {
		defer tagRows.Close()
		for tagRows.Next() {
			var tag string
			var cnt int
			if tagRows.Scan(&tag, &cnt) == nil {
				summary.InferredTagsCount[tag] = cnt
			}
		}
	}

	// Recent changes
	changes, _, _ := p.ListAssetChanges(ctx, models.ChangeFilter{TargetID: targetID, Limit: 10})
	summary.RecentChanges = changes

	return summary, nil
}

func (p *PostgresStorage) GetAssetDetail(ctx context.Context, targetID, assetID string) (*models.AssetDetail, error) {
	// Fetch asset
	var asset models.Asset
	err := p.db.QueryRowContext(ctx, `SELECT id, target_id, hostname, asset_type, status, first_seen, last_seen FROM assets WHERE id = $1 AND target_id = $2`, assetID, targetID).
		Scan(&asset.ID, &asset.TargetID, &asset.Hostname, &asset.AssetType, &asset.Status, &asset.FirstSeen, &asset.LastSeen)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	dns, _ := p.ListDNSRecords(ctx, assetID)
	services, _, _ := p.ListServiceObservations(ctx, models.ServiceFilter{TargetID: targetID, AssetID: assetID, Limit: 100})
	techs, _, _ := p.ListTechnologyObservations(ctx, models.TechnologyFilter{TargetID: targetID, AssetID: assetID, Limit: 100})
	security, _ := p.ListSecurityObservations(ctx, targetID, assetID)
	tags, _ := p.ListAssetTags(ctx, assetID)
	pageAssets, _ := p.ListPageAssets(ctx, assetID)
	changes, _, _ := p.ListAssetChanges(ctx, models.ChangeFilter{TargetID: targetID, AssetID: assetID, Limit: 50})

	// URLs for this asset
	urlRows, err := p.db.QueryContext(ctx, `SELECT id, asset_id, url, source, depth, first_seen, last_seen FROM urls WHERE asset_id = $1 LIMIT 100`, assetID)
	var urls []*models.URLRecord
	if err == nil {
		defer urlRows.Close()
		for urlRows.Next() {
			var u models.URLRecord
			if urlRows.Scan(&u.ID, &u.AssetID, &u.URL, &u.Source, &u.Depth, &u.FirstSeen, &u.LastSeen) == nil {
				urls = append(urls, &u)
			}
		}
	}

	return &models.AssetDetail{
		Asset:                &asset,
		DNSRecords:           dns,
		Services:             services,
		Technologies:         techs,
		SecurityObservations: security,
		Tags:                 tags,
		PageAssets:           pageAssets,
		URLs:                 urls,
		Changes:              changes,
	}, nil
}

func (p *PostgresStorage) ListAssetsFiltered(ctx context.Context, filter models.AssetFilter) ([]*models.Asset, int, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	conditions = append(conditions, fmt.Sprintf("a.target_id = $%d", idx))
	args = append(args, filter.TargetID)
	idx++

	if filter.Hostname != "" {
		conditions = append(conditions, fmt.Sprintf("a.hostname ILIKE $%d", idx))
		args = append(args, "%"+filter.Hostname+"%")
		idx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("a.status = $%d", idx))
		args = append(args, filter.Status)
		idx++
	}

	fromClause := "assets a"
	if filter.Tag != "" {
		fromClause += fmt.Sprintf(" JOIN asset_tags t ON a.id = t.asset_id AND LOWER(t.tag) = LOWER($%d)", idx)
		args = append(args, filter.Tag)
		idx++
	}

	whereClause := strings.Join(conditions, " AND ")
	countQuery := fmt.Sprintf("SELECT COUNT(DISTINCT a.id) FROM %s WHERE %s", fromClause, whereClause)
	var total int
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT a.id, a.target_id, a.hostname, a.asset_type, a.status, a.first_seen, a.last_seen
		FROM %s
		WHERE %s
		ORDER BY a.last_seen DESC
		LIMIT $%d OFFSET $%d
	`, fromClause, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*models.Asset
	for rows.Next() {
		var a models.Asset
		if err := rows.Scan(&a.ID, &a.TargetID, &a.Hostname, &a.AssetType, &a.Status, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, 0, err
		}
		results = append(results, &a)
	}
	return results, total, nil
}

// AIAnalysisRepository PostgreSQL Implementation

func (p *PostgresStorage) SaveAnalysisRun(ctx context.Context, run *models.AnalysisRun) error {
	query := `
		INSERT INTO analysis_runs (
			id, target_id, asset_id, status, provider, model,
			signals_count, candidates_count, summary, confidence_notes,
			error, execution_time_ms, created_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			signals_count = EXCLUDED.signals_count,
			candidates_count = EXCLUDED.candidates_count,
			summary = EXCLUDED.summary,
			confidence_notes = EXCLUDED.confidence_notes,
			error = EXCLUDED.error,
			execution_time_ms = EXCLUDED.execution_time_ms,
			completed_at = EXCLUDED.completed_at
	`
	_, err := p.db.ExecContext(ctx, query,
		run.ID, run.TargetID, run.AssetID, string(run.Status), run.Provider, run.Model,
		run.SignalsCount, run.CandidatesCount, run.Summary, run.ConfidenceNotes,
		run.Error, run.ExecutionTimeMS, run.CreatedAt, run.CompletedAt,
	)
	return err
}

func (p *PostgresStorage) GetAnalysisRun(ctx context.Context, id string) (*models.AnalysisRun, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), status, provider, model,
		       signals_count, candidates_count, COALESCE(summary, ''), COALESCE(confidence_notes, ''),
		       COALESCE(error, ''), execution_time_ms, created_at, completed_at
		FROM analysis_runs WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)
	var r models.AnalysisRun
	var statusStr string
	err := row.Scan(
		&r.ID, &r.TargetID, &r.AssetID, &statusStr, &r.Provider, &r.Model,
		&r.SignalsCount, &r.CandidatesCount, &r.Summary, &r.ConfidenceNotes,
		&r.Error, &r.ExecutionTimeMS, &r.CreatedAt, &r.CompletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Status = models.AnalysisRunStatus(statusStr)
	return &r, nil
}

func (p *PostgresStorage) ListAnalysisRuns(ctx context.Context, targetID string) ([]*models.AnalysisRun, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), status, provider, model,
		       signals_count, candidates_count, COALESCE(summary, ''), COALESCE(confidence_notes, ''),
		       COALESCE(error, ''), execution_time_ms, created_at, completed_at
		FROM analysis_runs
		WHERE ($1 = '' OR target_id = $1)
		ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.AnalysisRun
	for rows.Next() {
		var r models.AnalysisRun
		var statusStr string
		err := rows.Scan(
			&r.ID, &r.TargetID, &r.AssetID, &statusStr, &r.Provider, &r.Model,
			&r.SignalsCount, &r.CandidatesCount, &r.Summary, &r.ConfidenceNotes,
			&r.Error, &r.ExecutionTimeMS, &r.CreatedAt, &r.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		r.Status = models.AnalysisRunStatus(statusStr)
		results = append(results, &r)
	}
	return results, nil
}

func (p *PostgresStorage) UpdateAnalysisRun(ctx context.Context, run *models.AnalysisRun) error {
	return p.SaveAnalysisRun(ctx, run)
}

func (p *PostgresStorage) SaveSecuritySignal(ctx context.Context, signal *models.SecuritySignal) error {
	detailsJSON, err := json.Marshal(signal.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	query := `
		INSERT INTO security_signals (
			id, analysis_run_id, target_id, asset_id, signal_type,
			severity_hint, evidence, source, url, details, detected_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING
	`
	_, err = p.db.ExecContext(ctx, query,
		signal.ID, signal.AnalysisRunID, signal.TargetID, signal.AssetID, signal.SignalType,
		signal.SeverityHint, signal.Evidence, signal.Source, signal.URL, detailsJSON, signal.DetectedAt,
	)
	return err
}

func (p *PostgresStorage) ListSecuritySignals(ctx context.Context, targetID, assetID string) ([]*models.SecuritySignal, error) {
	query := `
		SELECT id, COALESCE(analysis_run_id, ''), target_id, asset_id, signal_type,
		       severity_hint, evidence, source, COALESCE(url, ''), details, detected_at
		FROM security_signals
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY detected_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.SecuritySignal
	for rows.Next() {
		var s models.SecuritySignal
		var detailsJSON []byte
		err := rows.Scan(
			&s.ID, &s.AnalysisRunID, &s.TargetID, &s.AssetID, &s.SignalType,
			&s.SeverityHint, &s.Evidence, &s.Source, &s.URL, &detailsJSON, &s.DetectedAt,
		)
		if err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &s.Details)
		}
		results = append(results, &s)
	}
	return results, nil
}

func (p *PostgresStorage) SaveFindingCandidate(ctx context.Context, candidate *models.FindingCandidate) error {
	validStepsJSON, _ := json.Marshal(candidate.ValidationSteps)
	eviRefsJSON, _ := json.Marshal(candidate.EvidenceReferences)

	query := `
		INSERT INTO finding_candidates (
			id, analysis_run_id, target_id, asset_id, category,
			title, description, state, confidence_score, reasoning,
			missing_evidence, validation_steps, evidence_references,
			recommended_verification, is_mock, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (id) DO UPDATE SET
			state = EXCLUDED.state,
			confidence_score = EXCLUDED.confidence_score,
			reasoning = EXCLUDED.reasoning,
			missing_evidence = EXCLUDED.missing_evidence,
			validation_steps = EXCLUDED.validation_steps,
			recommended_verification = EXCLUDED.recommended_verification,
			updated_at = EXCLUDED.updated_at
	`
	_, err := p.db.ExecContext(ctx, query,
		candidate.ID, candidate.AnalysisRunID, candidate.TargetID, candidate.AssetID, candidate.Category,
		candidate.Title, candidate.Description, string(candidate.State), candidate.ConfidenceScore, candidate.Reasoning,
		candidate.MissingEvidence, validStepsJSON, eviRefsJSON,
		candidate.RecommendedVerification, candidate.IsMock, candidate.CreatedAt, candidate.UpdatedAt,
	)
	return err
}

func (p *PostgresStorage) GetFindingCandidate(ctx context.Context, id string) (*models.FindingCandidate, error) {
	query := `
		SELECT id, COALESCE(analysis_run_id, ''), target_id, asset_id, category,
		       title, description, state, confidence_score, reasoning,
		       missing_evidence, validation_steps, evidence_references,
		       recommended_verification, is_mock, created_at, updated_at
		FROM finding_candidates
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)
	var c models.FindingCandidate
	var stateStr string
	var validStepsJSON, eviRefsJSON []byte

	err := row.Scan(
		&c.ID, &c.AnalysisRunID, &c.TargetID, &c.AssetID, &c.Category,
		&c.Title, &c.Description, &stateStr, &c.ConfidenceScore, &c.Reasoning,
		&c.MissingEvidence, &validStepsJSON, &eviRefsJSON,
		&c.RecommendedVerification, &c.IsMock, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.State = models.CandidateState(stateStr)
	if len(validStepsJSON) > 0 {
		_ = json.Unmarshal(validStepsJSON, &c.ValidationSteps)
	}
	if len(eviRefsJSON) > 0 {
		_ = json.Unmarshal(eviRefsJSON, &c.EvidenceReferences)
	}

	// Fetch evidence items
	evis, _ := p.ListCandidateEvidence(ctx, c.ID)
	c.Evidence = evis

	return &c, nil
}

func (p *PostgresStorage) ListFindingCandidates(ctx context.Context, filter models.CandidateFilter) ([]*models.FindingCandidate, int, error) {
	var conditions []string
	var args []any
	idx := 1

	if filter.TargetID != "" {
		conditions = append(conditions, fmt.Sprintf("target_id = $%d", idx))
		args = append(args, filter.TargetID)
		idx++
	}
	if filter.AssetID != "" {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", idx))
		args = append(args, filter.AssetID)
		idx++
	}
	if filter.Category != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(category) = LOWER($%d)", idx))
		args = append(args, filter.Category)
		idx++
	}
	if filter.State != "" {
		conditions = append(conditions, fmt.Sprintf("state = $%d", idx))
		args = append(args, string(filter.State))
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d OR reasoning ILIKE $%d)", idx, idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	whereClause := "1=1"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM finding_candidates WHERE %s", whereClause)
	var total int
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, COALESCE(analysis_run_id, ''), target_id, asset_id, category,
		       title, description, state, confidence_score, reasoning,
		       missing_evidence, validation_steps, evidence_references,
		       recommended_verification, is_mock, created_at, updated_at
		FROM finding_candidates
		WHERE %s
		ORDER BY confidence_score DESC, created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*models.FindingCandidate
	for rows.Next() {
		var c models.FindingCandidate
		var stateStr string
		var validStepsJSON, eviRefsJSON []byte

		err := rows.Scan(
			&c.ID, &c.AnalysisRunID, &c.TargetID, &c.AssetID, &c.Category,
			&c.Title, &c.Description, &stateStr, &c.ConfidenceScore, &c.Reasoning,
			&c.MissingEvidence, &validStepsJSON, &eviRefsJSON,
			&c.RecommendedVerification, &c.IsMock, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		c.State = models.CandidateState(stateStr)
		if len(validStepsJSON) > 0 {
			_ = json.Unmarshal(validStepsJSON, &c.ValidationSteps)
		}
		if len(eviRefsJSON) > 0 {
			_ = json.Unmarshal(eviRefsJSON, &c.EvidenceReferences)
		}
		results = append(results, &c)
	}

	return results, total, nil
}

func (p *PostgresStorage) UpdateCandidateState(ctx context.Context, id string, newState models.CandidateState, reason string) error {
	query := `
		UPDATE finding_candidates
		SET state = $1,
		    reasoning = CASE
		        WHEN $2 != '' THEN reasoning || E'\n[State changed to ' || $1 || ': ' || $2 || ']'
		        ELSE reasoning
		    END,
		    updated_at = NOW()
		WHERE id = $3
	`
	res, err := p.db.ExecContext(ctx, query, string(newState), reason, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStorage) SaveCandidateEvidence(ctx context.Context, evidence *models.CandidateEvidence) error {
	detailsJSON, err := json.Marshal(evidence.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	query := `
		INSERT INTO candidate_evidence (
			id, candidate_id, evidence_type, reference_id, summary, sha256, details, collected_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`
	_, err = p.db.ExecContext(ctx, query,
		evidence.ID, evidence.CandidateID, evidence.EvidenceType, evidence.ReferenceID,
		evidence.Summary, evidence.SHA256, detailsJSON, evidence.CollectedAt,
	)
	return err
}

func (p *PostgresStorage) ListCandidateEvidence(ctx context.Context, candidateID string) ([]*models.CandidateEvidence, error) {
	query := `
		SELECT id, candidate_id, evidence_type, reference_id, summary, sha256, details, collected_at
		FROM candidate_evidence
		WHERE candidate_id = $1
		ORDER BY collected_at ASC
	`
	rows, err := p.db.QueryContext(ctx, query, candidateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.CandidateEvidence
	for rows.Next() {
		var e models.CandidateEvidence
		var detailsJSON []byte
		err := rows.Scan(
			&e.ID, &e.CandidateID, &e.EvidenceType, &e.ReferenceID, &e.Summary, &e.SHA256, &detailsJSON, &e.CollectedAt,
		)
		if err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &e.Details)
		}
		results = append(results, &e)
	}
	return results, nil
}



