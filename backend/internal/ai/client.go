package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	ErrAIServiceUnavailable = errors.New("ai analysis service is unavailable")
	ErrInvalidAIResponse    = errors.New("invalid response from ai analysis service")
	ErrAnalysisFailed       = errors.New("ai analysis execution failed")
)

// Client defines the interface for communicating with the Python AI analysis engine.
type Client interface {
	Analyze(ctx context.Context, req *AnalyzePayload) (*AnalysisResultPayload, error)
	Health(ctx context.Context) (*HealthPayload, error)
}

// HTTPClient implements Client using standard net/http with robust timeouts.
type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient initializes a new HTTPClient pointing to the Python FastAPI microservice.
func NewClient(baseURL string, timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return &HTTPClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ServiceEvidencePayload matches Python ServiceEvidence schema
type ServiceEvidencePayload struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	ContentType    string            `json:"content_type,omitempty"`
	PageTitle      string            `json:"page_title,omitempty"`
	WebServer      string            `json:"web_server,omitempty"`
	ResponseTimeMS int               `json:"response_time_ms,omitempty"`
	TLSVersion     string            `json:"tls_version,omitempty"`
	Headers        map[string]string `json:"headers"`
	BodySnippet    string            `json:"body_snippet,omitempty"`
}

// TechnologyEvidencePayload matches Python TechnologyEvidence schema
type TechnologyEvidencePayload struct {
	TechnologyName string `json:"technology_name"`
	Category       string `json:"category"`
	Version        string `json:"version,omitempty"`
	Confidence     string `json:"confidence"`
	Evidence       string `json:"evidence"`
}

// SecurityObservationEvidencePayload matches Python SecurityObservationEvidence schema
type SecurityObservationEvidencePayload struct {
	PropertyName string `json:"property_name"`
	IsPresent    bool   `json:"is_present"`
	Details      string `json:"details,omitempty"`
	RawValue     string `json:"raw_value,omitempty"`
}

// URLEvidencePayload matches Python URLEvidence schema
type URLEvidencePayload struct {
	URL    string `json:"url"`
	Depth  int    `json:"depth,omitempty"`
	Source string `json:"source,omitempty"`
}

// StructuredEvidencePayload matches Python StructuredEvidence schema
type StructuredEvidencePayload struct {
	TargetID             string                                `json:"target_id"`
	AssetID              string                                `json:"asset_id"`
	JobID                string                                `json:"job_id,omitempty"`
	Service              *ServiceEvidencePayload               `json:"service,omitempty"`
	Technologies         []TechnologyEvidencePayload           `json:"technologies"`
	SecurityObservations []SecurityObservationEvidencePayload `json:"security_observations"`
	URLs                 []URLEvidencePayload                  `json:"urls"`
	PageAssets           []any                                 `json:"page_assets"`
	ResponseMetadata     map[string]any                        `json:"response_metadata"`
}

// AnalyzePayload is the POST /api/v1/analyze request body
type AnalyzePayload struct {
	TargetID string                    `json:"target_id"`
	AssetID  string                    `json:"asset_id"`
	RunID    string                    `json:"run_id,omitempty"`
	Evidence StructuredEvidencePayload `json:"evidence"`
}

// SignalPayload matches Python SecuritySignal schema
type SignalPayload struct {
	ID           string         `json:"id"`
	TargetID     string         `json:"target_id"`
	AssetID      string         `json:"asset_id"`
	SignalType   string         `json:"signal_type"`
	SeverityHint string         `json:"severity_hint"`
	Evidence     string         `json:"evidence"`
	Source       string         `json:"source"`
	URL          string         `json:"url,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
	DetectedAt   time.Time      `json:"detected_at"`
}

// CandidatePayload matches Python FindingCandidate schema
type CandidatePayload struct {
	ID                      string         `json:"id"`
	TargetID                string         `json:"target_id"`
	AssetID                 string         `json:"asset_id"`
	Category                string         `json:"category"`
	Title                   string         `json:"title"`
	Description             string         `json:"description"`
	State                   string         `json:"state"`
	ConfidenceScore         float64        `json:"confidence_score"`
	Reasoning               string         `json:"reasoning"`
	MissingEvidence         string         `json:"missing_evidence"`
	ValidationSteps         []string       `json:"validation_steps"`
	EvidenceReferences      []string       `json:"evidence_references"`
	RecommendedVerification string         `json:"recommended_verification"`
	IsMock                  bool           `json:"is_mock"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
	Details                 map[string]any `json:"details,omitempty"`
}

// AnalysisResultPayload matches Python AnalysisResult schema
type AnalysisResultPayload struct {
	RunID           string             `json:"run_id"`
	TargetID        string             `json:"target_id"`
	AssetID         string             `json:"asset_id"`
	Signals         []CandidatePayload `json:"signals_raw,omitempty"` // fallback if needed
	SignalsParsed   []SignalPayload    `json:"signals"`
	Candidates      []CandidatePayload `json:"candidates"`
	Summary         string             `json:"summary"`
	ConfidenceNotes string             `json:"confidence_notes"`
	Status          string             `json:"status"`
	Provider        string             `json:"provider"`
	Model           string             `json:"model"`
	ExecutionTimeMS int                `json:"execution_time_ms"`
}

// HealthPayload is the response from /health
type HealthPayload struct {
	Status        string `json:"status"`
	Service       string `json:"service"`
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	RateLimitRPM  int    `json:"rate_limit_rpm"`
	BaseURL       string `json:"base_url"`
}

// Analyze invokes the Python AI analysis engine over HTTP.
func (c *HTTPClient) Analyze(ctx context.Context, req *AnalyzePayload) (*AnalysisResultPayload, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal analyze request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/analyze", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAIServiceUnavailable, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read ai service response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d, body: %s", ErrAnalysisFailed, resp.StatusCode, string(respBody))
	}

	var result AnalysisResultPayload
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAIResponse, err)
	}

	return &result, nil
}

// Health checks the status of the Python AI service.
func (c *HTTPClient) Health(ctx context.Context) (*HealthPayload, error) {
	url := fmt.Sprintf("%s/health", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAIServiceUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	var h HealthPayload
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}
