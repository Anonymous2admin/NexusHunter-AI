export type TargetStatus = 'ACTIVE' | 'INACTIVE' | 'ARCHIVED';

export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface Target {
  id: string;
  name: string;
  root_domain: string;
  allowed_domains: string[];
  allowed_url_patterns: string[];
  excluded_patterns: string[];
  status: TargetStatus;
  created_at: string;
  updated_at: string;
}

export interface TargetScopeRule {
  id: string;
  target_id: string;
  rule_type: 'DOMAIN' | 'URL_PATTERN' | 'EXCLUSION';
  pattern: string;
  created_at: string;
}

export interface ScanJob {
  id: string;
  target_id: string;
  type: string;
  status: JobStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  metadata?: Record<string, any>;
}

export interface SystemEvent {
  event_id: string;
  event_type: string;
  job_id?: string;
  target_id?: string;
  timestamp: string;
  payload?: Record<string, any>;
}

export interface HealthResponse {
  status: string;
  service: string;
  mode?: 'LIVE' | 'DEMO_FALLBACK' | 'OFFLINE' | 'PARTIAL' | string;
  runtime_mode?: 'LIVE_BACKEND' | 'DEMO_SYNTHETIC' | 'OFFLINE' | 'PARTIAL' | 'UNKNOWN' | string;
  storage_mode?: 'POSTGRES' | 'MEMORY' | 'UNAVAILABLE' | string;
  data_origin?: 'LIVE_BACKEND' | 'DEMO_SYNTHETIC' | 'SIMULATED' | string;
  environment?: string;
  time?: string;
}

export interface VersionResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
}

export interface ScopeDecision {
  in_scope: boolean;
  reason: string;
  matched_rule?: string;
}

export interface ReconOptions {
  subdomain_discovery?: boolean;
  dns_resolution?: boolean;
  http_probe?: boolean;
  crawl?: boolean;
}

export interface DNSRecord {
  id: string;
  asset_id: string;
  record_type: string;
  value: string;
  ttl: number;
  status: string;
  discovered_at: string;
}

export interface HTTPService {
  id: string;
  asset_id: string;
  port: number;
  scheme: string;
  url: string;
  status_code: number;
  title?: string;
  web_server?: string;
  content_type?: string;
  content_length?: number;
  response_time_ms?: number;
  headers?: Record<string, string>;
  discovered_at: string;
}

export interface Asset {
  id: string;
  target_id: string;
  hostname: string;
  asset_type: string;
  ip_addresses: string[];
  status: string;
  discovered_at: string;
  updated_at: string;
  dns_records?: DNSRecord[];
}

export interface DiscoveredURL {
  id: string;
  target_id: string;
  asset_id?: string;
  url: string;
  method: string;
  source: string;
  depth: number;
  discovered_at: string;
}

export interface ReconRun {
  id: string;
  job_id: string;
  target_id: string;
  status: JobStatus;
  hosts_discovered: number;
  hosts_resolved: number;
  services_probed: number;
  urls_crawled: number;
  errors_count: number;
  skipped_out_of_scope: number;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
}

export interface TechnologyObservation {
  id: string;
  asset_id: string;
  target_id: string;
  technology_name: string;
  category: string;
  version?: string;
  confidence: number;
  detection_source: string;
  evidence: string;
  first_seen: string;
  last_seen: string;
}

export interface ServiceObservation {
  id: string;
  asset_id: string;
  target_id: string;
  service_identity: string;
  scheme: string;
  port: number;
  status_code: number;
  page_title: string;
  web_server: string;
  content_type: string;
  content_length: number;
  response_time_ms: number;
  tls_version: string;
  headers?: Record<string, string>;
  first_seen: string;
  last_seen: string;
}

export interface SecurityObservation {
  id: string;
  asset_id: string;
  target_id: string;
  service_id: string;
  property_name: string;
  is_present: boolean;
  details: string;
  raw_value: string;
  first_seen: string;
  last_seen: string;
}

export type AssetChangeType =
  | 'NEW_ASSET'
  | 'NEW_SERVICE'
  | 'NEW_TECHNOLOGY'
  | 'CHANGED_SERVICE'
  | 'REMOVED_SERVICE';

export interface AssetChange {
  id: string;
  target_id: string;
  asset_id: string;
  change_type: AssetChangeType;
  summary: string;
  details?: Record<string, any>;
  detected_at: string;
}

export interface AssetTag {
  id: string;
  asset_id: string;
  target_id: string;
  tag: string;
  is_inferred: boolean;
  created_at: string;
  created_by: string;
}

export interface PageAsset {
  id: string;
  asset_id: string;
  target_id: string;
  url: string;
  asset_type: 'script' | 'stylesheet' | 'sourcemap' | 'api_endpoint' | string;
  source_page: string;
  is_in_scope: boolean;
  discovered_at: string;
}

export interface TargetIntelligenceSummary {
  target_id: string;
  technologies?: TechnologyObservation[];
  services?: ServiceObservation[];
  security_observations?: SecurityObservation[];
  changes?: AssetChange[];
  tags?: AssetTag[];
  total_assets?: number;
  total_services?: number;
  total_technologies?: number;
  total_changes?: number;
  recent_changes?: AssetChange[];
  stats?: {
    total_assets: number;
    total_services: number;
    total_technologies: number;
    security_observations_count: number;
    changes_count: number;
  };
}

export interface AssetDetail {
  asset: Asset;
  dns_records: DNSRecord[];
  services: ServiceObservation[];
  technologies: TechnologyObservation[];
  security_observations: SecurityObservation[];
  tags: AssetTag[];
  page_assets: PageAsset[];
  changes: AssetChange[];
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: string;
  };
}

// Phase 4: AI Analysis & Finding Candidates

export type CandidateState =
  | 'OBSERVATION'
  | 'SIGNAL'
  | 'ANALYSIS_CANDIDATE'
  | 'CANDIDATE'
  | 'VALIDATING'
  | 'REPORTED'
  | 'RESOLVED'
  | 'DISMISSED';

export interface SecuritySignal {
  id: string;
  analysis_run_id?: string;
  target_id: string;
  asset_id?: string;
  signal_type: string;
  severity_hint: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: string;
  source: string;
  url?: string;
  details?: Record<string, any>;
  detected_at: string;
}

export interface CandidateEvidence {
  id: string;
  candidate_id: string;
  evidence_type: string;
  reference_id: string;
  summary: string;
  sha256: string;
  details?: Record<string, any>;
  collected_at: string;
}

export interface FindingCandidate {
  id: string;
  analysis_run_id?: string;
  target_id: string;
  asset_id?: string;
  category: string;
  title: string;
  description: string;
  state: CandidateState;
  confidence_score: number;
  reasoning: string;
  missing_evidence: string;
  validation_steps: string[];
  evidence_references: string[];
  recommended_verification: string;
  is_mock: boolean;
  created_at: string;
  updated_at: string;
  evidence?: CandidateEvidence[];
}

export interface AnalysisRun {
  id: string;
  target_id: string;
  asset_id?: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  provider: string;
  model: string;
  signals_count: number;
  candidates_count: number;
  summary?: string;
  confidence_notes?: string;
  error?: string;
  execution_time_ms: number;
  created_at: string;
  completed_at?: string;
}

// Phase 5: Differentiated Security Intelligence & Investigation Engine

export type GraphNodeType =
  | 'TARGET'
  | 'DOMAIN'
  | 'SUBDOMAIN'
  | 'IP'
  | 'DNS_RECORD'
  | 'HTTP_SERVICE'
  | 'URL'
  | 'ENDPOINT'
  | 'TECHNOLOGY'
  | 'JAVASCRIPT'
  | 'API'
  | 'AUTH_BOUNDARY'
  | 'SECURITY_SIGNAL'
  | 'CANDIDATE'
  | 'FINDING'
  | 'CHANGE';

export type GraphEdgeType =
  | 'RESOLVES_TO'
  | 'HOSTS'
  | 'SERVES'
  | 'REFERENCES'
  | 'DISCOVERED_FROM'
  | 'USES'
  | 'REDIRECTS_TO'
  | 'BELONGS_TO'
  | 'CHANGED_FROM'
  | 'RELATED_TO'
  | 'TRIGGERS'
  | 'SUPPORTS'
  | 'CONTRADICTS';

export interface GraphNode {
  id: string;
  target_id: string;
  asset_id?: string;
  type: GraphNodeType;
  label: string;
  properties?: Record<string, any>;
  first_seen: string;
  last_seen: string;
}

export interface GraphEdge {
  id: string;
  target_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship: GraphEdgeType;
  weight: number;
  properties?: Record<string, any>;
  created_at: string;
}

export interface GraphData {
  target_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
  metrics: Record<string, number>;
}

export type TemporalChangeType =
  | 'NEW_ASSET'
  | 'REMOVED_ASSET'
  | 'NEW_ENDPOINT'
  | 'REMOVED_ENDPOINT'
  | 'NEW_TECHNOLOGY'
  | 'TECHNOLOGY_CHANGED'
  | 'HTTP_BEHAVIOR_CHANGED'
  | 'SECURITY_HEADER_CHANGED'
  | 'DNS_CHANGED'
  | 'REDIRECT_CHANGED'
  | 'AUTH_OBSERVATION_CHANGED';

export interface TemporalChangeRecord {
  id: string;
  target_id: string;
  asset_id?: string;
  change_type: TemporalChangeType;
  summary: string;
  previous_value: string;
  current_value: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  detected_at: string;
  details?: Record<string, any>;
}

export interface InvariantSignal {
  id: string;
  target_id: string;
  asset_id: string;
  endpoint: string;
  state_from: string;
  state_to: string;
  observed_condition: string;
  invariant_violation: string;
  confidence: number;
  evidence: string;
  detected_at: string;
}

export interface BehaviorDifference {
  id: string;
  target_id: string;
  asset_id: string;
  probe_a_url: string;
  probe_b_url: string;
  context_a: string;
  context_b: string;
  status_diff: boolean;
  length_diff: number;
  header_diff: string[];
  body_diff_fingerprint: string;
  state_change_observed: boolean;
  timing_delta_ms: number;
  is_meaningful: boolean;
  normalized_details?: Record<string, any>;
  detected_at: string;
}

export interface PriorityFactor {
  name: string;
  score: number;
  weight: number;
  explanation: string;
}

export type ClusterStatus =
  | 'ACTIVE'
  | 'INVESTIGATING'
  | 'VALIDATING'
  | 'VALIDATED'
  | 'REJECTED'
  | 'CLOSED';

export interface InvestigationCluster {
  id: string;
  target_id: string;
  title: string;
  category: string;
  priority_score: number;
  priority_explanation: string;
  priority_factors: PriorityFactor[];
  related_assets: string[];
  related_endpoints: string[];
  related_signals?: SecuritySignal[];
  related_changes?: TemporalChangeRecord[];
  confidence: number;
  reason: string;
  recommended_validation: string[];
  status: ClusterStatus;
  created_at: string;
  updated_at: string;
}

export interface ResearchMemory {
  target_id: string;
  known_assets_count: number;
  known_endpoints_count: number;
  known_technologies_count: number;
  total_historical_changes: number;
  active_investigations_count: number;
  validated_findings_count: number;
  rejected_candidates_count: number;
  recent_what_changed: TemporalChangeRecord[];
  deserves_reinvestigation: InvestigationCluster[];
  last_scan_at: string;
}

export interface ControlledValidationResult {
  id: string;
  candidate_id?: string;
  cluster_id?: string;
  success: boolean;
  state: CandidateState;
  observations: string[];
  output_fact: string;
  executed_at: string;
}

// --- Phase 6 Evidence Intelligence & Security Reasoning Foundation Types ---

export type EvidenceType =
  | 'HTTP_REQUEST'
  | 'HTTP_RESPONSE'
  | 'HEADER_OBSERVATION'
  | 'DNS_OBSERVATION'
  | 'TLS_OBSERVATION'
  | 'REDIRECT_CHAIN'
  | 'TECHNOLOGY_OBSERVATION'
  | 'AUTHORIZATION_OBSERVATION'
  | 'STATE_TRANSITION'
  | 'DIFFERENTIAL_RESULT'
  | 'VALIDATION_RESULT'
  | 'SCREENSHOT_REFERENCE'
  | 'TIMELINE_EVENT'
  | 'GRAPH_RELATIONSHIP';

export type EvidenceSource =
  | 'RECON_HTTP'
  | 'RECON_CRAWLER'
  | 'CONTROLLED_VALIDATION'
  | 'DIFFERENTIAL_ENGINE'
  | 'TEMPORAL_DIFF'
  | 'MANUAL_PROBE'
  | 'SECURITY_OBSERVATION';

export interface EvidenceProvenance {
  source: EvidenceSource;
  operation_id: string;
  target_id: string;
  asset_id?: string;
  captured_at: string;
  initiator: string;
  notes?: string;
}

export interface ScopeDecisionRecord {
  is_in_scope: boolean;
  target_id: string;
  evaluated_host: string;
  evaluated_url?: string;
  rule_matched: string;
  reason: string;
  evaluated_at: string;
}

export interface RedactionStatusRecord {
  is_redacted: boolean;
  redacted_fields: string[];
  sanitized_at: string;
}

export interface HTTPRequestContext {
  method: string;
  url: string;
  headers: Record<string, string>;
  body_summary?: string;
  body_length: number;
  is_authenticated: boolean;
  auth_context_role?: string;
}

export interface HTTPResponseContext {
  status_code: number;
  headers: Record<string, string>;
  body_snippet?: string;
  body_length: number;
  body_hash: string;
  content_type: string;
  response_time_ms: number;
}

export interface DNSContext {
  hostname: string;
  ip_addresses: string[];
  cnames?: string[];
  ttl?: number;
}

export interface TLSMetadataContext {
  version: string;
  cipher_suite: string;
  issuer: string;
  subject: string;
  sans?: string[];
  valid_until: string;
  mutual_tls_required: boolean;
}

export interface Evidence {
  id: string;
  target_id: string;
  asset_id?: string;
  observation_id?: string;
  candidate_id?: string;
  source: EvidenceSource;
  evidence_type: EvidenceType;
  summary: string;
  captured_at: string;
  status_code?: number;
  request?: HTTPRequestContext;
  response?: HTTPResponseContext;
  relevant_headers?: Record<string, string>;
  redirect_chain?: string[];
  dns_context?: DNSContext;
  tls_metadata?: TLSMetadataContext;
  validation_context?: Record<string, any>;
  scope_decision: ScopeDecisionRecord;
  redaction_status: RedactionStatusRecord;
  canonical_representation?: string;
  sha256: string;
  provenance: EvidenceProvenance;
  metadata?: Record<string, any>;
}

export interface EvidenceIntegrityResult {
  evidence_id: string;
  original_sha256: string;
  computed_sha256: string;
  is_tampered: boolean;
  verified_at: string;
  canonical_matches: boolean;
}

export interface Level1RawDiff {
  status_from: number;
  status_to: number;
  status_changed: boolean;
  body_length_delta: number;
  body_hash_a: string;
  body_hash_b: string;
  body_hash_changed: boolean;
  added_headers?: Record<string, string>;
  removed_headers?: Record<string, string>;
  modified_headers?: Record<string, string>;
  response_time_delta_ms: number;
}

export interface Level2SemanticDiff {
  category: string;
  meaning: string;
  auth_behavior_changed: boolean;
  content_type_changed: boolean;
  redirect_changed: boolean;
  error_payload_detected: boolean;
  state_transition_detected?: boolean;
}

export interface Level3SecurityDiff {
  observation_context: string;
  relevance_explanation: string;
  requires_followup: boolean;
  suggested_questions: string[];
}

export interface EvidenceDiff {
  id: string;
  target_id: string;
  asset_id?: string;
  evidence_a_id: string;
  evidence_b_id: string;
  raw_diff: Level1RawDiff;
  semantic_diff: Level2SemanticDiff;
  security_diff: Level3SecurityDiff;
  is_noise_filtered: boolean;
  is_security_relevant: boolean;
  computed_at: string;
}

export type EpistemicObservationState =
  | 'PRESENT'
  | 'ABSENT'
  | 'NOT_OBSERVED'
  | 'UNKNOWN'
  | 'NOT_APPLICABLE';

export type ExpectedModelSource =
  | 'EXPLICIT_POLICY'
  | 'PEER_BASELINE'
  | 'HISTORICAL_BASELINE';

export interface SecurityExpectation {
  id: string;
  target_id: string;
  asset_id?: string;
  endpoint?: string;
  control_name: string;
  source: ExpectedModelSource;
  expected_state: EpistemicObservationState;
  description: string;
  rule_details?: Record<string, any>;
  created_at: string;
}

export type ContradictionType =
  | 'AUTHENTICATION_CONTRADICTION'
  | 'AUTHORIZATION_CONTRADICTION'
  | 'SECURITY_CONTROL_CONTRADICTION'
  | 'PROTOCOL_CONTRADICTION'
  | 'CONFIGURATION_CONTRADICTION'
  | 'TRUST_BOUNDARY_CONTRADICTION'
  | 'TEMPORAL_CONTRADICTION'
  | 'BEHAVIORAL_CONTRADICTION'
  | 'BUSINESS_RULE_CONTRADICTION';

export type ContradictionStatus =
  | 'UNVERIFIED'
  | 'INVESTIGATING'
  | 'CONFIRMED_DEVIATION'
  | 'REJECTED'
  | 'DISMISSED';

export interface SecurityContradiction {
  id: string;
  target_id: string;
  asset_id?: string;
  endpoint?: string;
  contradiction_type: ContradictionType;
  status: ContradictionStatus;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  expectation_id?: string;
  observed_state: EpistemicObservationState;
  evidence_refs: string[];
  explanation: string;
  suggested_followup: string[];
  created_at: string;
  updated_at: string;
}

export interface SecurityOutlier {
  id: string;
  target_id: string;
  asset_id?: string;
  endpoint?: string;
  comparison_group: string;
  observed_value: string;
  baseline_value: string;
  deviation_type: string;
  evidence_refs: string[];
  confidence: number;
  details?: Record<string, any>;
  created_at: string;
}

export type EpistemicStatus =
  | 'OBSERVED'
  | 'DERIVED'
  | 'INFERRED'
  | 'HYPOTHESIZED'
  | 'VALIDATING'
  | 'SUPPORTED'
  | 'REJECTED'
  | 'DISMISSED';

export interface InterestReason {
  factor_name: string;
  description: string;
  evidence_refs: string[];
  weight: number;
}

export interface AssetInterestSummary {
  asset_id: string;
  hostname: string;
  target_id: string;
  score: number;
  reasons: InterestReason[];
  linked_evidence_ids: string[];
  evaluated_at: string;
}

export interface EvidenceTimelineEvent {
  id: string;
  target_id: string;
  asset_id?: string;
  event_type: string;
  summary: string;
  epistemic_status: EpistemicStatus;
  timestamp: string;
  provenance: EvidenceProvenance;
  reference_id?: string;
  details?: Record<string, any>;
}

// ==========================================
// Phase 7: Reasoning, Hypothesis & Investigation Types
// ==========================================

export type SignalType =
  | 'AUTH_INCONSISTENCY'
  | 'AUTHORIZATION_DIFF'
  | 'HTTP_SECURITY_CONTROL_DIFF'
  | 'INFRASTRUCTURE_ANOMALY'
  | 'APPLICATION_BEHAVIOR_DIFF'
  | 'TEMPORAL_CHANGE';

export type AttentionSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SignalStatus = 'OPEN' | 'INVESTIGATING' | 'DISMISSED' | 'RESOLVED';

export interface ReasoningSignal {
  id: string;
  target_id: string;
  asset_id: string;
  endpoint?: string;
  signal_type: SignalType;
  category: string;
  title: string;
  description: string;
  epistemic_status: EpistemicStatus;
  status: SignalStatus;
  severity: AttentionSeverity;
  source_observations: string[];
  source_evidence: string[];
  detector: string;
  detector_version: string;
  created_at: string;
  updated_at: string;
}

export type HypothesisStatus =
  | 'HYPOTHESIZED'
  | 'TESTING'
  | 'SUPPORTED'
  | 'FALSIFIED'
  | 'INCONCLUSIVE'
  | 'UNKNOWN';

export type HypothesisCategory =
  | 'INTENTIONAL_PUBLIC'
  | 'AUTH_POLICY_DIFF'
  | 'LEGACY_ARTIFACT'
  | 'ENVIRONMENT_LEAK'
  | 'DEVELOPER_OVERRIDE'
  | 'ROUTING_MISCONFIGURATION'
  | 'RATE_LIMIT_BYPASS'
  | 'SECURITY_CONTROL_GAP'
  | 'CUSTOM_RESEARCH';

export type FalsificationResult = 'PENDING' | 'REFUTED' | 'SUPPORTED' | 'INCONCLUSIVE';

export interface FalsificationCondition {
  id: string;
  hypothesis_id: string;
  condition_description: string;
  required_evidence: string;
  validation_method: string;
  result: FalsificationResult;
  evaluated_at?: string;
  notes?: string;
}

export type RequirementStatus = 'MISSING' | 'ACQUIRED' | 'OBSOLETE';

export interface EvidenceRequirement {
  id: string;
  hypothesis_id: string;
  description: string;
  importance: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence_type: EvidenceType;
  collection_method: string;
  status: RequirementStatus;
  collected_evidence_id?: string;
  created_at: string;
}

export interface Hypothesis {
  id: string;
  group_id: string;
  target_id: string;
  asset_id: string;
  endpoint?: string;
  title: string;
  description: string;
  category: HypothesisCategory;
  epistemic_status: EpistemicStatus;
  status: HypothesisStatus;
  reasoning_method: string;
  supporting_signals: string[];
  supporting_evidence: string[];
  contradicting_evidence?: string[];
  falsification_conditions?: FalsificationCondition[];
  missing_evidence?: EvidenceRequirement[];
  evidence_strength: number; // 0 to 5
  investigation_priority: number; // 0 to 100
  priority_breakdown?: Record<string, number>;
  created_at: string;
  updated_at: string;
}

export interface HypothesisGroup {
  id: string;
  target_id: string;
  asset_id: string;
  subject: string;
  hypothesis_ids: string[];
  hypotheses?: Hypothesis[];
  signals: string[];
  has_competing_theories: boolean;
  created_at: string;
  updated_at: string;
}

export interface InvestigationStep {
  step_number: number;
  name: string;
  description: string;
  action_type: string;
  scope_constraint: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'SKIPPED';
  executed_at?: string;
  result_summary?: string;
}

export type InvestigationStatus = 'PLANNED' | 'RUNNING' | 'COMPLETED' | 'CANCELLED' | 'BLOCKED' | 'SIMULATED';

export interface Investigation {
  id: string;
  target_id: string;
  asset_id: string;
  hypothesis_id: string;
  group_id: string;
  title: string;
  objective: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  priority_score: number;
  priority_factors?: Record<string, number>;
  status: InvestigationStatus;
  data_origin?: 'LIVE_BACKEND' | 'DEMO_SYNTHETIC' | 'SIMULATED' | 'UNVERIFIED';
  steps: InvestigationStep[];
  created_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  result_summary?: string;
}

export interface TrustBoundary {
  id: string;
  target_id: string;
  asset_id: string;
  name: string;
  boundary_type: string;
  upstream_component: string;
  downstream_component: string;
  authentication_required: boolean;
  transport_security: string;
  header_scrubbing_active: boolean;
  notes?: string;
  observed_at: string;
}

export interface AuthContext {
  id: string;
  target_id: string;
  name: string;
  context_type: 'ANONYMOUS' | 'AUTHENTICATED_USER' | 'ADMINISTRATIVE' | 'SERVICE_ACCOUNT';
  identifier: string;
  token_hash_preview?: string;
  role: string;
  scope_claims?: string[];
  is_active: boolean;
  created_at: string;
}

export interface PermissionMatrixEntry {
  id: string;
  target_id: string;
  asset_id: string;
  endpoint: string;
  http_method: string;
  auth_context_id: string;
  auth_role: string;
  expected_access: 'ALLOW' | 'DENY' | 'CHALLENGE' | 'UNKNOWN';
  observed_access: 'ALLOW' | 'DENY' | 'CHALLENGE' | 'UNKNOWN';
  status_code: number;
  evidence_ref?: string;
  evaluated_at: string;
}

export interface SecurityControlRecord {
  id: string;
  target_id: string;
  asset_id: string;
  control_name: string;
  control_category: string;
  expected_behavior: string;
  observed_behavior: string;
  compliance_status: 'ALIGNED' | 'DEVIATING' | 'INCONCLUSIVE';
  evidence_ref?: string;
  evaluated_at: string;
}

// ==========================================
// Phase 8.2R: UI Truth Layer & Runtime Integrity
// ==========================================

export type RuntimeMode = 'LIVE' | 'DEMO' | 'OFFLINE' | 'PARTIAL' | 'UNKNOWN';

export type RequestState = 'IDLE' | 'LOADING' | 'SUCCESS_DATA' | 'SUCCESS_EMPTY' | 'ERROR' | 'OFFLINE' | 'PARTIAL';

export type RequestStatus = 'IDLE' | 'LOADING' | 'SUCCESS' | 'ERROR' | 'OFFLINE';

export type DataOrigin = 'LIVE_BACKEND' | 'DEMO_SYNTHETIC' | 'DERIVED' | 'SIMULATED' | 'OFFLINE' | 'UNVERIFIED';

export interface DataResponse<T> {
  status: RequestStatus;
  data: T | null;
  error: string | null;
  origin?: DataOrigin;
  timestamp?: string;
}

// ==========================================
// Phase 8: Scope Intelligence & Asset Inspection
// ==========================================

export interface ScopeNormalization {
  original: string;
  normalized: string;
  field: string;
  reason: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
}

export interface RootDomainCandidate {
  id: string;
  normalized_domain: string;
  source_file: string;
  source_path: string;
  source_rule_id?: string;
  evidence: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'DISCOVERED' | 'SELECTED' | 'REJECTED' | 'AMBIGUOUS';
}

export interface CanonicalScope {
  primary_root_domain: string;
  root_domains: string[];
  include_hosts: any[];
  exclude_hosts: any[];
  include_urls: any[];
  exclude_urls: any[];
  path_rules: any[];
  source_files: any[];
  normalizations: ScopeNormalization[];
}

export interface ScopeImportReview {
  id: string;
  file_name: string;
  status: 'PENDING_CONFIRMATION' | 'CONFIRMED' | 'REJECTED';
  root_domains: RootDomainCandidate[];
  selected_root_domain: string;
  rules_discovered: number;
  include_hosts_count: number;
  exclude_hosts_count: number;
  regex_rules_count: number;
  path_rules_count: number;
  warnings_count: number;
  ambiguous_count: number;
  normalizations: ScopeNormalization[];
  canonical_scope?: CanonicalScope;
  original_file_sha256: string;
  canonical_scope_sha256: string;
  normalization_manifest_sha256: string;
  selection_reason?: string;
  target_id?: string;
  confirmed_by?: string;
  source_import_id?: string;
  created_at: string;
  confirmed_at?: string;
}

export interface JSAsset {
  id: string;
  target_id: string;
  asset_id: string;
  url: string;
  parent_url: string;
  discovered_at: string;
  scope_decision: {
    in_scope: boolean;
    reason: string;
  };
  content_sha256: string;
  byte_size: number;
  is_third_party: boolean;
  fetch_status: 'FETCHED' | 'SKIPPED_OUT_OF_SCOPE' | 'FAILED' | 'SIZE_EXCEEDED';
  line_count: number;
  created_at: string;
}

export interface JSReference {
  id: string;
  target_id: string;
  asset_id: string;
  js_asset_id: string;
  source_url: string;
  category: 'API_ROUTE' | 'URL' | 'CLOUD_REFERENCE' | 'TECH_REFERENCE' | 'CONFIG_REFERENCE' | 'SECRET_INDICATOR';
  extracted_value: string;
  normalized_value: string;
  line_number?: number;
  byte_offset?: number;
  source_fragment?: string;
  scope_status: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNKNOWN';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidence_id?: string;
  provenance_sha: string;
  created_at: string;
}

export interface JSSecretIndicator {
  id: string;
  target_id: string;
  asset_id: string;
  js_asset_id: string;
  secret_type: string;
  location: string;
  masked_preview: string;
  sha256: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  source_js_asset: string;
  evidence_id?: string;
  created_at: string;
}

export interface CloudReference {
  id: string;
  target_id: string;
  asset_id?: string;
  provider: 'AWS' | 'AZURE' | 'GCP' | 'CLOUDFLARE' | 'DIGITALOCEAN' | 'OTHER';
  resource_type: 'S3_BUCKET' | 'BLOB_CONTAINER' | 'GCS_BUCKET' | 'CLOUDFRONT' | 'UNKNOWN';
  raw_reference: string;
  normalized_target: string;
  source_origin: string;
  source_location: string;
  scope_status: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNKNOWN';
  validation_status: 'UNCHECKED' | 'SAFE_PROBED' | 'VERIFIED_PUBLIC' | 'VERIFIED_PRIVATE' | 'UNAUTHORIZED';
  status_code?: number;
  public_accessible: boolean;
  evidence_id?: string;
  created_at: string;
}

export interface InvestigationPlanStep {
  step_number: number;
  action_type: string;
  description: string;
  target_url: string;
  status: 'PENDING' | 'APPROVED' | 'EXECUTED' | 'BLOCKED' | 'SKIPPED';
  approved_by_human: boolean;
  approved_at?: string;
  result_evidence_id?: string;
  result_observation?: string;
}

export interface InvestigationPlan {
  id: string;
  target_id: string;
  asset_id?: string;
  hypothesis_id?: string;
  title: string;
  reason: string;
  hypothesis: string;
  why_interesting?: {
    observed_facts: string[];
    deduction: string;
    missing_evidence: string[];
  };
  required_evidence?: string[];
  evidence_required_count: number;
  evidence_satisfied_count: number;
  safe_validation: string;
  expected_observation: string;
  alternative_explanation: string;
  stop_condition: string;
  scope_requirements?: string[];
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  epistemic_status: string;
  status: 'PLANNED' | 'APPROVED' | 'RUNNING' | 'COMPLETED' | 'DISMISSED';
  source_evidence_ids?: string[];
  steps: InvestigationPlanStep[];
  created_at: string;
  updated_at?: string;
}




