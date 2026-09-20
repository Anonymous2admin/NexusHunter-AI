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

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: string;
  };
}
