import {
  ApiResponse,
  Asset,
  DiscoveredURL,
  HealthResponse,
  ReconOptions,
  ReconRun,
  ScanJob,
  ScopeDecision,
  SystemEvent,
  Target,
  VersionResponse,
  TechnologyObservation,
  ServiceObservation,
  SecurityObservation,
  AssetChange,
  AssetTag,
  TargetIntelligenceSummary,
  AssetDetail,
} from '../types';

export class ApiError extends Error {
  code: string;
  status: number;
  details?: string;

  constructor(message: string, status: number = 500, code: string = 'API_ERROR', details?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

class ApiClient {
  private baseURL: string;

  constructor(baseURL: string = '') {
    this.baseURL = baseURL;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');

    if (options.body && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      // Handle HTTP error statuses
      if (!response.ok) {
        let errorData: any = null;
        try {
          errorData = await response.json();
        } catch {
          // Response body was not valid JSON
        }

        const message = errorData?.error?.message || errorData?.message || `HTTP error ${response.status}: ${response.statusText}`;
        const code = errorData?.error?.code || `HTTP_${response.status}`;
        const details = errorData?.error?.details || response.statusText;

        throw new ApiError(message, response.status, code, details);
      }

      // Handle 204 No Content
      if (response.status === 204) {
        return null as unknown as T;
      }

      const raw = await response.text();
      if (!raw || raw.trim() === '') {
        return null as unknown as T;
      }

      const json = JSON.parse(raw);
      // Support both { success: true, data: ... } and direct JSON payloads
      if (json && typeof json === 'object' && 'success' in json && 'data' in json) {
        return json.data as T;
      }
      return json as T;
    } catch (err: any) {
      if (err instanceof ApiError) {
        throw err;
      }
      // Network failures, CORS blocks, connection refused
      throw new ApiError(
        err.message || 'Network connectivity error. Could not connect to API server.',
        0,
        'NETWORK_ERROR',
        'Check network connectivity or backend server status.'
      );
    }
  }

  // System
  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/health');
  }

  async getVersion(): Promise<VersionResponse> {
    return this.request<VersionResponse>('/api/version');
  }

  // Targets
  async getTargets(): Promise<Target[]> {
    const res = await this.request<Target[]>('/api/targets');
    return res || [];
  }

  async getTarget(id: string): Promise<Target> {
    return this.request<Target>(`/api/targets/${encodeURIComponent(id)}`);
  }

  async createTarget(payload: {
    name: string;
    root_domain: string;
    allowed_domains: string[];
    allowed_url_patterns?: string[];
    excluded_patterns?: string[];
  }): Promise<Target> {
    return this.request<Target>('/api/targets', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async deleteTarget(id: string): Promise<{ message: string; id: string }> {
    return this.request<{ message: string; id: string }>(`/api/targets/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // Scope Verification
  async verifyScope(payload: {
    target_id: string;
    hostname: string;
    url?: string;
  }): Promise<ScopeDecision> {
    return this.request<ScopeDecision>('/api/scope/verify', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Jobs
  async getJobs(targetId?: string): Promise<ScanJob[]> {
    const query = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    const res = await this.request<ScanJob[]>(`/api/jobs${query}`);
    return res || [];
  }

  async getJob(id: string): Promise<ScanJob> {
    return this.request<ScanJob>(`/api/jobs/${encodeURIComponent(id)}`);
  }

  async createJob(payload: {
    target_id: string;
    type: string;
    metadata?: Record<string, any>;
  }): Promise<ScanJob> {
    return this.request<ScanJob>('/api/jobs', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Events Telemetry
  async getEvents(): Promise<SystemEvent[]> {
    const res = await this.request<SystemEvent[]>('/api/events');
    return res || [];
  }

  // High-Speed Recon Engine
  async startRecon(targetId: string, options?: ReconOptions): Promise<ScanJob> {
    return this.request<ScanJob>('/api/recon', {
      method: 'POST',
      body: JSON.stringify({
        target_id: targetId,
        options: options || {},
      }),
    });
  }

  async getReconRun(jobId: string): Promise<ReconRun> {
    return this.request<ReconRun>(`/api/recon/${encodeURIComponent(jobId)}`);
  }

  async cancelRecon(jobId: string): Promise<{ job_id: string; status: string }> {
    return this.request<{ job_id: string; status: string }>(`/api/recon/${encodeURIComponent(jobId)}/cancel`, {
      method: 'POST',
    });
  }

  async getTargetAssets(targetId: string): Promise<Asset[]> {
    const res = await this.request<Asset[]>(`/api/targets/${encodeURIComponent(targetId)}/assets`);
    return res || [];
  }

  async getTargetURLs(targetId: string): Promise<DiscoveredURL[]> {
    const res = await this.request<DiscoveredURL[]>(`/api/targets/${encodeURIComponent(targetId)}/urls`);
    return res || [];
  }

  // Asset Intelligence & Fingerprinting
  async getTargetIntelligence(targetId: string): Promise<TargetIntelligenceSummary> {
    return this.request<TargetIntelligenceSummary>(`/api/targets/${encodeURIComponent(targetId)}/intelligence`);
  }

  async getTargetTechnologies(targetId: string, category?: string): Promise<TechnologyObservation[]> {
    const query = category ? `?category=${encodeURIComponent(category)}` : '';
    const res = await this.request<TechnologyObservation[]>(`/api/targets/${encodeURIComponent(targetId)}/technologies${query}`);
    return res || [];
  }

  async getTargetServices(targetId: string): Promise<ServiceObservation[]> {
    const res = await this.request<ServiceObservation[]>(`/api/targets/${encodeURIComponent(targetId)}/services`);
    return res || [];
  }

  async getTargetChanges(targetId: string): Promise<AssetChange[]> {
    const res = await this.request<AssetChange[]>(`/api/targets/${encodeURIComponent(targetId)}/changes`);
    return res || [];
  }

  async getAssetDetail(targetId: string, assetId: string): Promise<AssetDetail> {
    return this.request<AssetDetail>(`/api/targets/${encodeURIComponent(targetId)}/assets/${encodeURIComponent(assetId)}`);
  }

  async addAssetTag(assetId: string, targetId: string, tag: string): Promise<AssetTag> {
    return this.request<AssetTag>(`/api/assets/${encodeURIComponent(assetId)}/tags`, {
      method: 'POST',
      body: JSON.stringify({ target_id: targetId, tag }),
    });
  }

  async deleteAssetTag(assetId: string, tag: string): Promise<{ message: string; tag: string }> {
    return this.request<{ message: string; tag: string }>(
      `/api/assets/${encodeURIComponent(assetId)}/tags/${encodeURIComponent(tag)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // Phase 4: AI Analysis & Finding Candidates
  async runAIAnalysis(payload: {
    target_id: string;
    asset_id?: string;
    provider?: string;
    model?: string;
  }): Promise<{ run_id: string; candidates: any[]; signals: any[]; execution_time_ms: number }> {
    return this.request('/api/ai/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getCandidates(targetId: string, state?: string): Promise<any[]> {
    const query = state ? `?state=${encodeURIComponent(state)}` : '';
    const res = await this.request<any[]>(`/api/targets/${encodeURIComponent(targetId)}/candidates${query}`);
    return res || [];
  }

  async getCandidateDetail(candidateId: string): Promise<any> {
    return this.request(`/api/candidates/${encodeURIComponent(candidateId)}`);
  }

  async updateCandidateState(candidateId: string, newState: string, reason?: string): Promise<any> {
    return this.request(`/api/candidates/${encodeURIComponent(candidateId)}/state`, {
      method: 'PATCH',
      body: JSON.stringify({ state: newState, reason }),
    });
  }

  // Phase 5: Security Intelligence & Investigation Engine
  async getTargetGraph(targetId: string): Promise<any> {
    return this.request(`/api/targets/${encodeURIComponent(targetId)}/graph`);
  }

  async getTemporalChanges(targetId: string, limit?: number): Promise<any[]> {
    const query = limit ? `?limit=${limit}` : '';
    const res = await this.request<any[]>(`/api/targets/${encodeURIComponent(targetId)}/temporal-changes${query}`);
    return res || [];
  }

  async getInvariants(targetId: string): Promise<any[]> {
    const res = await this.request<any[]>(`/api/targets/${encodeURIComponent(targetId)}/invariants`);
    return res || [];
  }

  async getBehaviorDifferences(targetId: string): Promise<any[]> {
    const res = await this.request<any[]>(`/api/targets/${encodeURIComponent(targetId)}/behavior-diffs`);
    return res || [];
  }

  async getInvestigationClusters(targetId: string): Promise<any[]> {
    const res = await this.request<any[]>(`/api/targets/${encodeURIComponent(targetId)}/investigation-clusters`);
    return res || [];
  }

  async updateClusterStatus(clusterId: string, status: string): Promise<any> {
    return this.request(`/api/investigation-clusters/${encodeURIComponent(clusterId)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  async getResearchMemory(targetId: string): Promise<any> {
    return this.request(`/api/targets/${encodeURIComponent(targetId)}/research-memory`);
  }

  async executeControlledValidation(payload: {
    target_id: string;
    candidate_id?: string;
    cluster_id?: string;
    verification_step?: string;
  }): Promise<any> {
    return this.request('/api/validation/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Phase 6: Evidence Intelligence & Security Reasoning
  async recordEvidence(evidence: any): Promise<any> {
    return this.request('/api/evidence', {
      method: 'POST',
      body: JSON.stringify(evidence),
    });
  }

  async getEvidence(id: string): Promise<any> {
    return this.request(`/api/evidence/${encodeURIComponent(id)}`);
  }

  async getTargetEvidence(targetId: string): Promise<any> {
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/evidence`);
    return res?.evidence || [];
  }

  async getAssetEvidence(assetId: string): Promise<any> {
    const res = await this.request<any>(`/api/assets/${encodeURIComponent(assetId)}/evidence`);
    return res?.evidence || [];
  }

  async computeEvidenceDiff(evidenceAId: string, evidenceBId: string, filterNoise: boolean = true): Promise<any> {
    return this.request('/api/evidence/diff', {
      method: 'POST',
      body: JSON.stringify({
        evidence_a_id: evidenceAId,
        evidence_b_id: evidenceBId,
        filter_noise: filterNoise,
      }),
    });
  }

  async getEvidenceDiff(id: string): Promise<any> {
    return this.request(`/api/evidence/diffs/${encodeURIComponent(id)}`);
  }

  async getTargetDiffs(targetId: string): Promise<any[]> {
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/diffs`);
    return res?.diffs || [];
  }

  async createSecurityExpectation(expectation: any): Promise<any> {
    return this.request('/api/expectations', {
      method: 'POST',
      body: JSON.stringify(expectation),
    });
  }

  async getTargetExpectations(targetId: string, assetId?: string): Promise<any[]> {
    const q = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : '';
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/expectations${q}`);
    return res?.expectations || [];
  }

  async evaluateContradiction(payload: any): Promise<any> {
    return this.request('/api/contradictions/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getTargetContradictions(targetId: string, assetId?: string): Promise<any[]> {
    const q = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : '';
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/contradictions${q}`);
    return res?.contradictions || [];
  }

  async updateContradictionStatus(id: string, status: string): Promise<any> {
    return this.request(`/api/contradictions/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  async getTargetOutliers(targetId: string, assetId?: string): Promise<any[]> {
    const q = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : '';
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/outliers${q}`);
    return res?.outliers || [];
  }

  async getAssetInterest(targetId: string, assetId: string, hostname?: string): Promise<any> {
    const q = hostname ? `?hostname=${encodeURIComponent(hostname)}` : '';
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/assets/${encodeURIComponent(assetId)}/interest${q}`);
    return res?.interest_summary;
  }

  async getEvidenceTimeline(targetId: string, assetId?: string, limit?: number): Promise<any[]> {
    const params = new URLSearchParams();
    if (assetId) params.set('asset_id', assetId);
    if (limit) params.set('limit', String(limit));
    const q = params.toString() ? `?${params.toString()}` : '';
    const res = await this.request<any>(`/api/targets/${encodeURIComponent(targetId)}/evidence-timeline${q}`);
    return res?.events || [];
  }

  // ==========================================
  // Phase 7: Reasoning & Investigation Intelligence
  // ==========================================

  async getSignals(targetId?: string, assetId?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (targetId) params.set('target_id', targetId);
    if (assetId) params.set('asset_id', assetId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return this.request<any[]>(`/api/signals${q}`);
  }

  async getSignal(id: string): Promise<any> {
    return this.request<any>(`/api/signals/${encodeURIComponent(id)}`);
  }

  async updateSignalStatus(id: string, status: string): Promise<any> {
    return this.request<any>(`/api/signals/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  async getHypotheses(targetId?: string, groupId?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (targetId) params.set('target_id', targetId);
    if (groupId) params.set('group_id', groupId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return this.request<any[]>(`/api/hypotheses${q}`);
  }

  async getHypothesis(id: string): Promise<any> {
    return this.request<any>(`/api/hypotheses/${encodeURIComponent(id)}`);
  }

  async updateHypothesisStatus(id: string, status: string): Promise<any> {
    return this.request<any>(`/api/hypotheses/${encodeURIComponent(id)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    });
  }

  async getHypothesisEvidence(id: string): Promise<any[]> {
    return this.request<any[]>(`/api/hypotheses/${encodeURIComponent(id)}/evidence`);
  }

  async getHypothesisAlternatives(id: string): Promise<any[]> {
    return this.request<any[]>(`/api/hypotheses/${encodeURIComponent(id)}/alternatives`);
  }

  async getHypothesisGroups(targetId?: string): Promise<any[]> {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    return this.request<any[]>(`/api/hypothesis-groups${q}`);
  }

  async getHypothesisGroup(id: string): Promise<any> {
    return this.request<any>(`/api/hypothesis-groups/${encodeURIComponent(id)}`);
  }

  async getInvestigations(targetId?: string): Promise<any[]> {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    return this.request<any[]>(`/api/investigations${q}`);
  }

  async planInvestigation(hypothesisId: string, createdBy: string = 'RESEARCHER'): Promise<any> {
    return this.request<any>('/api/investigations', {
      method: 'POST',
      body: JSON.stringify({ hypothesis_id: hypothesisId, created_by: createdBy }),
    });
  }

  async getInvestigation(id: string): Promise<any> {
    return this.request<any>(`/api/investigations/${encodeURIComponent(id)}`);
  }

  async cancelInvestigation(id: string): Promise<any> {
    return this.request<any>(`/api/investigations/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
    });
  }

  async executeInvestigationStep(id: string): Promise<any> {
    return this.request<any>(`/api/investigations/${encodeURIComponent(id)}/execute`, {
      method: 'POST',
    });
  }

  async getAssetTrustBoundaries(assetId: string, targetId?: string): Promise<any[]> {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    return this.request<any[]>(`/api/assets/${encodeURIComponent(assetId)}/trust-boundaries${q}`);
  }

  async getAssetPermissionMatrix(assetId: string, targetId?: string): Promise<any[]> {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    return this.request<any[]>(`/api/assets/${encodeURIComponent(assetId)}/permission-matrix${q}`);
  }

  async recordPermissionMatrixEntry(assetId: string, entry: any): Promise<any> {
    return this.request<any>(`/api/assets/${encodeURIComponent(assetId)}/permission-matrix`, {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  }

  async getAssetSecurityControls(assetId: string, targetId?: string): Promise<any[]> {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    return this.request<any[]>(`/api/assets/${encodeURIComponent(assetId)}/security-controls${q}`);
  }

  async getAuthContexts(targetId?: string): Promise<any[]> {
    const q = targetId ? `?target_id=${encodeURIComponent(targetId)}` : '';
    return this.request<any[]>(`/api/auth-contexts${q}`);
  }

  async createAuthContext(context: any): Promise<any> {
    return this.request<any>('/api/auth-contexts', {
      method: 'POST',
      body: JSON.stringify(context),
    });
  }

  async triggerReasoningCycle(targetId: string, assetId?: string): Promise<any> {
    return this.request<any>('/api/reasoning/analyze', {
      method: 'POST',
      body: JSON.stringify({ target_id: targetId, asset_id: assetId }),
    });
  }

  async aiAssistedReasoning(targetId: string, hypothesisId: string, prompt: string, evidenceIds: string[]): Promise<any> {
    return this.request<any>('/api/reasoning/ai-assist', {
      method: 'POST',
      body: JSON.stringify({
        target_id: targetId,
        hypothesis_id: hypothesisId,
        prompt,
        evidence_ids: evidenceIds,
      }),
    });
  }
}

export const api = new ApiClient();
export default api;

