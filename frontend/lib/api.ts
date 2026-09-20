import {
  ApiResponse,
  HealthResponse,
  ScanJob,
  ScopeDecision,
  SystemEvent,
  Target,
  VersionResponse,
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
}

export const api = new ApiClient();
export default api;
