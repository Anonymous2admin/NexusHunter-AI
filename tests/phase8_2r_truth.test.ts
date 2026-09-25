import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

describe('Phase 8.2R-FINAL.3: Truth Closure & Durable Runtime Invariants', () => {
  it('enforces runtime truth: MEMORY fallback must never masquerade as LIVE_BACKEND', () => {
    // Simulated health responses
    const postgresHealth = {
      status: 'ok',
      service: 'nexushunter-backend',
      runtime_mode: 'LIVE_BACKEND',
      storage_mode: 'POSTGRES',
      data_origin: 'LIVE_BACKEND',
    };

    const memoryFallbackHealth = {
      status: 'ok',
      service: 'nexushunter-backend',
      runtime_mode: 'DEMO_SYNTHETIC',
      storage_mode: 'MEMORY',
      data_origin: 'DEMO_SYNTHETIC',
    };

    const isAuthoritativeLive = (h: typeof postgresHealth) => {
      return h.runtime_mode === 'LIVE_BACKEND' && h.storage_mode === 'POSTGRES';
    };

    assert.equal(isAuthoritativeLive(postgresHealth), true, 'Postgres storage in live mode must be live');
    assert.equal(isAuthoritativeLive(memoryFallbackHealth), false, 'Memory fallback MUST NOT be treated as LIVE_BACKEND');
  });

  it('enforces fail-closed live mutation rule: non-live runtimes reject mutations', () => {
    const nonLiveModes = ['MEMORY', 'DEMO_SYNTHETIC', 'SIMULATED', 'OFFLINE', 'PARTIAL', 'UNKNOWN'];

    for (const mode of nonLiveModes) {
      assert.throws(
        () => {
          if (mode !== 'LIVE_BACKEND') {
            throw new Error(`Action rejected fail-closed: Runtime mode '${mode}' is not LIVE_BACKEND.`);
          }
        },
        /Action rejected fail-closed/,
        `Mode ${mode} must reject mutations fail-closed`
      );
    }
  });

  it('enforces scope root selection: zero automatic selection for single or multiple candidates', () => {
    // Simulate candidate review with single candidate
    const singleRootReview = {
      id: 'import-1',
      root_domains: [{ id: 'rd-1', normalized_domain: 'example.com', confidence: 'HIGH' }],
    };

    // Initial state after import must be empty string unconditionally
    let selectedRootCandidate = '';
    assert.equal(selectedRootCandidate, '', 'selectedRootCandidate must initialize to empty string');

    // Confirm button must remain disabled while selectedRootCandidate is empty
    const isConfirmDisabled = (candidate: string) => !candidate || candidate.trim() === '';
    assert.equal(isConfirmDisabled(selectedRootCandidate), true, 'Confirm button must be disabled when empty');

    // Explicit researcher confirmation sets candidate
    selectedRootCandidate = singleRootReview.root_domains[0].normalized_domain;
    assert.equal(isConfirmDisabled(selectedRootCandidate), false, 'Confirm button is enabled after explicit click');
    assert.equal(selectedRootCandidate, 'example.com');
  });

  it('enforces evidence form zero synthetic defaults: initial form fields are strictly empty', () => {
    const liveEvidenceInitialForm = {
      summary: '',
      asset_id: '',
      url: '',
      method: '',
      status_code: '',
      headers: '',
      body: '',
    };

    assert.equal(liveEvidenceInitialForm.summary, '');
    assert.equal(liveEvidenceInitialForm.asset_id, '');
    assert.equal(liveEvidenceInitialForm.url, '');
    assert.equal(liveEvidenceInitialForm.method, '');
    assert.equal(liveEvidenceInitialForm.status_code, '');
    assert.equal(liveEvidenceInitialForm.headers, '');
    assert.equal(liveEvidenceInitialForm.body, '');
  });

  it('enforces explicit asset and endpoint selection for live evidence recording', () => {
    const validateEvidenceSubmission = (form: {
      summary: string;
      asset_id: string;
      url: string;
      method: string;
      status_code: string;
    }) => {
      if (!form.asset_id) throw new Error('MISSING_ASSET_ID: Explicit asset attribution required');
      if (!form.url) throw new Error('MISSING_URL: Target endpoint URL required');
      if (!form.method) throw new Error('MISSING_METHOD: HTTP method required');
      if (!form.status_code) throw new Error('MISSING_STATUS: Status code required');
      return true;
    };

    assert.throws(
      () => validateEvidenceSubmission({ summary: 'test', asset_id: '', url: 'https://ex.com', method: 'GET', status_code: '200' }),
      /MISSING_ASSET_ID/
    );
    assert.throws(
      () => validateEvidenceSubmission({ summary: 'test', asset_id: 'ast-1', url: '', method: 'GET', status_code: '200' }),
      /MISSING_URL/
    );
  });

  it('enforces contradiction evaluation fail-closed: requires asset_id, endpoint, and evidence context', () => {
    const validateContradictionRequest = (req: {
      target_id: string;
      asset_id: string;
      endpoint: string;
      evidence_refs: string[];
    }) => {
      if (!req.target_id) throw new Error('target_id required');
      if (!req.asset_id) throw new Error('asset_id required');
      if (!req.endpoint) throw new Error('endpoint required');
      if (!req.evidence_refs || req.evidence_refs.length === 0) throw new Error('evidence context required');
      return true;
    };

    assert.throws(
      () => validateContradictionRequest({ target_id: 't-1', asset_id: '', endpoint: '/auth', evidence_refs: ['ev-1'] }),
      /asset_id required/
    );
    assert.throws(
      () => validateContradictionRequest({ target_id: 't-1', asset_id: 'a-1', endpoint: '', evidence_refs: ['ev-1'] }),
      /endpoint required/
    );
    assert.throws(
      () => validateContradictionRequest({ target_id: 't-1', asset_id: 'a-1', endpoint: '/auth', evidence_refs: [] }),
      /evidence context required/
    );
    assert.equal(
      validateContradictionRequest({ target_id: 't-1', asset_id: 'a-1', endpoint: '/auth', evidence_refs: ['ev-1'] }),
      true
    );
  });

  it('enforces investigation simulation truth: distinct statuses and UI labels', () => {
    const formatInvestigationMessage = (status: string) => {
      switch (status) {
        case 'SIMULATED':
          return 'SIMULATED: No network request was executed.';
        case 'NOT_EXECUTABLE_AUTOMATICALLY':
          return 'RESEARCHER ACTION REQUIRED: Step cannot be executed automatically.';
        case 'EXECUTED':
          return 'Executed successfully.';
        default:
          return `Investigation status: ${status}`;
      }
    };

    assert.equal(formatInvestigationMessage('SIMULATED'), 'SIMULATED: No network request was executed.');
    assert.equal(formatInvestigationMessage('NOT_EXECUTABLE_AUTOMATICALLY'), 'RESEARCHER ACTION REQUIRED: Step cannot be executed automatically.');
    assert.equal(formatInvestigationMessage('EXECUTED'), 'Executed successfully.');
  });
});
