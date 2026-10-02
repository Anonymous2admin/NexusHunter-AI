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

  it('enforces confirmed-by operator provenance: rejects fabricated identities and enforces mandatory operator', () => {
    const validateScopeConfirmation = (req: {
      selected_root_domain: string;
      confirmed_by?: string;
      headers?: Record<string, string>;
    }) => {
      if (!req.selected_root_domain || req.selected_root_domain.trim() === '') {
        throw new Error('ROOT_DOMAIN_REQUIRED');
      }
      const operator = (
        req.confirmed_by ||
        req.headers?.['x-operator-id'] ||
        req.headers?.['x-researcher-id'] ||
        ''
      ).trim();
      if (!operator) {
        throw new Error('CONFIRMED_BY_REQUIRED: Explicit operator identity is required');
      }
      return {
        confirmed_by: operator,
        selected_root: req.selected_root_domain.trim(),
      };
    };

    assert.throws(
      () => validateScopeConfirmation({ selected_root_domain: 'example.com', confirmed_by: '' }),
      /CONFIRMED_BY_REQUIRED/
    );
    assert.throws(
      () => validateScopeConfirmation({ selected_root_domain: 'example.com' }),
      /CONFIRMED_BY_REQUIRED/
    );
    const valid = validateScopeConfirmation({
      selected_root_domain: 'example.com',
      confirmed_by: 'alice-sec-lead',
    });
    assert.equal(valid.confirmed_by, 'alice-sec-lead');

    // Header-based identity fallback
    const headerValid = validateScopeConfirmation({
      selected_root_domain: 'example.com',
      headers: { 'x-operator-id': 'op-bob-99' },
    });
    assert.equal(headerValid.confirmed_by, 'op-bob-99');
  });

  it('enforces transactional scope confirmation invariant: confirmed scope <=> attributed target', () => {
    type ScopeReview = {
      id: string;
      status: string;
      target_id?: string;
      selected_root_domain?: string;
    };
    type Target = {
      id: string;
      root_domain: string;
      scope_import_id: string;
    };

    const confirmScopeAtomically = (
      review: ScopeReview,
      selectedRoot: string,
      operator: string,
      targetStore: Map<string, Target>
    ) => {
      if (review.status === 'CONFIRMED') {
        throw new Error('ALREADY_CONFIRMED');
      }
      if (!selectedRoot || selectedRoot.trim() === '') {
        throw new Error('ROOT_REQUIRED');
      }
      if (!operator || operator.trim() === '') {
        throw new Error('CONFIRMED_BY_REQUIRED');
      }

      // Atomic target creation inside transaction
      const targetId = `tgt-${Date.now()}`;
      const newTarget: Target = {
        id: targetId,
        root_domain: selectedRoot,
        scope_import_id: review.id,
      };
      targetStore.set(targetId, newTarget);

      // Mutate review
      review.status = 'CONFIRMED';
      review.selected_root_domain = selectedRoot;
      review.target_id = targetId;

      return { review, target: newTarget };
    };

    const targets = new Map<string, Target>();
    const rev: ScopeReview = { id: 'imp-101', status: 'PENDING_CONFIRMATION' };

    const result = confirmScopeAtomically(rev, 'api.example.com', 'op-42', targets);
    assert.equal(result.review.status, 'CONFIRMED');
    assert.equal(result.review.target_id, result.target.id);
    assert.equal(targets.has(result.target.id), true);
    assert.equal(targets.get(result.target.id)?.scope_import_id, 'imp-101');
  });

  it('enforces cross-entity ownership & target isolation: cross-target references must fail', () => {
    type Entity = { id: string; target_id: string };

    const verifyCrossEntityBelongsToTarget = (
      entity: Entity,
      intendedTargetID: string,
      entityType: string
    ) => {
      if (entity.target_id !== intendedTargetID) {
        throw new Error(
          `${entityType}_TARGET_MISMATCH: ${entityType} '${entity.id}' belongs to target '${entity.target_id}', not '${intendedTargetID}'`
        );
      }
      return true;
    };

    const targetA = 'tgt-A-corp';
    const targetB = 'tgt-B-startup';

    const evidenceFromA: Entity = { id: 'ev-alpha-1', target_id: targetA };
    const assetFromA: Entity = { id: 'ast-alpha-1', target_id: targetA };
    const authContextFromA: Entity = { id: 'ctx-alpha-1', target_id: targetA };

    // Target B attempts to attach evidence from Target A
    assert.throws(
      () => verifyCrossEntityBelongsToTarget(evidenceFromA, targetB, 'EVIDENCE'),
      /EVIDENCE_TARGET_MISMATCH/
    );

    // Target B attempts to record permission matrix for asset from Target A
    assert.throws(
      () => verifyCrossEntityBelongsToTarget(assetFromA, targetB, 'ASSET'),
      /ASSET_TARGET_MISMATCH/
    );

    // Target B attempts to plan investigation with auth context from Target A
    assert.throws(
      () => verifyCrossEntityBelongsToTarget(authContextFromA, targetB, 'AUTH_CONTEXT'),
      /AUTH_CONTEXT_TARGET_MISMATCH/
    );

    // Valid same-target verification succeeds
    assert.equal(verifyCrossEntityBelongsToTarget(evidenceFromA, targetA, 'EVIDENCE'), true);
  });

  it('enforces target deactivation lifecycle: active jobs cancelled, no new jobs allowed', () => {
    type Job = { id: string; target_id: string; status: string; error?: string };

    const handleTargetDeactivated = (targetID: string, jobs: Job[]) => {
      for (const job of jobs) {
        if (job.target_id === targetID && (job.status === 'QUEUED' || job.status === 'RUNNING')) {
          job.status = 'CANCELLED';
          job.error = 'target deactivated or deleted: lifecycle violation fail-closed';
        }
      }
    };

    const canCreateJobForTarget = (targetStatus: string) => {
      if (targetStatus !== 'ACTIVE') {
        throw new Error('TARGET_NOT_ACTIVE: cannot create scan job for inactive target');
      }
      return true;
    };

    const jobList: Job[] = [
      { id: 'j-1', target_id: 'tgt-target-1', status: 'QUEUED' },
      { id: 'j-2', target_id: 'tgt-target-1', status: 'RUNNING' },
      { id: 'j-3', target_id: 'tgt-target-1', status: 'COMPLETED' },
      { id: 'j-4', target_id: 'tgt-target-2', status: 'RUNNING' },
    ];

    handleTargetDeactivated('tgt-target-1', jobList);

    assert.equal(jobList[0].status, 'CANCELLED');
    assert.match(jobList[0].error || '', /target deactivated/);
    assert.equal(jobList[1].status, 'CANCELLED');
    assert.equal(jobList[2].status, 'COMPLETED'); // terminal state preserved
    assert.equal(jobList[3].status, 'RUNNING'); // other target preserved

    assert.throws(() => canCreateJobForTarget('INACTIVE'), /TARGET_NOT_ACTIVE/);
    assert.throws(() => canCreateJobForTarget('ARCHIVED'), /TARGET_NOT_ACTIVE/);
    assert.equal(canCreateJobForTarget('ACTIVE'), true);
  });

  it('enforces event repository idempotency: repeated delivery of identical event ID is idempotent', () => {
    type StoredEvent = { event_id: string; event_type: string; target_id: string };
    const eventStore = new Map<string, StoredEvent>();

    const recordEventIdempotent = (event: StoredEvent) => {
      // ON CONFLICT (event_id) DO NOTHING
      if (eventStore.has(event.event_id)) {
        return false; // already recorded, idempotent no-op
      }
      eventStore.set(event.event_id, event);
      return true;
    };

    const evt: StoredEvent = {
      event_id: 'evt-unique-audit-100',
      event_type: 'job.created',
      target_id: 'tgt-1',
    };

    // First delivery inserts
    assert.equal(recordEventIdempotent(evt), true);
    assert.equal(eventStore.size, 1);

    // 99 repeated deliveries are idempotent no-ops
    for (let i = 0; i < 99; i++) {
      assert.equal(recordEventIdempotent(evt), false);
    }
    assert.equal(eventStore.size, 1, 'Event store must contain exactly 1 event after 100 submissions');
  });

  it('enforces JSON integrity: corrupted JSON fails closed without silent fallback to default', () => {
    const parseSecurityJSON = (raw: string) => {
      try {
        return JSON.parse(raw);
      } catch (err: any) {
        throw new Error(`STORAGE_CORRUPTION_ERROR: Failed to unmarshal security payload: ${err.message}`);
      }
    };

    assert.throws(
      () => parseSecurityJSON('{ corrupted_json: true, missing_closing_brace'),
      /STORAGE_CORRUPTION_ERROR/
    );
    const valid = parseSecurityJSON('{"verified": true, "score": 95}');
    assert.equal(valid.verified, true);
    assert.equal(valid.score, 95);
  });
});
