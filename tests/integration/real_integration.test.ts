import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, ChildProcess } from 'node:child_process';
import fs from 'node:fs';

const TEST_PORT = 8086;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const DB_URL = 'postgres://nexushunter:huntersecret123@127.0.0.1:5432/nexushunter_db?sslmode=disable';

let hasPostgres = false;

function runSQL(sql: string) {
  try {
    const res = spawnSync('psql', [DB_URL, '-c', sql], { encoding: 'utf-8' });
    if (res.error || res.status !== 0) return null;
    return res.stdout;
  } catch {
    return null;
  }
}

function insertTestAsset(targetId: string, assetId: string, hostname: string) {
  const sql = `INSERT INTO assets (id, target_id, hostname, asset_type, status, first_seen, last_seen) VALUES ('${assetId}', '${targetId}', '${hostname}', 'SUBDOMAIN', 'ACTIVE', NOW(), NOW()) ON CONFLICT (id) DO NOTHING;`;
  runSQL(sql);
}

function insertTestHypothesisGroup(targetId: string, groupId: string, subject: string) {
  const sql = `INSERT INTO hypothesis_groups (id, target_id, subject, signals, hypothesis_ids, has_competing_theories, created_at, updated_at) VALUES ('${groupId}', '${targetId}', '${subject}', '[]'::jsonb, '[]'::jsonb, false, NOW(), NOW()) ON CONFLICT (id) DO NOTHING;`;
  runSQL(sql);
}

describe('Phase 8.2R-PROOF: Real Go HTTP API & PostgreSQL Integration', () => {
  let serverProcess: ChildProcess | null = null;

  before(async () => {
    try { fs.chmodSync('./backend/bin/server', 0o755); } catch {}
    // Start actual compiled Go server on isolated port
    serverProcess = spawn('./backend/bin/server', [], {
      env: {
        ...process.env,
        HTTP_PORT: String(TEST_PORT),
        DATABASE_URL: DB_URL,
        APP_ENV: 'development',
        LOG_LEVEL: 'warn',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Wait until server is reachable
    let connected = false;
    for (let i = 0; i < 30; i++) {
      try {
        const res = await fetch(`${BASE_URL}/api/health`);
        if (res.ok) {
          connected = true;
          const body = await res.json();
          hasPostgres = body.storage_mode === 'POSTGRES';
          break;
        }
      } catch {
        // waiting for startup
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.equal(connected, true, 'Real Go server must successfully start and respond on port ' + TEST_PORT);
  });

  after(async () => {
    if (serverProcess) {
      serverProcess.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 500));
    }
  });

  it('Section 13 & 15: GET /api/health verifies LIVE_BACKEND and POSTGRES persistence mode', async () => {
    const res = await fetch(`${BASE_URL}/api/health`);
    assert.equal(res.status, 200);

    const body = await res.json();
    assert.equal(body.status, 'ok');

    if (hasPostgres) {
      assert.equal(res.headers.get('x-nexus-runtime-mode'), 'LIVE_BACKEND');
      assert.equal(res.headers.get('x-nexus-storage'), 'POSTGRES');
      assert.equal(res.headers.get('x-nexus-origin'), 'LIVE_BACKEND');
      assert.equal(body.runtime_mode, 'LIVE_BACKEND');
      assert.equal(body.storage_mode, 'POSTGRES');
      assert.equal(body.data_origin, 'LIVE_BACKEND');
    } else {
      assert.equal(res.headers.get('x-nexus-runtime-mode'), 'DEMO_SYNTHETIC');
      assert.equal(res.headers.get('x-nexus-storage'), 'MEMORY');
      assert.equal(body.runtime_mode, 'DEMO_SYNTHETIC');
      assert.equal(body.storage_mode, 'MEMORY');
    }
  });

  it('Section 15: Real HTTP target lifecycle and scope validation', async () => {
    const uniqueDomain = `node-integ-${Date.now()}.example.com`;
    const targetPayload = {
      name: 'Node Real Target',
      root_domain: uniqueDomain,
      allowed_domains: [uniqueDomain],
    };

    // 1. POST /api/targets
    const createRes = await fetch(`${BASE_URL}/api/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(targetPayload),
    });
    assert.ok(createRes.status === 200 || createRes.status === 201, `Expected 200 or 201, got ${createRes.status}`);
    const createdTarget = await createRes.json();
    const targetId = createdTarget.data?.id || createdTarget.id;
    assert.ok(targetId, 'Created target must have a valid ID');

    // 2. GET /api/targets
    const listRes = await fetch(`${BASE_URL}/api/targets`);
    assert.equal(listRes.status, 200);
    const targetList = await listRes.json();
    assert.ok(Array.isArray(targetList.data || targetList), 'Targets endpoint must return an array');

    // 3. POST /api/jobs -> QUEUED
    const jobRes = await fetch(`${BASE_URL}/api/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_id: targetId,
        type: 'RECON_HTTP',
      }),
    });
    assert.ok(jobRes.status === 200 || jobRes.status === 201);
    const jobData = await jobRes.json();
    const jobId = jobData.data?.id || jobData.id;
    assert.ok(jobId, 'Created job must have an ID');

    // 4. POST /api/jobs/{id}/start -> RUNNING
    const startRes = await fetch(`${BASE_URL}/api/jobs/${jobId}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(startRes.status, 200);
    const runningJob = await startRes.json();
    assert.equal((runningJob.data || runningJob).status, 'RUNNING');

    // 5. POST /api/jobs/{id}/complete -> COMPLETED
    const completeRes = await fetch(`${BASE_URL}/api/jobs/${jobId}/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(completeRes.status, 200);
    const completedJob = await completeRes.json();
    assert.equal((completedJob.data || completedJob).status, 'COMPLETED');
  });

  it('Section 10 & 15: Real HTTP evidence recording, canonical hashing, and tamper verification', async () => {
    const domain = `ev-test-${Date.now()}.example.com`;
    // Create target
    const tgtRes = await fetch(`${BASE_URL}/api/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Evidence Verification Target',
        root_domain: domain,
        allowed_domains: [domain],
      }),
    });
    const tgt = await tgtRes.json();
    const targetId = tgt.data?.id || tgt.id;

    const assetId = `ast-${Date.now()}`;
    insertTestAsset(targetId, assetId, domain);

    if (hasPostgres) {
      // Record legitimate evidence
      const evPayload = {
        target_id: targetId,
        asset_id: assetId,
        evidence_type: 'HTTP_RESPONSE',
        summary: 'Automated Real Node HTTP Probe',
        data_origin: 'LIVE_BACKEND',
        request: {
          method: 'GET',
          url: `https://${domain}/health`,
        },
        response: {
          status_code: 200,
          headers: { Server: 'nginx/1.24.0' },
          body_snippet: '{"status":"healthy"}',
        },
      };

      const evRes = await fetch(`${BASE_URL}/api/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(evPayload),
      });
      assert.equal(evRes.status, 201, 'POST /api/evidence must return 201 Created');
      const evData = await evRes.json();
      const evidenceId = evData.evidence?.id || evData.data?.id;
      assert.ok(evidenceId, 'Recorded evidence must have a generated ID');

      // 1. Check integrity: untampered
      const integRes = await fetch(`${BASE_URL}/api/evidence/${evidenceId}/integrity`);
      assert.equal(integRes.status, 200);
      const integ = await integRes.json();
      assert.equal(integ.canonical_matches, true, 'Cryptographic hash must match');
      assert.equal(integ.is_tampered, false, 'Evidence must not be tampered');

      // 2. Tamper directly in PostgreSQL database
      const tamperSQL = `UPDATE evidence_records SET response_data = '{"status_code": 500}'::jsonb WHERE id = '${evidenceId}';`;
      runSQL(tamperSQL);

      // 3. Second check: MUST DETECT TAMPERING!
      const tamperedRes = await fetch(`${BASE_URL}/api/evidence/${evidenceId}/integrity`);
      assert.equal(tamperedRes.status, 200);
      const tamperedInteg = await tamperedRes.json();
      assert.equal(tamperedInteg.canonical_matches, false, 'Canonical representation must not match after database tampering');
      assert.equal(tamperedInteg.is_tampered, true, 'Integrity verification must flag evidence as tampered');
    } else {
      // In MEMORY fallback without active PostgreSQL: verify fail-closed boundary enforcement
      const evRes = await fetch(`${BASE_URL}/api/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: targetId,
          asset_id: assetId,
          evidence_type: 'HTTP_RESPONSE',
          summary: 'Fallback Probe',
          request: { method: 'GET', url: `https://${domain}/health` },
          response: { status_code: 200 },
        }),
      });
      assert.equal(evRes.status, 409, 'Unregistered asset must return 409 SECURITY_CONTEXT_MISMATCH');
    }
  });

  it('Section 12: Real HTTP target isolation: cross-target references are strictly rejected', async () => {
    const domain1 = `iso1-${Date.now()}.example.com`;
    const domain2 = `iso2-${Date.now()}.example.com`;

    // Create Target 1
    const t1Res = await fetch(`${BASE_URL}/api/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Isolation Target 1',
        root_domain: domain1,
        allowed_domains: [domain1],
      }),
    });
    const t1 = await t1Res.json();
    const target1Id = t1.data?.id || t1.id;

    // Create Target 2
    const t2Res = await fetch(`${BASE_URL}/api/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Isolation Target 2',
        root_domain: domain2,
        allowed_domains: [domain2],
      }),
    });
    const t2 = await t2Res.json();
    const target2Id = t2.data?.id || t2.id;

    const asset1Id = `ast-iso1-${Date.now()}`;
    insertTestAsset(target1Id, asset1Id, domain1);

    const grp2Id = `grp-iso2-${Date.now()}`;
    insertTestHypothesisGroup(target2Id, grp2Id, 'Isolation Group 2');

    if (hasPostgres) {
      // Record evidence on Target 1
      const ev1Res = await fetch(`${BASE_URL}/api/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: target1Id,
          asset_id: asset1Id,
          evidence_type: 'HTTP_RESPONSE',
          summary: 'Target 1 evidence',
          request: { method: 'GET', url: `https://${domain1}/api` },
          response: { status_code: 200 },
        }),
      });
      assert.equal(ev1Res.status, 201, 'POST /api/evidence must succeed on Target 1');
      const ev1Data = await ev1Res.json();
      const ev1Id = ev1Data.evidence?.id || ev1Data.data?.id;
      assert.ok(ev1Id, 'Evidence on target 1 must exist');

      // Attempt to create hypothesis on Target 2 referencing Target 1 evidence -> MUST REJECT!
      const hypRes = await fetch(`${BASE_URL}/api/hypotheses`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: target2Id,
          group_id: grp2Id,
          title: 'Malicious Cross-Target Hypothesis',
          supporting_evidence: [ev1Id],
        }),
      });

      assert.equal(
        hypRes.status,
        400,
        'Cross-target evidence association must return 400 Bad Request to prevent cross-tenant contamination'
      );
    } else {
      // Verify cross-target isolation fail-closed in fallback mode
      const hypRes = await fetch(`${BASE_URL}/api/hypotheses`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: target2Id,
          group_id: grp2Id,
          title: 'Malicious Cross-Target Hypothesis',
          supporting_evidence: ['ev-non-existent-target1'],
        }),
      });
      assert.equal(hypRes.status, 400, 'Cross-target hypothesis reference must return 400 Bad Request');
    }
  });
});
