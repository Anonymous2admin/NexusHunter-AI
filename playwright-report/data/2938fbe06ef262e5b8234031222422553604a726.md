# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: browser-truth.spec.ts >> Phase 8.2R-PROOF.2: Real Browser E2E Suite (Chromium + Vite + React + Go) >> Section 12: Real UI Distinction between HTTP 500 ERROR and HTTP 200 SUCCESS_EMPTY
- Location: tests/browser-e2e/browser-truth.spec.ts:267:3

# Error details

```
Error: expect(locator).toBeVisible() failed

Locator: locator('text=No active security hypotheses')
Expected: visible
Timeout: 8000ms
Error: element(s) not found

Call log:
  - Expect "toBeVisible" locator('text=No active security hypotheses') with timeout 8000ms
  - waiting for locator('text=No active security hypotheses')

```

```yaml
- complementary:
  - text: NexusHunter AI
  - paragraph: Security Research Engine
  - text: Scope Policy Active
  - paragraph: Strict authorization mode. Probing unauthorized hosts fails closed.
  - navigation:
    - paragraph: Platform Modules
    - button "Dashboard"
    - button "Authorized Targets 1"
    - button "Scan Lifecycle"
    - button "Asset Intelligence Assets"
    - button "Finding Pipeline 2"
    - button "Investigation Graph Intel"
    - button "Evidence & Comparative Analysis 3"
    - button "Security Reasoning & Investigation Logic"
    - button "Scope Inspector Fail-Closed"
  - text: Go Core API v0.1.0-alpha PostgreSQL Connected
- banner:
  - heading "Security Reasoning & Investigation" [level=1]
  - paragraph: Competing explanations, falsification conditions, missing evidence requirements & bounded investigations
  - text: LIVE (ENGINE) Local-First
  - button "Sync"
- main:
  - heading "Security Reasoning & Hypotheses" [level=1]
  - text: Phase 7
  - paragraph: Transforms raw empirical observations into competing hypotheses, falsification criteria, and bounded investigations.
  - combobox:
    - option "Example Security Program (example.com)" [selected]
  - button "Run Reasoning Cycle"
  - text: "Strict Epistemic Principles: Competing hypotheses are maintained simultaneously. A state of NOT_OBSERVED is never assumed to mean ABSENT. An endpoint or behavior is HYPOTHESIZED until empirical evidence satisfies deliberate falsification conditions. Reasoning Signals 0 From verified observations Hypothesis Groups 0 Clustered attack surfaces Competing Theories 0 Falsifiable explanations Planned Investigations 0 Safe, non-destructive"
  - button "Competing Hypotheses (0)"
  - button "Reasoning Signals (0)"
  - button "Investigations (0)"
  - button "Trust Boundaries & Matrix"
  - button "Evidence-Grounded Planner & Guardrail"
  - heading "No Hypotheses Generated Yet" [level=3]
  - paragraph: Trigger a reasoning cycle to correlate existing evidence and contradictions into structured, competing explanations.
  - button "Run Reasoning Cycle"
```

# Test source

```ts
  198 |     // Artificially delay responses for Target A by 400ms to simulate late arrival
  199 |     await page.route(`**/api/signals?target_id=${targetAId}`, async (route) => {
  200 |       await new Promise((r) => setTimeout(r, 400));
  201 |       await route.continue();
  202 |     });
  203 | 
  204 |     const select = page.locator('select').first();
  205 |     await select.selectOption(targetAId);
  206 |     await select.selectOption(targetBId);
  207 | 
  208 |     await page.waitForTimeout(600);
  209 | 
  210 |     const selectedVal = await select.inputValue();
  211 |     expect(selectedVal).toBe(targetBId);
  212 |   });
  213 | 
  214 |   // Section 10 & 11: Real Runtime Context & Mutation Gating UI
  215 |   test('Section 10 & 11: Real Runtime Context Badges & Fail-Closed Mutation Gating', async ({ page }) => {
  216 |     // Scenario A: OFFLINE mode
  217 |     await page.route('**/api/health', (route) => {
  218 |       route.fulfill({
  219 |         status: 503,
  220 |         contentType: 'application/json',
  221 |         body: JSON.stringify({
  222 |           error: 'BACKEND_OFFLINE',
  223 |           runtime_mode: 'OFFLINE',
  224 |           storage_mode: 'UNAVAILABLE',
  225 |           data_origin: 'OFFLINE',
  226 |         }),
  227 |       });
  228 |     });
  229 | 
  230 |     await page.goto(BASE_URL);
  231 |     const modeText = page.locator('[data-testid="runtime-mode-text"]');
  232 |     await expect(modeText).toHaveText('OFFLINE');
  233 | 
  234 |     const offlineBanner = page.locator('#runtime-demo-banner');
  235 |     await expect(offlineBanner).toBeVisible();
  236 |     await expect(offlineBanner).toContainText('BACKEND OFFLINE');
  237 | 
  238 |     // Scenario B: UNKNOWN mode
  239 |     await page.unroute('**/api/health');
  240 |     await page.route('**/api/health', (route) => {
  241 |       route.fulfill({
  242 |         status: 200,
  243 |         contentType: 'application/json',
  244 |         body: JSON.stringify({
  245 |           unexpected_property: 12345,
  246 |           runtime_mode: 'UNKNOWN_CORRUPTED_STRING',
  247 |         }),
  248 |       });
  249 |     });
  250 | 
  251 |     await page.goto(BASE_URL);
  252 |     await expect(modeText).toHaveText('UNKNOWN');
  253 |     const unknownBanner = page.locator('#runtime-demo-banner');
  254 |     await expect(unknownBanner).toBeVisible();
  255 |     await expect(unknownBanner).toContainText('RUNTIME UNKNOWN');
  256 | 
  257 |     // Scenario C: LIVE_BACKEND + POSTGRES displays LIVE badge
  258 |     await page.unroute('**/api/health');
  259 |     await setupLiveHealth(page);
  260 | 
  261 |     await page.goto(BASE_URL);
  262 |     await expect(modeText).toHaveText('LIVE');
  263 |     await expect(page.locator('#runtime-demo-banner')).not.toBeVisible();
  264 |   });
  265 | 
  266 |   // Section 12: Real Error vs Empty UI Distinction
  267 |   test('Section 12: Real UI Distinction between HTTP 500 ERROR and HTTP 200 SUCCESS_EMPTY', async ({ page }) => {
  268 |     await setupLiveHealth(page);
  269 | 
  270 |     // Subtest 1: Force HTTP 500 error on hypotheses endpoint
  271 |     await page.route('**/api/hypotheses**', (route) => {
  272 |       route.fulfill({
  273 |         status: 500,
  274 |         contentType: 'application/json',
  275 |         body: JSON.stringify({ error: 'DATABASE_FAILURE', message: 'Internal Server Error' }),
  276 |       });
  277 |     });
  278 | 
  279 |     await page.goto(BASE_URL);
  280 |     await page.click('[data-testid="nav-reasoning"]');
  281 | 
  282 |     // Expect explicit ERROR / UNAVAILABLE banner
  283 |     await expect(page.locator('text=Failed to Load Hypotheses')).toBeVisible();
  284 | 
  285 |     // Subtest 2: Restore endpoint to return HTTP 200 [] (SUCCESS_EMPTY)
  286 |     await page.unroute('**/api/hypotheses**');
  287 |     await page.route('**/api/hypotheses**', (route) => {
  288 |       route.fulfill({
  289 |         status: 200,
  290 |         contentType: 'application/json',
  291 |         body: JSON.stringify([]),
  292 |       });
  293 |     });
  294 | 
  295 |     // Click the in-view Retry button to re-fetch
  296 |     await page.click('button:has-text("Retry")');
  297 |     await expect(page.locator('text=Failed to Load Hypotheses')).not.toBeVisible();
> 298 |     await expect(page.locator('text=No active security hypotheses')).toBeVisible();
      |                                                                      ^ Error: expect(locator).toBeVisible() failed
  299 |   });
  300 | 
  301 |   // Section 13 & 14: Multi-Root & Single-Root Scope Import UI
  302 |   test('Section 13 & 14: Scope Import: Zero automatic selection and explicit choice required', async ({ page }) => {
  303 |     await setupLiveHealth(page);
  304 | 
  305 |     const reviewId = 'rev-multi-roots-001';
  306 |     await page.route('**/api/scope/imports', (route) => {
  307 |       route.fulfill({
  308 |         status: 200,
  309 |         contentType: 'application/json',
  310 |         body: JSON.stringify([
  311 |           {
  312 |             id: reviewId,
  313 |             file_name: 'multi_scope.json',
  314 |             source_platform: 'HACKERONE',
  315 |             status: 'PENDING_CONFIRMATION',
  316 |             include_hosts_count: 5,
  317 |             exclude_hosts_count: 1,
  318 |             regex_rules_count: 2,
  319 |             canonical_scope_sha256: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
  320 |             root_domains: [
  321 |               { id: 'rd-1', root_domain: 'example.com', normalized_domain: 'example.com', confidence: 'HIGH' },
  322 |               { id: 'rd-2', root_domain: 'example.io', normalized_domain: 'example.io', confidence: 'HIGH' },
  323 |               { id: 'rd-3', root_domain: 'examplecloud.com', normalized_domain: 'examplecloud.com', confidence: 'MEDIUM' },
  324 |             ],
  325 |             imported_at: new Date().toISOString(),
  326 |           },
  327 |         ]),
  328 |       });
  329 |     });
  330 | 
  331 |     await page.goto(BASE_URL);
  332 |     await page.click('[data-testid="nav-scope-verifier"]');
  333 |     await page.click('[data-testid="scope-tab-import"]');
  334 | 
  335 |     // Click on the review card to view its root domains
  336 |     await page.click('button:has-text("multi_scope.json")');
  337 | 
  338 |     // Rule 1: Confirm button must be initially disabled when no root candidate is selected
  339 |     const confirmBtn = page.locator('[data-testid="confirm-scope-btn"]');
  340 |     await expect(confirmBtn).toBeVisible();
  341 |     await expect(confirmBtn).toBeDisabled();
  342 | 
  343 |     const selectedNotice = page.locator('[data-testid="selected-root-candidate-text"]');
  344 |     await expect(selectedNotice).toContainText('No root domain selected');
  345 | 
  346 |     // Rule 2: Click example.io candidate
  347 |     await page.click('[data-testid="root-candidate-example.io"]');
  348 | 
  349 |     // Verify candidate text and confirm button becomes enabled
  350 |     await expect(selectedNotice).toContainText('Selected: example.io');
  351 |     await expect(confirmBtn).toBeEnabled();
  352 | 
  353 |     // Setup confirmation route handler
  354 |     let confirmedRoot = '';
  355 |     await page.route('**/api/scope/imports/*/confirm', async (route) => {
  356 |       const payload = JSON.parse(route.request().postData() || '{}');
  357 |       confirmedRoot = payload.selected_root_domain || payload.selected_root;
  358 |       await route.fulfill({
  359 |         status: 200,
  360 |         contentType: 'application/json',
  361 |         body: JSON.stringify({
  362 |           id: reviewId,
  363 |           status: 'CONFIRMED',
  364 |           selected_root_domain: confirmedRoot,
  365 |           created_target_id: 'tgt-established-01',
  366 |         }),
  367 |       });
  368 |     });
  369 | 
  370 |     // Click confirm
  371 |     await confirmBtn.click();
  372 |     expect(confirmedRoot).toBe('example.io');
  373 |   });
  374 | 
  375 |   // Section 15 & 16: Real Evidence UI, SHA-256 Fingerprint & Integrity Mismatch UI
  376 |   test('Section 15 & 16: Evidence Recording, SHA-256 Fingerprint & Cryptographic Integrity Mismatch UI', async ({ page }) => {
  377 |     await setupLiveHealth(page);
  378 | 
  379 |     const testEvId = 'ev-integrity-test-101';
  380 |     const testSha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  381 | 
  382 |     await page.route('**/api/targets/*/evidence', (route) => {
  383 |       route.fulfill({
  384 |         status: 200,
  385 |         contentType: 'application/json',
  386 |         body: JSON.stringify({
  387 |           evidence: [
  388 |             {
  389 |               id: testEvId,
  390 |               target_id: 'tgt-alpha-001',
  391 |               asset_id: 'ast-01',
  392 |               evidence_type: 'HTTP_RESPONSE',
  393 |               source: 'MANUAL_PROBE',
  394 |               status: 'COLLECTED',
  395 |               sha256: testSha,
  396 |               summary: 'Observed 200 OK with session token',
  397 |               canonical_representation: '{"asset_id":"ast-01","method":"GET","status_code":200}',
  398 |               observed_at: new Date().toISOString(),
```