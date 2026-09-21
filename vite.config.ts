import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import http from 'node:http';
import path from 'path';
import { defineConfig, Plugin } from 'vite';

// In-memory data store for live preview fallback if Go backend is not independently running
const initialTargets = [
  {
    id: 'tgt-alpha-001',
    name: 'Example Security Program',
    root_domain: 'example.com',
    allowed_domains: ['example.com', '*.example.com'],
    allowed_url_patterns: ['/api/*', '/v1/*'],
    excluded_patterns: ['admin.example.com', '*.internal.example.com'],
    status: 'ACTIVE',
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
];

let targetsStore = [...initialTargets];
let jobsStore: any[] = [
  {
    id: 'job-init-101',
    target_id: 'tgt-alpha-001',
    type: 'CERT_TRANSPARENCY_LOGS',
    status: 'COMPLETED',
    created_at: new Date(Date.now() - 3000000).toISOString(),
    started_at: new Date(Date.now() - 2990000).toISOString(),
    completed_at: new Date(Date.now() - 2950000).toISOString(),
    metadata: { depth: 1, crt_sh_queried: true, sans_found: 4 },
  },
];
let eventsStore: any[] = [
  {
    event_id: 'evt-init-01',
    event_type: 'TARGET_CREATED',
    target_id: 'tgt-alpha-001',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    payload: { root_domain: 'example.com' },
  },
  {
    event_id: 'evt-init-02',
    event_type: 'JOB_COMPLETED',
    job_id: 'job-init-101',
    target_id: 'tgt-alpha-001',
    timestamp: new Date(Date.now() - 2950000).toISOString(),
    payload: { status: 'COMPLETED' },
  },
];

let assetsStore: any[] = [
  {
    id: 'ast-01',
    target_id: 'tgt-alpha-001',
    hostname: 'example.com',
    asset_type: 'ROOT_DOMAIN',
    ip_addresses: ['93.184.216.34'],
    status: 'ACTIVE',
    discovered_at: new Date(Date.now() - 7200000).toISOString(),
    updated_at: new Date(Date.now() - 1800000).toISOString(),
    dns_records: [
      { id: 'dns-1', asset_id: 'ast-01', record_type: 'A', value: '93.184.216.34', ttl: 300, status: 'RESOLVED', discovered_at: new Date().toISOString() },
      { id: 'dns-2', asset_id: 'ast-01', record_type: 'AAAA', value: '2606:2800:220:1:248:1893:25c8:1946', ttl: 300, status: 'RESOLVED', discovered_at: new Date().toISOString() },
    ],
  },
  {
    id: 'ast-02',
    target_id: 'tgt-alpha-001',
    hostname: 'api.example.com',
    asset_type: 'SUBDOMAIN',
    ip_addresses: ['93.184.216.35'],
    status: 'ACTIVE',
    discovered_at: new Date(Date.now() - 5400000).toISOString(),
    updated_at: new Date(Date.now() - 1200000).toISOString(),
    dns_records: [
      { id: 'dns-3', asset_id: 'ast-02', record_type: 'A', value: '93.184.216.35', ttl: 300, status: 'RESOLVED', discovered_at: new Date().toISOString() },
      { id: 'dns-4', asset_id: 'ast-02', record_type: 'CNAME', value: 'lb-prod.example.com', ttl: 600, status: 'RESOLVED', discovered_at: new Date().toISOString() },
    ],
  },
  {
    id: 'ast-03',
    target_id: 'tgt-alpha-001',
    hostname: 'auth.example.com',
    asset_type: 'SUBDOMAIN',
    ip_addresses: ['93.184.216.36'],
    status: 'ACTIVE',
    discovered_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 600000).toISOString(),
    dns_records: [
      { id: 'dns-5', asset_id: 'ast-03', record_type: 'A', value: '93.184.216.36', ttl: 300, status: 'RESOLVED', discovered_at: new Date().toISOString() },
    ],
  },
];

let servicesStore: any[] = [
  {
    id: 'svc-01',
    asset_id: 'ast-01',
    target_id: 'tgt-alpha-001',
    service_identity: 'https:443',
    scheme: 'https',
    port: 443,
    status_code: 200,
    page_title: 'Example Security Research Portal',
    web_server: 'cloudflare',
    content_type: 'text/html; charset=UTF-8',
    content_length: 1258,
    response_time_ms: 84,
    tls_version: 'TLS 1.3',
    headers: {
      server: 'cloudflare',
      'cf-ray': '8f12d8a1c9e8300-DFW',
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-content-type-options': 'nosniff',
    },
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'svc-02',
    asset_id: 'ast-02',
    target_id: 'tgt-alpha-001',
    service_identity: 'https:443',
    scheme: 'https',
    port: 443,
    status_code: 200,
    page_title: 'NexusHunter Microservices Gateway',
    web_server: 'nginx/1.24.0',
    content_type: 'application/json',
    content_length: 432,
    response_time_ms: 112,
    tls_version: 'TLS 1.3',
    headers: {
      server: 'nginx/1.24.0',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'x-powered-by': 'Express',
      'x-content-type-options': 'nosniff',
    },
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'svc-03',
    asset_id: 'ast-03',
    target_id: 'tgt-alpha-001',
    service_identity: 'https:443',
    scheme: 'https',
    port: 443,
    status_code: 401,
    page_title: 'OAuth2 Authentication Portal',
    web_server: 'nginx/1.24.0',
    content_type: 'text/html; charset=UTF-8',
    content_length: 890,
    response_time_ms: 65,
    tls_version: 'TLS 1.3',
    headers: {
      server: 'nginx/1.24.0',
      'www-authenticate': 'Bearer realm="NexusAuth"',
      'x-frame-options': 'DENY',
      'strict-transport-security': 'max-age=31536000',
    },
    first_seen: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date().toISOString(),
  },
];

let technologiesStore: any[] = [
  {
    id: 'tech-01',
    asset_id: 'ast-01',
    target_id: 'tgt-alpha-001',
    technology_name: 'Cloudflare',
    category: 'CDN/WAF',
    version: undefined,
    confidence: 98,
    detection_source: 'Header',
    evidence: 'Header Server matches regex "(?i)cloudflare"',
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'tech-02',
    asset_id: 'ast-02',
    target_id: 'tgt-alpha-001',
    technology_name: 'Nginx',
    category: 'Web Server',
    version: '1.24.0',
    confidence: 95,
    detection_source: 'Header',
    evidence: 'Server header "nginx/1.24.0" matches version capture group',
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'tech-03',
    asset_id: 'ast-02',
    target_id: 'tgt-alpha-001',
    technology_name: 'Express',
    category: 'Framework',
    version: '4.x',
    confidence: 92,
    detection_source: 'Header',
    evidence: 'X-Powered-By header indicates Express web application framework',
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'tech-04',
    asset_id: 'ast-01',
    target_id: 'tgt-alpha-001',
    technology_name: 'React',
    category: 'Framework',
    version: '19.0.1',
    confidence: 90,
    detection_source: 'Script',
    evidence: 'Discovered React bundle asset: /static/js/react.production.min.js',
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'tech-05',
    asset_id: 'ast-02',
    target_id: 'tgt-alpha-001',
    technology_name: 'TypeScript',
    category: 'Language',
    version: '5.8',
    confidence: 88,
    detection_source: 'Sourcemap',
    evidence: 'Extracted source-map file references .ts interface definitions',
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'tech-06',
    asset_id: 'ast-03',
    target_id: 'tgt-alpha-001',
    technology_name: 'OpenSSL',
    category: 'Security',
    version: '1.3',
    confidence: 95,
    detection_source: 'TLS Handshake',
    evidence: 'TLS 1.3 negotiated cipher TLS_AES_256_GCM_SHA384',
    first_seen: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date().toISOString(),
  },
];

let securityObsStore: any[] = [
  {
    id: 'sec-01',
    asset_id: 'ast-01',
    target_id: 'tgt-alpha-001',
    service_id: 'svc-01',
    property_name: 'Content-Security-Policy',
    is_present: false,
    details: 'Content-Security-Policy header is missing, exposing web clients to potential XSS injection vulnerabilities',
    raw_value: '',
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'sec-02',
    asset_id: 'ast-01',
    target_id: 'tgt-alpha-001',
    service_id: 'svc-01',
    property_name: 'Strict-Transport-Security',
    is_present: true,
    details: 'HSTS is properly configured with max-age=31536000 and includeSubDomains',
    raw_value: 'max-age=31536000; includeSubDomains; preload',
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'sec-03',
    asset_id: 'ast-02',
    target_id: 'tgt-alpha-001',
    service_id: 'svc-02',
    property_name: 'Server Banner Disclosure',
    is_present: true,
    details: 'Web server actively announces precise software version "nginx/1.24.0", aiding reconnaissance vulnerability mapping',
    raw_value: 'nginx/1.24.0',
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'sec-04',
    asset_id: 'ast-02',
    target_id: 'tgt-alpha-001',
    service_id: 'svc-02',
    property_name: 'Permissive CORS Wildcard',
    is_present: true,
    details: 'Access-Control-Allow-Origin is set to wildcard (*), permitting arbitrary external origins to query endpoints',
    raw_value: '*',
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
  },
  {
    id: 'sec-05',
    asset_id: 'ast-01',
    target_id: 'tgt-alpha-001',
    service_id: 'svc-01',
    property_name: 'X-Frame-Options',
    is_present: false,
    details: 'Missing X-Frame-Options and frame-ancestors directive; target is potentially vulnerable to UI clickjacking',
    raw_value: '',
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
  },
];

let tagsStore: any[] = [
  { id: 'tag-01', asset_id: 'ast-01', target_id: 'tgt-alpha-001', tag: 'cdn:cloudflare', is_inferred: true, created_at: new Date().toISOString(), created_by: 'system:intel' },
  { id: 'tag-02', asset_id: 'ast-01', target_id: 'tgt-alpha-001', tag: 'tier:critical', is_inferred: false, created_at: new Date().toISOString(), created_by: 'user:admin' },
  { id: 'tag-03', asset_id: 'ast-02', target_id: 'tgt-alpha-001', tag: 'server:nginx', is_inferred: true, created_at: new Date().toISOString(), created_by: 'system:intel' },
  { id: 'tag-04', asset_id: 'ast-02', target_id: 'tgt-alpha-001', tag: 'cors:wildcard', is_inferred: true, created_at: new Date().toISOString(), created_by: 'system:intel' },
  { id: 'tag-05', asset_id: 'ast-02', target_id: 'tgt-alpha-001', tag: 'api:public', is_inferred: false, created_at: new Date().toISOString(), created_by: 'user:security' },
  { id: 'tag-06', asset_id: 'ast-03', target_id: 'tgt-alpha-001', tag: 'auth:sso', is_inferred: false, created_at: new Date().toISOString(), created_by: 'user:admin' },
];

let changesStore: any[] = [
  {
    id: 'chg-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-03',
    change_type: 'NEW_SERVICE',
    summary: 'New HTTPS service discovered on port 443 (HTTP 401 Unauthorized)',
    details: { port: 443, scheme: 'https', status_code: 401 },
    detected_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'chg-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    change_type: 'NEW_TECHNOLOGY',
    summary: 'Identified Nginx (v1.24.0) with confidence 95% via Server header',
    details: { tech: 'Nginx', version: '1.24.0', confidence: 95 },
    detected_at: new Date(Date.now() - 5400000).toISOString(),
  },
  {
    id: 'chg-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    change_type: 'CHANGED_SERVICE',
    summary: 'Security parameter upgraded to TLS 1.3 on port 443',
    details: { previous: 'TLS 1.2', current: 'TLS 1.3' },
    detected_at: new Date(Date.now() - 7200000).toISOString(),
  },
];

let pageAssetsStore: any[] = [
  { id: 'pa-01', asset_id: 'ast-01', target_id: 'tgt-alpha-001', url: 'https://example.com/static/js/main.chunk.js', asset_type: 'script', source_page: 'https://example.com', is_in_scope: true, discovered_at: new Date().toISOString() },
  { id: 'pa-02', asset_id: 'ast-01', target_id: 'tgt-alpha-001', url: 'https://example.com/static/css/theme.min.css', asset_type: 'stylesheet', source_page: 'https://example.com', is_in_scope: true, discovered_at: new Date().toISOString() },
  { id: 'pa-03', asset_id: 'ast-01', target_id: 'tgt-alpha-001', url: 'https://example.com/static/js/main.chunk.js.map', asset_type: 'sourcemap', source_page: 'https://example.com', is_in_scope: true, discovered_at: new Date().toISOString() },
  { id: 'pa-04', asset_id: 'ast-02', target_id: 'tgt-alpha-001', url: 'https://api.example.com/v1/auth/token', asset_type: 'api_endpoint', source_page: 'https://api.example.com', is_in_scope: true, discovered_at: new Date().toISOString() },
  { id: 'pa-05', asset_id: 'ast-01', target_id: 'tgt-alpha-001', url: 'https://cdn.thirdparty.com/telemetry.js', asset_type: 'script', source_page: 'https://example.com', is_in_scope: false, discovered_at: new Date().toISOString() },
];

let urlsStore: any[] = [
  { id: 'url-01', target_id: 'tgt-alpha-001', asset_id: 'ast-01', url: 'https://example.com/', method: 'GET', source: 'seed', depth: 0, discovered_at: new Date().toISOString() },
  { id: 'url-02', target_id: 'tgt-alpha-001', asset_id: 'ast-01', url: 'https://example.com/security', method: 'GET', source: 'crawl', depth: 1, discovered_at: new Date().toISOString() },
  { id: 'url-03', target_id: 'tgt-alpha-001', asset_id: 'ast-02', url: 'https://api.example.com/v1/health', method: 'GET', source: 'crawl', depth: 1, discovered_at: new Date().toISOString() },
];

// Phase 4 & 5 Stores: AI Analysis, Graph, Temporal Intelligence, Invariants, Clusters
let signalsStore: any[] = [
  {
    id: 'sig-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    signal_type: 'PERMISSIVE_CORS_WILDCARD',
    severity_hint: 'HIGH',
    evidence: 'Header Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true on api.example.com/v1/auth/token',
    source: 'HTTP_HEADER_ANALYZER',
    url: 'https://api.example.com/v1/auth/token',
    details: { header: 'Access-Control-Allow-Origin', value: '*' },
    detected_at: new Date(Date.now() - 4800000).toISOString(),
  },
  {
    id: 'sig-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    signal_type: 'MISSING_CSP_HEADER',
    severity_hint: 'MEDIUM',
    evidence: 'Response from https://example.com/ lacks Content-Security-Policy header, enabling inline script execution',
    source: 'SECURITY_HEADER_CHECKER',
    url: 'https://example.com/',
    details: { missing: 'Content-Security-Policy' },
    detected_at: new Date(Date.now() - 7200000).toISOString(),
  },
  {
    id: 'sig-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    signal_type: 'PUBLIC_SOURCEMAP_LEAK',
    severity_hint: 'LOW',
    evidence: 'Publicly fetchable webpack sourcemap /static/js/main.chunk.js.map exposes unminified API route declarations',
    source: 'JAVASCRIPT_INSPECTOR',
    url: 'https://example.com/static/js/main.chunk.js.map',
    details: { size_bytes: 482910, contains_routes: true },
    detected_at: new Date(Date.now() - 3600000).toISOString(),
  },
];

let candidatesStore: any[] = [
  {
    id: 'cand-01',
    analysis_run_id: 'run-ai-001',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    category: 'BROKEN_OBJECT_LEVEL_AUTH',
    title: 'Arbitrary Origin Reflection with Credentialed API Token Endpoint',
    description: 'API endpoint on api.example.com reflects untrusted origin requests while serving sensitive bearer tokens.',
    state: 'CANDIDATE',
    confidence_score: 0.88,
    reasoning: 'Observed Access-Control-Allow-Origin wildcard on authenticated routes. Differential probe shows origin echoing without proper domain whitelist verification.',
    missing_evidence: 'Need verification that browser clients automatically attach authenticated session cookies or auth tokens under cross-origin fetch.',
    validation_steps: [
      'Send benign preflight OPTIONS request with Origin: https://evil.example.com',
      'Verify if server responds with Access-Control-Allow-Origin mirroring the probe origin',
      'Check if Access-Control-Allow-Credentials header is set to true',
    ],
    evidence_references: ['sig-01', 'pa-04'],
    recommended_verification: 'Execute non-destructive preflight CORS query with dummy origin to verify reflection state.',
    is_mock: false,
    created_at: new Date(Date.now() - 4200000).toISOString(),
    updated_at: new Date(Date.now() - 1200000).toISOString(),
    evidence: [
      {
        id: 'ev-01',
        candidate_id: 'cand-01',
        evidence_type: 'HTTP_RESPONSE_HEADER',
        reference_id: 'sig-01',
        summary: 'Access-Control-Allow-Origin: * with Auth endpoint',
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        collected_at: new Date(Date.now() - 4800000).toISOString(),
      },
    ],
  },
  {
    id: 'cand-02',
    analysis_run_id: 'run-ai-001',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    category: 'CONTENT_SECURITY_POLICY',
    title: 'Absence of Content-Security-Policy on Public Portal Entrypoint',
    description: 'The root domain application serves user-facing DOM components without a restrictive CSP or script-src nonces.',
    state: 'OBSERVATION',
    confidence_score: 0.95,
    reasoning: 'HTTP probe of root domain verified total absence of Content-Security-Policy and X-XSS-Protection headers.',
    missing_evidence: 'User-input reflection vectors inside DOM elements have not been validated.',
    validation_steps: [
      'Check HTTP response headers for Content-Security-Policy or Content-Security-Policy-Report-Only',
      'Inspect meta tags in HTML DOM for equivalent http-equiv directives',
    ],
    evidence_references: ['sig-02', 'sec-01'],
    recommended_verification: 'Perform static inspection of root HTML headers.',
    is_mock: false,
    created_at: new Date(Date.now() - 7000000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
    evidence: [
      {
        id: 'ev-02',
        candidate_id: 'cand-02',
        evidence_type: 'SECURITY_HEADER_AUDIT',
        reference_id: 'sec-01',
        summary: 'Content-Security-Policy header verified missing in 200 OK response',
        sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        collected_at: new Date(Date.now() - 7200000).toISOString(),
      },
    ],
  },
  {
    id: 'cand-03',
    analysis_run_id: 'run-ai-001',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    category: 'INFORMATION_DISCLOSURE',
    title: 'Source Code & Internal API Route Exposure via Sourcemap Artifacts',
    description: 'Production frontend exposes full client-side TypeScript source trees and administrative endpoint mappings in public sourcemaps.',
    state: 'ANALYSIS_CANDIDATE',
    confidence_score: 0.91,
    reasoning: 'Sourcemap /static/js/main.chunk.js.map contains full source files array revealing internal /admin/v2/debug and /internal/metrics routes.',
    missing_evidence: 'Confirm whether internal routes disclosed in sourcemap are reachable externally or protected by reverse-proxy auth.',
    validation_steps: [
      'Fetch sourcemap header / URI non-destructively',
      'Parse sourcemap sources list for /admin/ or /internal/ references',
      'Safely verify HTTP status code of discovered route',
    ],
    evidence_references: ['sig-03', 'pa-03'],
    recommended_verification: 'Safe HEAD request on internal route to check if auth boundary is enforced.',
    is_mock: false,
    created_at: new Date(Date.now() - 3500000).toISOString(),
    updated_at: new Date(Date.now() - 1800000).toISOString(),
    evidence: [
      {
        id: 'ev-03',
        candidate_id: 'cand-03',
        evidence_type: 'SOURCEMAP_INSPECTION',
        reference_id: 'sig-03',
        summary: 'Parsed sourcemap revealed 14 unpublished route identifiers',
        sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
        collected_at: new Date(Date.now() - 3600000).toISOString(),
      },
    ],
  },
];

let graphNodesStore: any[] = [
  { id: 'node-tgt-01', target_id: 'tgt-alpha-001', type: 'TARGET', label: 'Example Corp Bug Bounty', properties: { scope: '*.example.com' }, first_seen: new Date(Date.now() - 86400000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-ast-01', target_id: 'tgt-alpha-001', asset_id: 'ast-01', type: 'DOMAIN', label: 'example.com', properties: { ip: '93.184.216.34', tier: 'PRODUCTION' }, first_seen: new Date(Date.now() - 7200000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-ast-02', target_id: 'tgt-alpha-001', asset_id: 'ast-02', type: 'SUBDOMAIN', label: 'api.example.com', properties: { ip: '93.184.216.35', cname: 'lb-prod.example.com' }, first_seen: new Date(Date.now() - 5400000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-ast-03', target_id: 'tgt-alpha-001', asset_id: 'ast-03', type: 'SUBDOMAIN', label: 'auth.example.com', properties: { ip: '93.184.216.36', tier: 'IDENTITY' }, first_seen: new Date(Date.now() - 3600000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-ip-01', target_id: 'tgt-alpha-001', type: 'IP', label: '93.184.216.34', properties: { asn: 'AS15133', org: 'Edgecast Networks' }, first_seen: new Date(Date.now() - 7200000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-svc-01', target_id: 'tgt-alpha-001', type: 'HTTP_SERVICE', label: 'https://example.com (443)', properties: { web_server: 'cloudflare', tls: 'TLS 1.3' }, first_seen: new Date(Date.now() - 7200000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-svc-02', target_id: 'tgt-alpha-001', type: 'HTTP_SERVICE', label: 'https://api.example.com (443)', properties: { web_server: 'nginx/1.24.0', framework: 'Express' }, first_seen: new Date(Date.now() - 5400000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-tech-01', target_id: 'tgt-alpha-001', type: 'TECHNOLOGY', label: 'Cloudflare CDN', properties: { category: 'CDN', confidence: 98 }, first_seen: new Date(Date.now() - 7200000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-tech-02', target_id: 'tgt-alpha-001', type: 'TECHNOLOGY', label: 'Express (v4.x)', properties: { category: 'Framework', confidence: 92 }, first_seen: new Date(Date.now() - 5400000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-boundary-01', target_id: 'tgt-alpha-001', type: 'AUTH_BOUNDARY', label: 'OAuth 2.0 / JWT Gateway', properties: { issuer: 'https://auth.example.com', token_url: '/v1/auth/token' }, first_seen: new Date(Date.now() - 3600000).toISOString(), last_seen: new Date().toISOString() },
  { id: 'node-cand-01', target_id: 'tgt-alpha-001', type: 'CANDIDATE', label: 'CORS Wildcard Candidate', properties: { score: 0.88, category: 'BOLA' }, first_seen: new Date(Date.now() - 4200000).toISOString(), last_seen: new Date().toISOString() },
];

let graphEdgesStore: any[] = [
  { id: 'edge-01', target_id: 'tgt-alpha-001', source_node_id: 'node-tgt-01', target_node_id: 'node-ast-01', relationship: 'BELONGS_TO', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-02', target_id: 'tgt-alpha-001', source_node_id: 'node-tgt-01', target_node_id: 'node-ast-02', relationship: 'BELONGS_TO', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-03', target_id: 'tgt-alpha-001', source_node_id: 'node-tgt-01', target_node_id: 'node-ast-03', relationship: 'BELONGS_TO', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-04', target_id: 'tgt-alpha-001', source_node_id: 'node-ast-01', target_node_id: 'node-ip-01', relationship: 'RESOLVES_TO', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-05', target_id: 'tgt-alpha-001', source_node_id: 'node-ast-01', target_node_id: 'node-svc-01', relationship: 'SERVES', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-06', target_id: 'tgt-alpha-001', source_node_id: 'node-ast-02', target_node_id: 'node-svc-02', relationship: 'SERVES', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-07', target_id: 'tgt-alpha-001', source_node_id: 'node-svc-01', target_node_id: 'node-tech-01', relationship: 'USES', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-08', target_id: 'tgt-alpha-001', source_node_id: 'node-svc-02', target_node_id: 'node-tech-02', relationship: 'USES', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-09', target_id: 'tgt-alpha-001', source_node_id: 'node-ast-03', target_node_id: 'node-boundary-01', relationship: 'HOSTS', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
  { id: 'edge-10', target_id: 'tgt-alpha-001', source_node_id: 'node-svc-02', target_node_id: 'node-cand-01', relationship: 'TRIGGERS', weight: 1.0, properties: {}, created_at: new Date().toISOString() },
];

let temporalChangesStore: any[] = [
  {
    id: 'tchg-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-03',
    change_type: 'NEW_ASSET',
    summary: 'Discovered new authentication subdomain auth.example.com resolving to 93.184.216.36',
    previous_value: 'Unresolved',
    current_value: 'auth.example.com [93.184.216.36]',
    source: 'DNS_ENUMERATION',
    confidence: 0.99,
    first_seen: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date().toISOString(),
    detected_at: new Date(Date.now() - 3600000).toISOString(),
    details: { asset_id: 'ast-03', record: 'A' },
  },
  {
    id: 'tchg-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    change_type: 'HTTP_BEHAVIOR_CHANGED',
    summary: 'Header Access-Control-Allow-Origin modified from restricted domain to wildcard (*)',
    previous_value: 'https://example.com',
    current_value: '*',
    source: 'HTTP_PROBE_DIFFERENTIAL',
    confidence: 0.95,
    first_seen: new Date(Date.now() - 5400000).toISOString(),
    last_seen: new Date().toISOString(),
    detected_at: new Date(Date.now() - 4800000).toISOString(),
    details: { endpoint: '/v1/auth/token' },
  },
  {
    id: 'tchg-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    change_type: 'SECURITY_HEADER_CHANGED',
    summary: 'Content-Security-Policy header absent in current scan cycle (was report-only)',
    previous_value: 'Content-Security-Policy-Report-Only: default-src https:',
    current_value: '[Header Dropped / Absent]',
    source: 'SECURITY_HEADER_CHECKER',
    confidence: 0.92,
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date().toISOString(),
    detected_at: new Date(Date.now() - 6000000).toISOString(),
    details: { header: 'Content-Security-Policy' },
  },
  {
    id: 'tchg-04',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    change_type: 'NEW_ENDPOINT',
    summary: 'Discovered new endpoint /static/js/main.chunk.js.map via script tag inspection',
    previous_value: 'None',
    current_value: 'https://example.com/static/js/main.chunk.js.map',
    source: 'CRAWLER_HTML_PARSER',
    confidence: 0.98,
    first_seen: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date().toISOString(),
    detected_at: new Date(Date.now() - 3600000).toISOString(),
    details: { asset_type: 'sourcemap' },
  },
];

let invariantSignalsStore: any[] = [
  {
    id: 'inv-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    state_from: 'UNAUTHENTICATED',
    state_to: 'AUTHENTICATED',
    observed_condition: 'Cross-origin request with arbitrary Origin reflected Access-Control-Allow-Origin header without prior session token challenge',
    invariant_violation: 'Authentication state transition permitted without origin boundary validation',
    confidence: 0.88,
    evidence: 'OPTIONS /v1/auth/token with Origin: https://untrusted-domain.com returned 200 OK and ACAO: *',
    detected_at: new Date(Date.now() - 4800000).toISOString(),
  },
  {
    id: 'inv-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    endpoint: '/api/v1/health',
    state_from: 'INTERNAL_ONLY',
    state_to: 'PUBLICLY_REACHABLE',
    observed_condition: 'Healthcheck diagnostic route is accessible over public internet without mutual TLS or IP restriction',
    invariant_violation: 'Internal health monitoring invariant violated: route responds with system environment and uptime',
    confidence: 0.94,
    evidence: 'GET https://api.example.com/v1/health returned 200 OK with runtime telemetry',
    detected_at: new Date(Date.now() - 5400000).toISOString(),
  },
];

let behaviorDiffsStore: any[] = [
  {
    id: 'diff-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    probe_a_url: 'https://api.example.com/v1/auth/token [Origin: https://example.com]',
    probe_b_url: 'https://api.example.com/v1/auth/token [Origin: https://attacker.io]',
    context_a: 'Authorized Portal Origin',
    context_b: 'External Arbitrary Origin',
    status_diff: false,
    length_diff: 14,
    header_diff: ['Access-Control-Allow-Origin: *'],
    body_diff_fingerprint: '3a88f7b2c',
    state_change_observed: true,
    timing_delta_ms: 18,
    is_meaningful: true,
    normalized_details: {
      finding: 'Server fails to enforce origin distinction; returns identical permissive headers to both origins.',
    },
    detected_at: new Date(Date.now() - 4500000).toISOString(),
  },
  {
    id: 'diff-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    probe_a_url: 'https://example.com/ [User-Agent: Chrome/120]',
    probe_b_url: 'https://example.com/ [User-Agent: SecurityScanner/1.0]',
    context_a: 'Standard Browser UA',
    context_b: 'Security Scanner UA',
    status_diff: false,
    length_diff: 0,
    header_diff: [],
    body_diff_fingerprint: '1b2c3d4e',
    state_change_observed: false,
    timing_delta_ms: 5,
    is_meaningful: false,
    normalized_details: {
      finding: 'No differential rate limiting or blocking observed between standard and scanner User-Agents.',
    },
    detected_at: new Date(Date.now() - 6000000).toISOString(),
  },
];

let investigationClustersStore: any[] = [
  {
    id: 'cl-01',
    target_id: 'tgt-alpha-001',
    title: 'Cross-Origin Authentication Boundary Bypass Surface',
    category: 'AUTH_BOUNDARY',
    priority_score: 88,
    priority_explanation: 'Permissive CORS configuration on active auth gateway combines with recent temporal change and state invariant violation.',
    priority_factors: [
      { name: 'External Exposure', score: 95, weight: 0.3, explanation: 'Endpoint is publicly exposed and mapped to primary API hostname' },
      { name: 'Temporal Novelty', score: 85, weight: 0.25, explanation: 'CORS policy change detected within last 4 hours' },
      { name: 'Invariant Violation', score: 90, weight: 0.25, explanation: 'State transition permits unauthenticated preflight origin reflection' },
      { name: 'Differential Anomaly', score: 80, weight: 0.2, explanation: 'Origin probe confirmed wildcard behavior across differing contexts' },
    ],
    related_assets: ['ast-02', 'ast-03'],
    related_endpoints: ['/v1/auth/token'],
    confidence: 0.88,
    reason: 'Correlated 3 distinct evidence items: HTTP header probe, temporal diff record, and differential probe response.',
    recommended_validation: [
      'Send non-destructive curl preflight with -H "Origin: https://probe-test.example.com"',
      'Inspect if response reflects probe origin with Access-Control-Allow-Credentials: true',
      'Verify if any session tokens are exposed in preflight exchange',
    ],
    status: 'ACTIVE',
    created_at: new Date(Date.now() - 4000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'cl-02',
    target_id: 'tgt-alpha-001',
    title: 'Client-Side Source Tree & Endpoint Map Disclosure',
    category: 'INFORMATION_DISCLOSURE',
    priority_score: 72,
    priority_explanation: 'Publicly reachable sourcemap directly indexes internal administrative routes on root production web portal.',
    priority_factors: [
      { name: 'External Exposure', score: 90, weight: 0.3, explanation: 'Sourcemap asset is hosted without access restrictions' },
      { name: 'Surface Mapping', score: 80, weight: 0.25, explanation: 'Contains 14 internal route definitions and component files' },
      { name: 'Temporal Novelty', score: 60, weight: 0.25, explanation: 'Discovered in most recent crawling cycle' },
      { name: 'Exploitability Barrier', score: 50, weight: 0.2, explanation: 'Reveals route addresses but requires secondary verification for auth protection' },
    ],
    related_assets: ['ast-01'],
    related_endpoints: ['/static/js/main.chunk.js.map'],
    confidence: 0.91,
    reason: 'Sourcemap file parsed and validated against public URL list; confirms disclosure of internal module paths.',
    recommended_validation: [
      'Perform HTTP HEAD requests to discovered internal paths to verify if 401/403 is returned',
      'Ensure no production API keys or credentials are hardcoded within sourcemap source text',
    ],
    status: 'INVESTIGATING',
    created_at: new Date(Date.now() - 3200000).toISOString(),
    updated_at: new Date().toISOString(),
  },
];

let evidenceRecordsStore: any[] = [
  {
    id: 'ev-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    source: 'RECON_HTTP',
    evidence_type: 'HTTP_RESPONSE',
    summary: 'GET /v1/auth/token response with permissive CORS and unauthenticated token reflection',
    captured_at: new Date(Date.now() - 5400000).toISOString(),
    status_code: 200,
    request: {
      method: 'GET',
      url: 'https://api.example.com/v1/auth/token',
      headers: {
        'User-Agent': 'NexusHunter-Engine/6.0',
        'Origin': 'https://attacker-domain.org',
        'Authorization': '[REDACTED_SECRET]',
        'Cookie': '[REDACTED_SESSION_COOKIE]',
      },
      body_summary: '',
      body_length: 0,
      is_authenticated: false,
      auth_context_role: 'ANONYMOUS',
    },
    response: {
      status_code: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': 'https://attacker-domain.org',
        'Access-Control-Allow-Credentials': 'true',
        'Server': 'nginx/1.24.0',
        'Set-Cookie': '[REDACTED_COOKIE_VALUE]',
      },
      body_snippet: '{"status":"issued","token_type":"Bearer","claims":{"sub":"guest-anon"}}',
      body_length: 71,
      body_hash: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
      content_type: 'application/json',
      response_time_ms: 124,
    },
    relevant_headers: {
      'Access-Control-Allow-Origin': 'https://attacker-domain.org',
      'Access-Control-Allow-Credentials': 'true',
    },
    scope_decision: {
      is_in_scope: true,
      target_id: 'tgt-alpha-001',
      evaluated_host: 'api.example.com',
      evaluated_url: 'https://api.example.com/v1/auth/token',
      rule_matched: '*.example.com',
      reason: 'Host matches target wildcard allowlist',
      evaluated_at: new Date(Date.now() - 5400000).toISOString(),
    },
    redaction_status: {
      is_redacted: true,
      redacted_fields: ['Authorization', 'Cookie', 'Set-Cookie'],
      sanitized_at: new Date(Date.now() - 5400000).toISOString(),
    },
    canonical_representation: '{"asset_id":"ast-02","evidence_type":"HTTP_RESPONSE","request":{"headers":{"Origin":"https://attacker-domain.org"},"method":"GET","url":"https://api.example.com/v1/auth/token"},"response":{"headers":{"Access-Control-Allow-Credentials":"true","Access-Control-Allow-Origin":"https://attacker-domain.org"},"status_code":200},"source":"RECON_HTTP","target_id":"tgt-alpha-001"}',
    sha256: '9f2a4bc8813a3e62ddc6a7139265f01908bf41a457199c9c3e21ea1bbf7f59d4',
    provenance: {
      source: 'RECON_HTTP',
      operation_id: 'op-probe-902',
      target_id: 'tgt-alpha-001',
      asset_id: 'ast-02',
      captured_at: new Date(Date.now() - 5400000).toISOString(),
      initiator: 'engine:recon-probe',
      notes: 'Captured during automated endpoint profiling run',
    },
  },
  {
    id: 'ev-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    source: 'RECON_HTTP',
    evidence_type: 'HTTP_RESPONSE',
    summary: 'GET /login baseline response with standard security headers and 401 requirement',
    captured_at: new Date(Date.now() - 7200000).toISOString(),
    status_code: 401,
    request: {
      method: 'GET',
      url: 'https://example.com/login',
      headers: {
        'User-Agent': 'NexusHunter-Engine/6.0',
        'Origin': 'https://example.com',
      },
      body_length: 0,
      is_authenticated: false,
    },
    response: {
      status_code: 401,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
      },
      body_snippet: '<!DOCTYPE html><html><head><title>Authentication Required</title></head></html>',
      body_length: 210,
      body_hash: '1e345bfa8811cf69ca9001b2c451928374a5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
      content_type: 'text/html',
      response_time_ms: 68,
    },
    scope_decision: {
      is_in_scope: true,
      target_id: 'tgt-alpha-001',
      evaluated_host: 'example.com',
      rule_matched: 'example.com',
      reason: 'Host matches primary target domain',
      evaluated_at: new Date(Date.now() - 7200000).toISOString(),
    },
    redaction_status: {
      is_redacted: false,
      redacted_fields: [],
      sanitized_at: new Date(Date.now() - 7200000).toISOString(),
    },
    sha256: '4a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef',
    provenance: {
      source: 'RECON_HTTP',
      operation_id: 'op-probe-901',
      target_id: 'tgt-alpha-001',
      asset_id: 'ast-01',
      captured_at: new Date(Date.now() - 7200000).toISOString(),
      initiator: 'engine:baseline-profiler',
    },
  },
  {
    id: 'ev-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-03',
    source: 'RECON_HTTP',
    evidence_type: 'TLS_OBSERVATION',
    summary: 'TLS 1.3 negotiated parameters on auth.example.com:443 with valid certificate',
    captured_at: new Date(Date.now() - 3600000).toISOString(),
    status_code: 200,
    tls_metadata: {
      version: 'TLS 1.3',
      cipher_suite: 'TLS_AES_256_GCM_SHA384',
      issuer: 'Let\'s Encrypt Authority X3',
      subject: 'CN=auth.example.com',
      sans: ['auth.example.com', 'id.example.com'],
      valid_until: '2026-12-31T23:59:59Z',
      mutual_tls_required: false,
    },
    scope_decision: {
      is_in_scope: true,
      target_id: 'tgt-alpha-001',
      evaluated_host: 'auth.example.com',
      rule_matched: '*.example.com',
      reason: 'Host matches target subdomain wildcard',
      evaluated_at: new Date(Date.now() - 3600000).toISOString(),
    },
    redaction_status: {
      is_redacted: false,
      redacted_fields: [],
      sanitized_at: new Date(Date.now() - 3600000).toISOString(),
    },
    sha256: '8b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c',
    provenance: {
      source: 'RECON_HTTP',
      operation_id: 'op-tls-probe-104',
      target_id: 'tgt-alpha-001',
      asset_id: 'ast-03',
      captured_at: new Date(Date.now() - 3600000).toISOString(),
      initiator: 'engine:tls-analyzer',
    },
  },
];

let evidenceDiffsStore: any[] = [
  {
    id: 'ediff-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    evidence_a_id: 'ev-02',
    evidence_b_id: 'ev-01',
    raw_diff: {
      status_from: 401,
      status_to: 200,
      status_changed: true,
      body_length_delta: -139,
      body_hash_a: '1e345bfa8811cf69ca9001b2c451928374a5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
      body_hash_b: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
      body_hash_changed: true,
      added_headers: {
        'Access-Control-Allow-Origin': 'https://attacker-domain.org',
        'Access-Control-Allow-Credentials': 'true',
      },
      removed_headers: {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      },
      modified_headers: {
        'Content-Type': 'text/html -> application/json; charset=utf-8',
      },
      response_time_delta_ms: 56,
    },
    semantic_diff: {
      category: 'AUTH_BEHAVIOR_SHIFT',
      meaning: 'Baseline /login strictly requires credentials (401), whereas /v1/auth/token allows unauthenticated access (200) with origin reflection.',
      auth_behavior_changed: true,
      content_type_changed: true,
      redirect_changed: false,
      error_payload_detected: false,
      state_transition_detected: true,
    },
    security_diff: {
      observation_context: 'Differential comparison across authentication boundary endpoints on target.',
      relevance_explanation: 'Permissive cross-origin response on token issuance route violates zero-trust cross-origin isolation policy.',
      requires_followup: true,
      suggested_questions: [
        'Does /v1/auth/token issue authenticated session claims without prior credential challenge?',
        'Can external origins read the returned claims payload via standard Fetch/XHR with credentials?',
      ],
    },
    is_noise_filtered: true,
    is_security_relevant: true,
    computed_at: new Date(Date.now() - 3600000).toISOString(),
  },
];

let securityExpectationsStore: any[] = [
  {
    id: 'exp-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    control_name: 'Authentication Required for Token Issuance',
    source: 'EXPLICIT_POLICY',
    expected_state: 'PRESENT',
    description: 'Endpoints issuing bearer claims must enforce strict caller authentication (HTTP 401 when anonymous).',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: 'exp-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    control_name: 'Strict Origin Whitelist for CORS',
    source: 'EXPLICIT_POLICY',
    expected_state: 'PRESENT',
    description: 'Origin reflection must be constrained strictly to *.example.com domains.',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: 'exp-03',
    target_id: 'tgt-alpha-001',
    control_name: 'Strict-Transport-Security Baseline',
    source: 'PEER_BASELINE',
    expected_state: 'PRESENT',
    description: 'All public HTTPS production assets must serve HSTS headers to eliminate plaintext downgrade attacks.',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
];

let securityContradictionsStore: any[] = [
  {
    id: 'con-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    contradiction_type: 'AUTHENTICATION_CONTRADICTION',
    status: 'CONFIRMED_DEVIATION',
    severity: 'HIGH',
    title: 'Authentication Missing on Token Issuance Endpoint',
    description: 'Policy expects authentication enforcement (PRESENT), but observation confirmed unauthenticated 200 OK (ABSENT).',
    expectation_id: 'exp-01',
    observed_state: 'ABSENT',
    evidence_refs: ['ev-01'],
    explanation: 'Deterministic observation confirms /v1/auth/token returned HTTP 200 and guest token without credentials. This contradicts explicit security specification.',
    suggested_followup: [
      'Verify whether returned guest token possesses permission escalation capabilities',
      'Test token validation against downstream services /api/v1/user/*',
    ],
    created_at: new Date(Date.now() - 4800000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'con-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    contradiction_type: 'TRUST_BOUNDARY_CONTRADICTION',
    status: 'CONFIRMED_DEVIATION',
    severity: 'HIGH',
    title: 'Arbitrary External Origin Reflection with Credentials',
    description: 'Policy mandates strict origin whitelist (PRESENT), but server reflected untrusted external origin with Allow-Credentials: true (ABSENT).',
    expectation_id: 'exp-02',
    observed_state: 'ABSENT',
    evidence_refs: ['ev-01'],
    explanation: 'Origin header supplied as attacker-domain.org was directly mirrored in Access-Control-Allow-Origin response header with credentials enabled.',
    suggested_followup: [
      'Confirm browser cross-origin credential transmission in isolated sandboxed runner',
      'Evaluate impact on authenticated user session hijacking',
    ],
    created_at: new Date(Date.now() - 4500000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'con-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    contradiction_type: 'SECURITY_CONTROL_CONTRADICTION',
    status: 'INVESTIGATING',
    severity: 'MEDIUM',
    title: 'HSTS Header Missing Relative to Peer Baseline',
    description: 'Peer baseline expects HSTS across all target assets (PRESENT), but /v1/auth/token omitted Strict-Transport-Security header (ABSENT).',
    expectation_id: 'exp-03',
    observed_state: 'ABSENT',
    evidence_refs: ['ev-01'],
    explanation: 'Root domain example.com emits HSTS max-age=31536000, whereas api.example.com omitted the header during HTTP response inspection.',
    suggested_followup: [
      'Check if HSTS is applied at ingress CDN level or upstream reverse proxy',
    ],
    created_at: new Date(Date.now() - 4200000).toISOString(),
    updated_at: new Date().toISOString(),
  },
];

let securityOutliersStore: any[] = [
  {
    id: 'out-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    comparison_group: 'All HTTP Services on *.example.com (3 assets)',
    observed_value: 'Access-Control-Allow-Origin: [reflected arbitrary origin] with credentials',
    baseline_value: 'No CORS headers or strict internal origin matching',
    deviation_type: 'CrossOriginPolicyDeviation',
    evidence_refs: ['ev-01'],
    confidence: 0.96,
    details: {
      peer_services_checked: 3,
      outlier_ratio: '1/3 hosts deviate',
    },
    created_at: new Date(Date.now() - 4000000).toISOString(),
  },
  {
    id: 'out-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    comparison_group: 'Web Server Fingerprints in Target Scope',
    observed_value: 'nginx/1.24.0 + Express 4.x runtime',
    baseline_value: 'Cloudflare CDN edge cache (example.com, auth.example.com)',
    deviation_type: 'BypassEdgeArchitecture',
    evidence_refs: ['ev-01'],
    confidence: 0.91,
    details: {
      notes: 'Asset directly exposes origin daemon rather than terminating at Cloudflare edge',
    },
    created_at: new Date(Date.now() - 4000000).toISOString(),
  },
];

let evidenceTimelineStore: any[] = [
  {
    id: 'tl-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    event_type: 'BASELINE_PROBE',
    summary: 'Captured HTTP baseline response for root web portal',
    epistemic_status: 'OBSERVED',
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    provenance: {
      source: 'RECON_HTTP',
      operation_id: 'op-probe-901',
      target_id: 'tgt-alpha-001',
      captured_at: new Date(Date.now() - 7200000).toISOString(),
      initiator: 'engine:baseline-profiler',
    },
    reference_id: 'ev-02',
  },
  {
    id: 'tl-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    event_type: 'EVIDENCE_RECORDED',
    summary: 'Recorded HTTP response with origin reflection on /v1/auth/token',
    epistemic_status: 'OBSERVED',
    timestamp: new Date(Date.now() - 5400000).toISOString(),
    provenance: {
      source: 'RECON_HTTP',
      operation_id: 'op-probe-902',
      target_id: 'tgt-alpha-001',
      captured_at: new Date(Date.now() - 5400000).toISOString(),
      initiator: 'engine:recon-probe',
    },
    reference_id: 'ev-01',
  },
  {
    id: 'tl-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    event_type: 'DIFFERENTIAL_ANALYSIS',
    summary: 'Computed 3-level comparative diff against baseline; detected auth behavior shift',
    epistemic_status: 'DERIVED',
    timestamp: new Date(Date.now() - 5000000).toISOString(),
    provenance: {
      source: 'DIFFERENTIAL_ENGINE',
      operation_id: 'op-diff-501',
      target_id: 'tgt-alpha-001',
      captured_at: new Date(Date.now() - 5000000).toISOString(),
      initiator: 'engine:differential-analyzer',
    },
    reference_id: 'ediff-01',
  },
  {
    id: 'tl-04',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    event_type: 'CONTRADICTION_DETECTED',
    summary: 'Contradiction confirmed: Policy mandates authentication, but observation recorded ABSENT',
    epistemic_status: 'CONFIRMED_DEVIATION',
    timestamp: new Date(Date.now() - 4800000).toISOString(),
    provenance: {
      source: 'SECURITY_OBSERVATION',
      operation_id: 'op-contradiction-eval',
      target_id: 'tgt-alpha-001',
      captured_at: new Date(Date.now() - 4800000).toISOString(),
      initiator: 'engine:contradiction-detector',
    },
    reference_id: 'con-01',
  },
  {
    id: 'tl-05',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    event_type: 'OUTLIER_IDENTIFIED',
    summary: 'Identified cross-origin header outlier compared to peer service baseline',
    epistemic_status: 'DERIVED',
    timestamp: new Date(Date.now() - 4000000).toISOString(),
    provenance: {
      source: 'DIFFERENTIAL_ENGINE',
      operation_id: 'op-outlier-det',
      target_id: 'tgt-alpha-001',
      captured_at: new Date(Date.now() - 4000000).toISOString(),
      initiator: 'engine:outlier-detector',
    },
    reference_id: 'out-01',
  },
];

// ==========================================
// Phase 7: Deterministic Reasoning & Investigation Stores
// ==========================================

const evidenceStore = evidenceRecordsStore;

function validateSignalTransition(current: string, next: string): boolean {
  if (current === next) return true;
  switch (current) {
    case 'OPEN':
      return next === 'CORRELATED' || next === 'DISMISSED';
    case 'CORRELATED':
      return next === 'SUPERSEDED' || next === 'DISMISSED';
    case 'SUPERSEDED':
      return false; // Terminal state
    case 'DISMISSED':
      return next === 'OPEN'; // Reopen
    default:
      return false;
  }
}

function validateHypothesisTransition(current: string, next: string): boolean {
  if (current === next) return true;
  switch (current) {
    case 'HYPOTHESIZED':
      return next === 'INVESTIGATING' || next === 'DISMISSED';
    case 'INVESTIGATING':
      return next === 'SUPPORTED' || next === 'FALSIFIED' || next === 'UNKNOWN' || next === 'DISMISSED';
    case 'SUPPORTED':
      return next === 'FALSIFIED' || next === 'INVESTIGATING';
    case 'FALSIFIED':
      return false; // Terminal state
    case 'UNKNOWN':
      return next === 'INVESTIGATING' || next === 'DISMISSED';
    case 'DISMISSED':
      return next === 'HYPOTHESIZED'; // Reopen
    default:
      return false;
  }
}

function validateInvestigationTransition(current: string, next: string): boolean {
  if (current === next) return true;
  switch (current) {
    case 'PLANNED':
      return next === 'QUEUED' || next === 'RUNNING' || next === 'CANCELLED';
    case 'QUEUED':
      return next === 'RUNNING' || next === 'CANCELLED';
    case 'RUNNING':
      return next === 'COMPLETED' || next === 'FAILED' || next === 'CANCELLED';
    case 'COMPLETED':
    case 'FAILED':
    case 'CANCELLED':
      return false; // Terminal states
    default:
      return false;
  }
}

const reasoningSignalsStore: any[] = [
  {
    id: 'sig-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/v1/auth/token',
    signal_type: 'AUTH_INCONSISTENCY',
    category: 'AUTHENTICATION',
    title: 'Unauthenticated Token Reflection on Sensitive Route',
    description: 'Endpoint returns active token structure when queried without Authorization header, contradicting documented OAuth 2.0 bearer specification.',
    epistemic_status: 'OBSERVED',
    status: 'OPEN',
    severity_of_attention: 'HIGH',
    source_observations: ['obs-sec-01', 'con-01'],
    source_evidence: ['ev-01'],
    detector: 'ContradictionBridgeDetector',
    detector_version: '7.0.0',
    metadata: { route: '/v1/auth/token', observed_status: 200 },
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'sig-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    endpoint: '/api/v1/users',
    signal_type: 'HTTP_SECURITY_CONTROL_DIFF',
    category: 'SECURITY_CONTROL',
    title: 'Differential Permissive CORS Header on API Gateway',
    description: 'Access-Control-Allow-Origin: * emitted on internal user endpoint while baseline gateway blocks untrusted origins.',
    epistemic_status: 'OBSERVED',
    status: 'CORRELATED',
    severity_of_attention: 'MEDIUM',
    source_observations: ['obs-diff-01', 'out-01'],
    source_evidence: ['ediff-01'],
    detector: 'DifferentialAnalysisDetector',
    detector_version: '7.0.0',
    metadata: { header: 'Access-Control-Allow-Origin', value: '*' },
    created_at: new Date(Date.now() - 3400000).toISOString(),
    updated_at: new Date(Date.now() - 3400000).toISOString(),
  },
  {
    id: 'sig-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    endpoint: '/admin/metrics',
    signal_type: 'UNEXPECTED_ENDPOINT_BEHAVIOR',
    category: 'AUTHORIZATION',
    title: 'Direct Origin Exposure Bypassing WAF Boundary',
    description: 'Direct IP requests reach origin daemon on port 8080 without Cloudflare Ray ID header validation.',
    epistemic_status: 'OBSERVED',
    status: 'OPEN',
    severity_of_attention: 'HIGH',
    source_observations: ['obs-out-02'],
    source_evidence: ['ev-03'],
    detector: 'BoundaryExposureDetector',
    detector_version: '7.0.0',
    metadata: { port: 8080, bypass: true },
    created_at: new Date(Date.now() - 3000000).toISOString(),
    updated_at: new Date(Date.now() - 3000000).toISOString(),
  },
];

const hypothesisGroupsStore: any[] = [
  {
    id: 'hg-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    subject: 'Authentication Boundary & Token Handling on /v1/auth/token',
    competing_theories_count: 2,
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'hg-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    subject: 'Direct Origin Ingress Bypassing Cloudflare Edge Controls',
    competing_theories_count: 1,
    created_at: new Date(Date.now() - 3000000).toISOString(),
    updated_at: new Date(Date.now() - 3000000).toISOString(),
  },
];

const hypothesesStore: any[] = [
  {
    id: 'hyp-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    group_id: 'hg-01',
    category: 'AUTH_POLICY_DIFF',
    title: 'Unauthenticated Token Issuance via Inadvertent Test Mock or Debug Bypass',
    description: 'The endpoint /v1/auth/token emits active credentials without authorization headers, indicating either a debug route inadvertently deployed to production or an auth gateway routing flaw.',
    epistemic_status: 'HYPOTHESIZED',
    status: 'HYPOTHESIZED',
    reasoning_method: 'ABDUCTIVE',
    evidence_strength: 4,
    investigation_priority: 92,
    supporting_evidence: ['ev-01'],
    contradicting_evidence: [],
    missing_evidence: ['Response behavior with invalid Bearer token', 'JWT signature validation check'],
    falsification_conditions: [
      {
        condition_description: 'Validating cryptographic signature of emitted token fails against public JWKS key',
        required_evidence: 'Token JWKS signature verification result',
        validation_method: 'NON_DESTRUCTIVE_SIGNATURE_CHECK',
        result: 'PENDING',
      },
      {
        condition_description: 'Emitted token is rejected by protected API downstream service with 401',
        required_evidence: 'Downstream /api/v1/user probe with emitted token',
        validation_method: 'SAFE_REPLAY_TEST',
        result: 'PENDING',
      },
    ],
    metadata: { confidence_level: 0.85 },
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'hyp-02',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    group_id: 'hg-01',
    category: 'INTENTIONAL_PUBLIC',
    title: 'Public Anonymous Guest Session Token Issuance',
    description: 'The /v1/auth/token endpoint intentionally issues limited-privilege guest sessions anonymously as part of onboarding flow.',
    epistemic_status: 'HYPOTHESIZED',
    status: 'HYPOTHESIZED',
    reasoning_method: 'COMPETING_THEORY',
    evidence_strength: 2,
    investigation_priority: 45,
    supporting_evidence: ['ev-01'],
    contradicting_evidence: [],
    missing_evidence: ['Scope claims inside decoded JWT payload'],
    falsification_conditions: [
      {
        condition_description: 'Token payload claims reveal "admin" or elevated roles rather than "guest" or "anonymous"',
        required_evidence: 'Decoded JWT claims inspecting roles/scopes',
        validation_method: 'PAYLOAD_ANALYSIS',
        result: 'PENDING',
      },
    ],
    metadata: { confidence_level: 0.35 },
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'hyp-03',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-01',
    group_id: 'hg-02',
    category: 'WAF_BYPASS',
    title: 'Direct Origin IP Reachability Exposing Internal Management Ports',
    description: 'Origin server responds to direct IP connections on port 8080 without requiring Cloudflare mTLS or authenticated origin pull headers.',
    epistemic_status: 'HYPOTHESIZED',
    status: 'INVESTIGATING',
    reasoning_method: 'DEDUCTIVE',
    evidence_strength: 4,
    investigation_priority: 88,
    supporting_evidence: ['ev-03'],
    contradicting_evidence: [],
    missing_evidence: ['Origin security group firewall rules'],
    falsification_conditions: [
      {
        condition_description: 'Direct origin connection drops or rejects TCP SYN without Cloudflare IP range',
        required_evidence: 'SYN packet probe from non-Cloudflare egress',
        validation_method: 'TCP_PORT_PROBE',
        result: 'PENDING',
      },
    ],
    metadata: { confidence_level: 0.9 },
    created_at: new Date(Date.now() - 3000000).toISOString(),
    updated_at: new Date(Date.now() - 3000000).toISOString(),
  },
];

const investigationsStore: any[] = [
  {
    id: 'inv-01',
    target_id: 'tgt-alpha-001',
    asset_id: 'ast-02',
    hypothesis_id: 'hyp-01',
    title: 'Controlled Non-Destructive Token Decoupling & Claim Verification',
    status: 'PLANNED',
    safety_boundary: {
      is_non_destructive: true,
      requires_credential: false,
      max_requests_per_second: 2,
      max_total_requests: 10,
      read_only: true,
      allowed_endpoints: ['/v1/auth/token', '/v1/auth/jwks.json'],
    },
    steps: [
      {
        step_number: 1,
        name: 'Retrieve JWKS Public Key Set',
        description: 'Fetch public key set from standard discovery endpoint to evaluate signature veracity',
        action_type: 'CAPTURE_BASELINE',
        status: 'PENDING',
      },
      {
        step_number: 2,
        name: 'Inspect Issued Token Claims for Elevated Scopes',
        description: 'Parse unauthenticated token payload without executing unauthorized actions',
        action_type: 'COMPARE_CONTEXTS',
        status: 'PENDING',
      },
    ],
    generated_evidence: [],
    falsification_result: 'UNDETERMINED',
    created_at: new Date(Date.now() - 1800000).toISOString(),
    updated_at: new Date(Date.now() - 1800000).toISOString(),
  },
];

const trustBoundariesStore: any[] = [
  {
    id: 'tb-01',
    asset_id: 'ast-02',
    boundary_name: 'Edge API Gateway to Internal Microservices',
    boundary_type: 'API_GATEWAY',
    ingress_protocol: 'HTTPS',
    egress_protocol: 'HTTP/Internal',
    authentication_required: true,
    authorization_model: 'RBAC_BEARER',
    data_classification: 'CONFIDENTIAL',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: 'tb-02',
    asset_id: 'ast-01',
    boundary_name: 'Cloudflare Edge CDN to Origin Ingress',
    boundary_type: 'CDN_EDGE',
    ingress_protocol: 'HTTPS',
    egress_protocol: 'HTTPS',
    authentication_required: false,
    authorization_model: 'ORIGIN_PULL_CERT',
    data_classification: 'PUBLIC',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
];

const permissionMatrixStore: any[] = [
  {
    id: 'pm-01',
    asset_id: 'ast-02',
    endpoint: '/api/v1/users',
    role: 'ANONYMOUS',
    expected_access: 'DENIED',
    observed_access: 'ALLOWED',
    has_anomaly: true,
    last_verified: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'pm-02',
    asset_id: 'ast-02',
    endpoint: '/api/v1/users',
    role: 'USER',
    expected_access: 'ALLOWED',
    observed_access: 'ALLOWED',
    has_anomaly: false,
    last_verified: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'pm-03',
    asset_id: 'ast-02',
    endpoint: '/admin/metrics',
    role: 'USER',
    expected_access: 'DENIED',
    observed_access: 'DENIED',
    has_anomaly: false,
    last_verified: new Date(Date.now() - 3600000).toISOString(),
  },
];

const securityControlsStore: any[] = [
  {
    id: 'sc-01',
    asset_id: 'ast-02',
    control_name: 'Strict-Transport-Security',
    control_type: 'HTTP_HEADER',
    enforcement_state: 'ENFORCED',
    configuration_details: 'max-age=31536000; includeSubDomains',
    last_audited: new Date(Date.now() - 7200000).toISOString(),
  },
  {
    id: 'sc-02',
    asset_id: 'ast-02',
    control_name: 'CORS Origin Whitelist',
    control_type: 'ACCESS_POLICY',
    enforcement_state: 'MISCONFIGURED',
    configuration_details: 'Wildcard * returned on authenticated endpoints',
    last_audited: new Date(Date.now() - 3600000).toISOString(),
  },
];

const authContextsStore: any[] = [
  {
    id: 'ac-01',
    target_id: 'tgt-alpha-001',
    name: 'Anonymous Guest Session',
    auth_type: 'NONE',
    headers: {},
    is_active: true,
  },
  {
    id: 'ac-02',
    target_id: 'tgt-alpha-001',
    name: 'Standard User Token',
    auth_type: 'BEARER_JWT',
    headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
    is_active: true,
  },
];

function nexusApiPlugin(): Plugin {
  return {
    name: 'nexus-api-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = req.url || '';
        if (!url.startsWith('/api/')) {
          return next();
        }

        // Buffer incoming request body
        const rawBody: Buffer = await new Promise((resolve) => {
          const chunks: Buffer[] = [];
          req.on('data', (c) => chunks.push(c));
          req.on('end', () => resolve(Buffer.concat(chunks)));
        });

        // Attempt live proxy to Go backend on port 8081
        const proxied = await new Promise<boolean>((resolve) => {
          const proxyReq = http.request(
            {
              hostname: '127.0.0.1',
              port: 8081,
              path: req.url,
              method: req.method,
              headers: {
                ...req.headers,
                host: '127.0.0.1:8081',
              },
              timeout: 2000,
            },
            (proxyRes) => {
              res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
              proxyRes.pipe(res);
              resolve(true);
            }
          );

          proxyReq.on('error', () => {
            resolve(false);
          });
          proxyReq.on('timeout', () => {
            proxyReq.destroy();
            resolve(false);
          });

          if (rawBody.length > 0) {
            proxyReq.write(rawBody);
          }
          proxyReq.end();
        });

        if (proxied) {
          return;
        }

        res.setHeader('Content-Type', 'application/json');

        // Helper to parse JSON body from buffered stream
        const readBody = (): Promise<any> => {
          try {
            return Promise.resolve(rawBody.length ? JSON.parse(rawBody.toString('utf-8')) : {});
          } catch {
            return Promise.resolve({});
          }
        };

        // 1. GET /api/health
        if (url === '/api/health' && req.method === 'GET') {
          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              status: 'ok',
              service: 'nexushunter-api',
              time: new Date().toISOString(),
            })
          );
        }

        // 2. GET /api/version
        if (url === '/api/version' && req.method === 'GET') {
          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              status: 'ok',
              service: 'nexushunter-api',
              version: '0.1.0-alpha',
              environment: 'development',
            })
          );
        }

        // 3. GET /api/events
        if (url === '/api/events' && req.method === 'GET') {
          res.statusCode = 200;
          return res.end(JSON.stringify(eventsStore));
        }

        // 4. /api/targets
        if (url === '/api/targets') {
          if (req.method === 'GET') {
            res.statusCode = 200;
            return res.end(JSON.stringify(targetsStore));
          }
          if (req.method === 'POST') {
            const body = await readBody();
            if (!body.name || !body.root_domain) {
              res.statusCode = 422;
              return res.end(
                JSON.stringify({
                  error: { code: 'INVALID_TARGET', message: 'Name and root_domain are required' },
                })
              );
            }
            const newTarget = {
              id: `tgt-${Date.now().toString(36)}`,
              name: body.name,
              root_domain: body.root_domain.toLowerCase().trim(),
              allowed_domains: body.allowed_domains || [body.root_domain],
              allowed_url_patterns: body.allowed_url_patterns || [],
              excluded_patterns: body.excluded_patterns || [],
              status: 'ACTIVE',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
            targetsStore.unshift(newTarget);
            eventsStore.unshift({
              event_id: `evt-${Date.now().toString(36)}`,
              event_type: 'TARGET_CREATED',
              target_id: newTarget.id,
              timestamp: new Date().toISOString(),
              payload: { name: newTarget.name, root_domain: newTarget.root_domain },
            });
            res.statusCode = 201;
            return res.end(JSON.stringify({ success: true, data: newTarget }));
          }
        }

        // Target by ID: /api/targets/:id
        const targetIdMatch = url.match(/^\/api\/targets\/([^/?]+)(?:\?.*)?$/);
        if (targetIdMatch) {
          const id = targetIdMatch[1];
          if (req.method === 'GET') {
            const tgt = targetsStore.find((t) => t.id === id);
            if (!tgt) {
              res.statusCode = 404;
              return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Target not found' } }));
            }
            res.statusCode = 200;
            return res.end(JSON.stringify(tgt));
          }
          if (req.method === 'DELETE') {
            targetsStore = targetsStore.filter((t) => t.id !== id);
            eventsStore.unshift({
              event_id: `evt-${Date.now().toString(36)}`,
              event_type: 'TARGET_DELETED',
              target_id: id,
              timestamp: new Date().toISOString(),
            });
            res.statusCode = 200;
            return res.end(JSON.stringify({ message: 'Target deleted', id }));
          }
        }

        // 5. /api/jobs
        if (url.startsWith('/api/jobs')) {
          if (req.method === 'GET') {
            res.statusCode = 200;
            return res.end(JSON.stringify(jobsStore));
          }
          if (req.method === 'POST') {
            const body = await readBody();
            if (!body.target_id) {
              res.statusCode = 422;
              return res.end(
                JSON.stringify({
                  error: { code: 'INVALID_JOB', message: 'target_id is required' },
                })
              );
            }
            const tgt = targetsStore.find((t) => t.id === body.target_id);
            if (!tgt) {
              res.statusCode = 404;
              return res.end(
                JSON.stringify({
                  error: { code: 'NOT_FOUND', message: 'Associated target does not exist' },
                })
              );
            }
            const newJob = {
              id: `job-${Date.now().toString(36)}`,
              target_id: body.target_id,
              type: body.type || 'PASSIVE_DNS_ENUMERATION',
              status: 'QUEUED',
              created_at: new Date().toISOString(),
              metadata: body.metadata || {},
            };
            jobsStore.unshift(newJob);
            eventsStore.unshift({
              event_id: `evt-${Date.now().toString(36)}`,
              event_type: 'JOB_QUEUED',
              job_id: newJob.id,
              target_id: newJob.target_id,
              timestamp: new Date().toISOString(),
            });
            res.statusCode = 201;
            return res.end(JSON.stringify({ success: true, data: newJob }));
          }
        }

        // 6. POST /api/scope/verify (Fail-closed matching internal/scope in Go)
        if (url === '/api/scope/verify' && req.method === 'POST') {
          const body = await readBody();
          const target = targetsStore.find((t) => t.id === body.target_id);
          if (!target) {
            res.statusCode = 200;
            return res.end(
              JSON.stringify({
                in_scope: false,
                reason: 'Target not found; fail closed',
              })
            );
          }

          let host = (body.hostname || '').toLowerCase().trim();
          let pathPart = '';
          if (body.url) {
            try {
              const parsed = new URL(body.url);
              if (!host) host = parsed.hostname.toLowerCase();
              pathPart = parsed.pathname;
            } catch {
              res.statusCode = 200;
              return res.end(
                JSON.stringify({
                  in_scope: false,
                  reason: 'Malformed URL; fail closed',
                })
              );
            }
          }

          // RFC 1123 hostname check
          const hostRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
          if (!host || (!hostRegex.test(host) && host !== 'localhost')) {
            res.statusCode = 200;
            return res.end(
              JSON.stringify({
                in_scope: false,
                reason: 'Malformed or invalid hostname; fail closed',
              })
            );
          }

          // Check exclusions
          for (const excl of target.excluded_patterns) {
            const cleanExcl = excl.toLowerCase().trim();
            if (cleanExcl.startsWith('*.')) {
              const base = cleanExcl.slice(2);
              if (host === base || host.endsWith('.' + base)) {
                res.statusCode = 200;
                return res.end(
                  JSON.stringify({
                    in_scope: false,
                    reason: `Explicitly excluded by pattern: ${cleanExcl}`,
                  })
                );
              }
            } else if (host === cleanExcl) {
              res.statusCode = 200;
              return res.end(
                JSON.stringify({
                  in_scope: false,
                  reason: `Explicitly excluded host: ${cleanExcl}`,
                })
              );
            }
          }

          // Check allowed domains
          let domainAllowed = false;
          let matchedDomainRule = '';
          const allowedList = target.allowed_domains.length > 0 ? target.allowed_domains : [target.root_domain];

          for (const allowed of allowedList) {
            const cleanAllowed = allowed.toLowerCase().trim();
            if (cleanAllowed.startsWith('*.')) {
              const base = cleanAllowed.slice(2);
              if (host === base || host.endsWith('.' + base)) {
                domainAllowed = true;
                matchedDomainRule = cleanAllowed;
                break;
              }
            } else if (host === cleanAllowed) {
              domainAllowed = true;
              matchedDomainRule = cleanAllowed;
              break;
            }
          }

          if (!domainAllowed) {
            res.statusCode = 200;
            return res.end(
              JSON.stringify({
                in_scope: false,
                reason: `Hostname '${host}' does not match allowed domains for target '${target.name}'`,
              })
            );
          }

          // Check path restrictions if applicable
          if (target.allowed_url_patterns && target.allowed_url_patterns.length > 0 && pathPart) {
            let pathAllowed = false;
            for (const pattern of target.allowed_url_patterns) {
              const cleanPat = pattern.trim();
              if (cleanPat.endsWith('/*')) {
                const prefix = cleanPat.slice(0, -2);
                if (pathPart.startsWith(prefix)) {
                  pathAllowed = true;
                  break;
                }
              } else if (pathPart === cleanPat) {
                pathAllowed = true;
                break;
              }
            }
            if (!pathAllowed) {
              res.statusCode = 200;
              return res.end(
                JSON.stringify({
                  in_scope: false,
                  reason: `Path '${pathPart}' is not permitted by allowed URL patterns`,
                })
              );
            }
          }

          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              in_scope: true,
              reason: 'Target explicitly authorized and passed fail-closed inspection',
              matched_rule: matchedDomainRule,
            })
          );
        }

        // 7. GET /api/targets/:id/assets
        const targetAssetsMatch = url.match(/^\/api\/targets\/([^/?]+)\/assets(?:\?.*)?$/);
        if (targetAssetsMatch && req.method === 'GET') {
          const targetId = targetAssetsMatch[1];
          const matched = assetsStore.filter((a) => a.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 8. GET /api/targets/:id/urls
        const targetUrlsMatch = url.match(/^\/api\/targets\/([^/?]+)\/urls(?:\?.*)?$/);
        if (targetUrlsMatch && req.method === 'GET') {
          const targetId = targetUrlsMatch[1];
          const matched = urlsStore.filter((u) => u.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 9. GET /api/targets/:id/intelligence
        const targetIntelMatch = url.match(/^\/api\/targets\/([^/?]+)\/intelligence(?:\?.*)?$/);
        if (targetIntelMatch && req.method === 'GET') {
          const targetId = targetIntelMatch[1];
          const targetTechs = technologiesStore.filter((t) => t.target_id === targetId);
          const targetSvcs = servicesStore.filter((s) => s.target_id === targetId);
          const targetSec = securityObsStore.filter((s) => s.target_id === targetId);
          const targetChg = changesStore.filter((c) => c.target_id === targetId);
          const targetTags = tagsStore.filter((t) => t.target_id === targetId);
          const targetAssets = assetsStore.filter((a) => a.target_id === targetId);

          const summary = {
            target_id: targetId,
            technologies: targetTechs,
            services: targetSvcs,
            security_observations: targetSec,
            changes: targetChg,
            tags: targetTags,
            total_assets: targetAssets.length,
            total_services: targetSvcs.length,
            total_technologies: targetTechs.length,
            total_changes: targetChg.length,
            recent_changes: targetChg.slice(0, 10),
            stats: {
              total_assets: targetAssets.length,
              total_services: targetSvcs.length,
              total_technologies: targetTechs.length,
              security_observations_count: targetSec.length,
              changes_count: targetChg.length,
            },
          };
          res.statusCode = 200;
          return res.end(JSON.stringify(summary));
        }

        // 10. GET /api/targets/:id/technologies
        const targetTechsMatch = url.match(/^\/api\/targets\/([^/?]+)\/technologies(?:\?.*)?$/);
        if (targetTechsMatch && req.method === 'GET') {
          const targetId = targetTechsMatch[1];
          const urlObj = new URL(url, 'http://localhost');
          const category = urlObj.searchParams.get('category');
          let matched = technologiesStore.filter((t) => t.target_id === targetId);
          if (category) {
            matched = matched.filter((t) => t.category.toLowerCase() === category.toLowerCase());
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 11. GET /api/targets/:id/services
        const targetSvcsMatch = url.match(/^\/api\/targets\/([^/?]+)\/services(?:\?.*)?$/);
        if (targetSvcsMatch && req.method === 'GET') {
          const targetId = targetSvcsMatch[1];
          const matched = servicesStore.filter((s) => s.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 12. GET /api/targets/:id/changes
        const targetChangesMatch = url.match(/^\/api\/targets\/([^/?]+)\/changes(?:\?.*)?$/);
        if (targetChangesMatch && req.method === 'GET') {
          const targetId = targetChangesMatch[1];
          const matched = changesStore.filter((c) => c.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 13. GET /api/targets/:id/assets/:assetId
        const assetDetailMatch = url.match(/^\/api\/targets\/([^/?]+)\/assets\/([^/?]+)(?:\?.*)?$/);
        if (assetDetailMatch && req.method === 'GET') {
          const targetId = assetDetailMatch[1];
          const assetId = assetDetailMatch[2];
          const asset = assetsStore.find((a) => a.id === assetId && a.target_id === targetId);
          if (!asset) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Asset not found' } }));
          }
          const detail = {
            asset,
            dns_records: asset.dns_records || [],
            services: servicesStore.filter((s) => s.asset_id === assetId),
            technologies: technologiesStore.filter((t) => t.asset_id === assetId),
            security_observations: securityObsStore.filter((s) => s.asset_id === assetId),
            tags: tagsStore.filter((t) => t.asset_id === assetId),
            page_assets: pageAssetsStore.filter((p) => p.asset_id === assetId),
            changes: changesStore.filter((c) => c.asset_id === assetId),
          };
          res.statusCode = 200;
          return res.end(JSON.stringify(detail));
        }

        // 14. POST /api/assets/:id/tags
        const addTagMatch = url.match(/^\/api\/assets\/([^/?]+)\/tags$/);
        if (addTagMatch && req.method === 'POST') {
          const assetId = addTagMatch[1];
          const body = await readBody();
          const cleanTag = (body.tag || '').toLowerCase().trim();
          if (!cleanTag) {
            res.statusCode = 400;
            return res.end(JSON.stringify({ error: { code: 'INVALID_TAG', message: 'Tag cannot be empty' } }));
          }
          const newTag = {
            id: `tag-${Date.now().toString(36)}`,
            asset_id: assetId,
            target_id: body.target_id || 'tgt-alpha-001',
            tag: cleanTag,
            is_inferred: false,
            created_at: new Date().toISOString(),
            created_by: 'user:manual',
          };
          tagsStore.push(newTag);
          res.statusCode = 201;
          return res.end(JSON.stringify(newTag));
        }

        // 15. DELETE /api/assets/:id/tags/:tag
        const deleteTagMatch = url.match(/^\/api\/assets\/([^/?]+)\/tags\/([^/?]+)$/);
        if (deleteTagMatch && req.method === 'DELETE') {
          const assetId = deleteTagMatch[1];
          const tagParam = decodeURIComponent(deleteTagMatch[2]).toLowerCase().trim();
          tagsStore = tagsStore.filter((t) => !(t.asset_id === assetId && t.tag.toLowerCase() === tagParam));
          res.statusCode = 200;
          return res.end(JSON.stringify({ message: 'Tag removed', tag: tagParam }));
        }

        // 16. POST /api/recon
        if (url === '/api/recon' && req.method === 'POST') {
          const body = await readBody();
          const newJob = {
            id: `job-recon-${Date.now().toString(36)}`,
            target_id: body.target_id || 'tgt-alpha-001',
            type: 'HIGH_SPEED_RECON',
            status: 'RUNNING',
            created_at: new Date().toISOString(),
            started_at: new Date().toISOString(),
            metadata: { options: body.options || {}, stages: ['DNS', 'HTTP_PROBE', 'INTEL'] },
          };
          jobsStore.unshift(newJob);
          eventsStore.unshift({
            event_id: `evt-${Date.now().toString(36)}`,
            event_type: 'RECON_STARTED',
            job_id: newJob.id,
            target_id: newJob.target_id,
            timestamp: new Date().toISOString(),
          });
          res.statusCode = 201;
          return res.end(JSON.stringify(newJob));
        }

        // 17. GET /api/recon/:jobId
        const reconRunMatch = url.match(/^\/api\/recon\/([^/?]+)$/);
        if (reconRunMatch && req.method === 'GET') {
          const jobId = reconRunMatch[1];
          const job = jobsStore.find((j) => j.id === jobId);
          const run = {
            id: `run-${jobId}`,
            job_id: jobId,
            target_id: job?.target_id || 'tgt-alpha-001',
            status: job?.status || 'COMPLETED',
            hosts_discovered: 3,
            hosts_resolved: 3,
            services_probed: 3,
            urls_crawled: 5,
            errors_count: 0,
            skipped_out_of_scope: 1,
            started_at: job?.started_at || new Date().toISOString(),
            completed_at: job?.completed_at,
            duration_ms: 1250,
          };
          res.statusCode = 200;
          return res.end(JSON.stringify(run));
        }

        // 18. POST /api/recon/:jobId/cancel
        const reconCancelMatch = url.match(/^\/api\/recon\/([^/?]+)\/cancel$/);
        if (reconCancelMatch && req.method === 'POST') {
          const jobId = reconCancelMatch[1];
          const job = jobsStore.find((j) => j.id === jobId);
          if (job) {
            job.status = 'CANCELLED';
            job.completed_at = new Date().toISOString();
          }
          res.statusCode = 200;
          return res.end(JSON.stringify({ job_id: jobId, status: 'CANCELLED' }));
        }

        // 19. POST /api/ai/analyze
        if (url === '/api/ai/analyze' && req.method === 'POST') {
          const body = await readBody();
          const targetId = body.target_id || 'tgt-alpha-001';
          const runId = `run-ai-${Date.now().toString(36)}`;
          const matchedCandidates = candidatesStore.filter((c) => c.target_id === targetId);
          const matchedSignals = signalsStore.filter((s) => s.target_id === targetId);
          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              run_id: runId,
              target_id: targetId,
              status: 'COMPLETED',
              provider: body.provider || 'gemini-1.5-flash',
              model: body.model || 'security-audit-v1',
              signals_count: matchedSignals.length,
              candidates_count: matchedCandidates.length,
              candidates: matchedCandidates,
              signals: matchedSignals,
              execution_time_ms: 184,
            })
          );
        }

        // 20. GET /api/targets/:id/candidates
        const targetCandidatesMatch = url.match(/^\/api\/targets\/([^/?]+)\/candidates(?:\?.*)?$/);
        if (targetCandidatesMatch && req.method === 'GET') {
          const targetId = targetCandidatesMatch[1];
          const urlObj = new URL(url, 'http://localhost');
          const state = urlObj.searchParams.get('state');
          let matched = candidatesStore.filter((c) => c.target_id === targetId);
          if (state) {
            matched = matched.filter((c) => c.state === state);
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 21. GET /api/candidates/:id
        const candidateDetailMatch = url.match(/^\/api\/candidates\/([^/?]+)$/);
        if (candidateDetailMatch && req.method === 'GET') {
          const candidateId = candidateDetailMatch[1];
          const cand = candidatesStore.find((c) => c.id === candidateId);
          if (!cand) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Candidate not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(cand));
        }

        // 22. PATCH /api/candidates/:id/state
        const candidateStateMatch = url.match(/^\/api\/candidates\/([^/?]+)\/state$/);
        if (candidateStateMatch && req.method === 'PATCH') {
          const candidateId = candidateStateMatch[1];
          const body = await readBody();
          const cand = candidatesStore.find((c) => c.id === candidateId);
          if (!cand) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Candidate not found' } }));
          }
          cand.state = body.state || cand.state;
          cand.updated_at = new Date().toISOString();
          if (body.reason) {
            cand.reasoning += `\n[State updated to ${cand.state}: ${body.reason}]`;
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(cand));
        }

        // 23. GET /api/targets/:id/graph
        const targetGraphMatch = url.match(/^\/api\/targets\/([^/?]+)\/graph(?:\?.*)?$/);
        if (targetGraphMatch && req.method === 'GET') {
          const targetId = targetGraphMatch[1];
          const nodes = graphNodesStore.filter((n) => n.target_id === targetId);
          const edges = graphEdgesStore.filter((e) => e.target_id === targetId);
          const metrics: Record<string, number> = {};
          nodes.forEach((n) => {
            metrics[n.type] = (metrics[n.type] || 0) + 1;
          });
          res.statusCode = 200;
          return res.end(
            JSON.stringify({
              target_id: targetId,
              nodes,
              edges,
              total_nodes: nodes.length,
              total_edges: edges.length,
              metrics,
            })
          );
        }

        // 24. GET /api/targets/:id/temporal-changes
        const targetTemporalMatch = url.match(/^\/api\/targets\/([^/?]+)\/temporal-changes(?:\?.*)?$/);
        if (targetTemporalMatch && req.method === 'GET') {
          const targetId = targetTemporalMatch[1];
          const urlObj = new URL(url, 'http://localhost');
          const limit = parseInt(urlObj.searchParams.get('limit') || '50', 10);
          let matched = temporalChangesStore.filter((t) => t.target_id === targetId);
          if (limit > 0) {
            matched = matched.slice(0, limit);
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 25. GET /api/targets/:id/invariants
        const targetInvariantsMatch = url.match(/^\/api\/targets\/([^/?]+)\/invariants(?:\?.*)?$/);
        if (targetInvariantsMatch && req.method === 'GET') {
          const targetId = targetInvariantsMatch[1];
          const matched = invariantSignalsStore.filter((i) => i.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 26. GET /api/targets/:id/behavior-diffs
        const targetDiffsMatch = url.match(/^\/api\/targets\/([^/?]+)\/behavior-diffs(?:\?.*)?$/);
        if (targetDiffsMatch && req.method === 'GET') {
          const targetId = targetDiffsMatch[1];
          const matched = behaviorDiffsStore.filter((d) => d.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 27. GET /api/targets/:id/investigation-clusters
        const targetClustersMatch = url.match(/^\/api\/targets\/([^/?]+)\/investigation-clusters(?:\?.*)?$/);
        if (targetClustersMatch && req.method === 'GET') {
          const targetId = targetClustersMatch[1];
          const matched = investigationClustersStore.filter((c) => c.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(matched));
        }

        // 28. PATCH /api/investigation-clusters/:id/status
        const clusterStatusMatch = url.match(/^\/api\/investigation-clusters\/([^/?]+)\/status$/);
        if (clusterStatusMatch && req.method === 'PATCH') {
          const clusterId = clusterStatusMatch[1];
          const body = await readBody();
          const cl = investigationClustersStore.find((c) => c.id === clusterId);
          if (!cl) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Cluster not found' } }));
          }
          cl.status = body.status || cl.status;
          cl.updated_at = new Date().toISOString();
          res.statusCode = 200;
          return res.end(JSON.stringify(cl));
        }

        // 29. GET /api/targets/:id/research-memory
        const targetMemoryMatch = url.match(/^\/api\/targets\/([^/?]+)\/research-memory(?:\?.*)?$/);
        if (targetMemoryMatch && req.method === 'GET') {
          const targetId = targetMemoryMatch[1];
          const assets = assetsStore.filter((a) => a.target_id === targetId);
          const urls = urlsStore.filter((u) => u.target_id === targetId);
          const techs = technologiesStore.filter((t) => t.target_id === targetId);
          const changes = temporalChangesStore.filter((c) => c.target_id === targetId);
          const clusters = investigationClustersStore.filter((c) => c.target_id === targetId && (c.status === 'ACTIVE' || c.status === 'INVESTIGATING'));
          const candidates = candidatesStore.filter((c) => c.target_id === targetId);

          const memory = {
            target_id: targetId,
            known_assets_count: assets.length,
            known_endpoints_count: urls.length,
            known_technologies_count: techs.length,
            total_historical_changes: changes.length,
            active_investigations_count: clusters.length,
            validated_findings_count: candidates.filter((c) => c.state === 'REPORTED' || c.state === 'RESOLVED').length,
            rejected_candidates_count: candidates.filter((c) => c.state === 'DISMISSED').length,
            recent_what_changed: changes.slice(0, 5),
            deserves_reinvestigation: clusters,
            last_scan_at: new Date().toISOString(),
          };
          res.statusCode = 200;
          return res.end(JSON.stringify(memory));
        }

        // 30. POST /api/validation/execute
        if (url === '/api/validation/execute' && req.method === 'POST') {
          const body = await readBody();
          const targetId = body.target_id || 'tgt-alpha-001';
          const candidateId = body.candidate_id;
          const clusterId = body.cluster_id;

          // Non-destructive verification result
          const result = {
            id: `val-${Date.now().toString(36)}`,
            candidate_id: candidateId,
            cluster_id: clusterId,
            success: true,
            state: 'VALIDATING',
            observations: [
              'Non-destructive HTTP preflight dispatched safely within defined target scope',
              'Captured response headers and verified boundary isolation',
              'Recorded state-machine invariant observation without modifying server state',
            ],
            output_fact: 'Confirmed: Preflight check returns expected response without persistent side effects.',
            executed_at: new Date().toISOString(),
          };

          if (candidateId) {
            const cand = candidatesStore.find((c) => c.id === candidateId);
            if (cand && cand.state === 'CANDIDATE') {
              cand.state = 'VALIDATING';
              cand.updated_at = new Date().toISOString();
            }
          }

          res.statusCode = 200;
          return res.end(JSON.stringify(result));
        }

        // --- Phase 6 Evidence Intelligence & Security Reasoning Routes ---

        // 31. POST /api/evidence
        if (url === '/api/evidence' && req.method === 'POST') {
          const body = await readBody();
          const newEv = {
            id: `ev-${Date.now().toString(36)}`,
            target_id: body.target_id || 'tgt-alpha-001',
            asset_id: body.asset_id || 'ast-01',
            source: body.source || 'MANUAL_PROBE',
            evidence_type: body.evidence_type || 'HTTP_RESPONSE',
            summary: body.summary || 'User-recorded security evidence item',
            captured_at: new Date().toISOString(),
            status_code: body.status_code || 200,
            request: body.request,
            response: body.response,
            relevant_headers: body.relevant_headers,
            scope_decision: body.scope_decision || {
              is_in_scope: true,
              target_id: body.target_id || 'tgt-alpha-001',
              evaluated_host: body.request?.url ? new URL(body.request.url).hostname : 'example.com',
              rule_matched: '*.example.com',
              reason: 'Manually recorded within program scope',
              evaluated_at: new Date().toISOString(),
            },
            redaction_status: body.redaction_status || {
              is_redacted: true,
              redacted_fields: ['Authorization', 'Cookie'],
              sanitized_at: new Date().toISOString(),
            },
            canonical_representation: JSON.stringify({
              asset_id: body.asset_id,
              evidence_type: body.evidence_type,
              target_id: body.target_id,
            }),
            sha256: `ev${Math.random().toString(16).substring(2, 10)}${Date.now().toString(16)}000000000000000000000000000000000000`.substring(0, 64),
            provenance: body.provenance || {
              source: 'MANUAL_PROBE',
              operation_id: `op-rec-${Date.now().toString(36)}`,
              target_id: body.target_id || 'tgt-alpha-001',
              captured_at: new Date().toISOString(),
              initiator: 'user:security-analyst',
            },
          };
          evidenceRecordsStore.unshift(newEv);
          evidenceTimelineStore.unshift({
            id: `tl-${Date.now().toString(36)}`,
            target_id: newEv.target_id,
            asset_id: newEv.asset_id,
            event_type: 'EVIDENCE_RECORDED',
            summary: newEv.summary,
            epistemic_status: 'OBSERVED',
            timestamp: new Date().toISOString(),
            provenance: newEv.provenance,
            reference_id: newEv.id,
          });
          res.statusCode = 201;
          return res.end(JSON.stringify({ status: 'recorded', evidence: newEv }));
        }

        // 32. GET /api/evidence/:id
        const evIntegMatch = url.match(/^\/api\/evidence\/([^\/?]+)\/integrity$/);
        if (evIntegMatch && req.method === 'GET') {
          const evId = evIntegMatch[1];
          const ev = evidenceRecordsStore.find((e) => e.id === evId);
          if (!ev) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Evidence record not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify({
            evidence_id: ev.id,
            original_sha256: ev.sha256,
            computed_sha256: ev.sha256,
            is_tampered: false,
            verified_at: new Date().toISOString(),
            canonical_matches: true,
          }));
        }

        const evMatch = url.match(/^\/api\/evidence\/([^\/?]+)$/);
        if (evMatch && req.method === 'GET') {
          const evId = evMatch[1];
          const ev = evidenceRecordsStore.find((e) => e.id === evId);
          if (!ev) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Evidence not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify({ evidence: ev }));
        }

        // 33. GET /api/targets/:id/evidence
        const tgtEvMatch = url.match(/^\/api\/targets\/([^\/?]+)\/evidence(\?.*)?$/);
        if (tgtEvMatch && req.method === 'GET') {
          const targetId = tgtEvMatch[1];
          const list = evidenceRecordsStore.filter((e) => e.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ target_id: targetId, evidence: list, count: list.length }));
        }

        // 34. GET /api/assets/:id/evidence
        const astEvMatch = url.match(/^\/api\/assets\/([^\/?]+)\/evidence(\?.*)?$/);
        if (astEvMatch && req.method === 'GET') {
          const assetId = astEvMatch[1];
          const list = evidenceRecordsStore.filter((e) => e.asset_id === assetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ asset_id: assetId, evidence: list, count: list.length }));
        }

        // 35. POST /api/evidence/diff
        if (url === '/api/evidence/diff' && req.method === 'POST') {
          const body = await readBody();
          const evA = evidenceRecordsStore.find((e) => e.id === body.evidence_a_id);
          const evB = evidenceRecordsStore.find((e) => e.id === body.evidence_b_id);

          const statusA = evA?.status_code || 200;
          const statusB = evB?.status_code || 200;
          const statusChanged = statusA !== statusB;
          const lenA = evA?.response?.body_length || 0;
          const lenB = evB?.response?.body_length || 0;

          const diffResult = {
            id: `ediff-${Date.now().toString(36)}`,
            target_id: evA?.target_id || evB?.target_id || 'tgt-alpha-001',
            asset_id: evA?.asset_id || evB?.asset_id,
            evidence_a_id: body.evidence_a_id,
            evidence_b_id: body.evidence_b_id,
            raw_diff: {
              status_from: statusA,
              status_to: statusB,
              status_changed: statusChanged,
              body_length_delta: lenB - lenA,
              body_hash_a: evA?.response?.body_hash || 'hashA',
              body_hash_b: evB?.response?.body_hash || 'hashB',
              body_hash_changed: evA?.response?.body_hash !== evB?.response?.body_hash,
              added_headers: { 'Differential-Evaluated': 'true' },
              removed_headers: {},
              modified_headers: {},
              response_time_delta_ms: Math.abs((evB?.response?.response_time_ms || 100) - (evA?.response?.response_time_ms || 100)),
            },
            semantic_diff: {
              category: statusChanged ? 'AUTH_BEHAVIOR_SHIFT' : 'BEHAVIORAL_STABILITY',
              meaning: statusChanged
                ? `HTTP status changed from ${statusA} to ${statusB}; state boundary affected.`
                : 'Responses exhibit consistent status handling across test contexts.',
              auth_behavior_changed: statusChanged && (statusA === 401 || statusB === 401 || statusA === 403 || statusB === 403),
              content_type_changed: evA?.response?.content_type !== evB?.response?.content_type,
              redirect_changed: false,
              error_payload_detected: statusB >= 400,
              state_transition_detected: statusChanged,
            },
            security_diff: {
              observation_context: `Compared Evidence ${body.evidence_a_id} with ${body.evidence_b_id} (Noise filtering: ${body.filter_noise !== false})`,
              relevance_explanation: statusChanged
                ? 'Differential reveals privilege or validation discrepancy between examined contexts.'
                : 'No structural authorization divergence detected between evidence items.',
              requires_followup: statusChanged,
              suggested_questions: statusChanged
                ? ['Is this difference intentional under authorization role policy?', 'Does the second context bypass security filters?']
                : ['Verify if internal parameters affect response state.'],
            },
            is_noise_filtered: body.filter_noise !== false,
            is_security_relevant: statusChanged,
            computed_at: new Date().toISOString(),
          };

          evidenceDiffsStore.unshift(diffResult);
          res.statusCode = 200;
          return res.end(JSON.stringify({ diff: diffResult }));
        }

        // 36. GET /api/evidence/diffs/:id
        const diffMatch = url.match(/^\/api\/evidence\/diffs\/([^\/?]+)$/);
        if (diffMatch && req.method === 'GET') {
          const diffId = diffMatch[1];
          const diff = evidenceDiffsStore.find((d) => d.id === diffId);
          if (!diff) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Evidence diff not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify({ diff }));
        }

        // 37. GET /api/targets/:id/diffs
        const tgtDiffMatch = url.match(/^\/api\/targets\/([^\/?]+)\/diffs(\?.*)?$/);
        if (tgtDiffMatch && req.method === 'GET') {
          const targetId = tgtDiffMatch[1];
          const list = evidenceDiffsStore.filter((d) => d.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ target_id: targetId, diffs: list, count: list.length }));
        }

        // 38. POST /api/expectations
        if (url === '/api/expectations' && req.method === 'POST') {
          const body = await readBody();
          const newExp = {
            id: `exp-${Date.now().toString(36)}`,
            target_id: body.target_id || 'tgt-alpha-001',
            asset_id: body.asset_id,
            endpoint: body.endpoint,
            control_name: body.control_name || 'Security Control Expectation',
            source: body.source || 'EXPLICIT_POLICY',
            expected_state: body.expected_state || 'PRESENT',
            description: body.description || '',
            created_at: new Date().toISOString(),
          };
          securityExpectationsStore.unshift(newExp);
          res.statusCode = 201;
          return res.end(JSON.stringify({ status: 'created', expectation: newExp }));
        }

        // 39. GET /api/targets/:id/expectations
        const tgtExpMatch = url.match(/^\/api\/targets\/([^\/?]+)\/expectations(\?.*)?$/);
        if (tgtExpMatch && req.method === 'GET') {
          const targetId = tgtExpMatch[1];
          const list = securityExpectationsStore.filter((e) => e.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ target_id: targetId, expectations: list, count: list.length }));
        }

        // 40. POST /api/contradictions/evaluate
        if (url === '/api/contradictions/evaluate' && req.method === 'POST') {
          const body = await readBody();
          const exp = body.expectation || {};
          const observed = body.observed_state || 'UNKNOWN';

          // Rigorous Epistemic Discipline: NOT_OBSERVED does not declare contradiction
          if (observed === 'NOT_OBSERVED') {
            res.statusCode = 200;
            return res.end(JSON.stringify({
              contradiction_found: false,
              message: 'State is NOT_OBSERVED; no affirmative absence demonstrated. Strict epistemic rule prevents false positive.',
            }));
          }

          if (exp.expected_state === 'PRESENT' && observed === 'ABSENT') {
            const newCon = {
              id: `con-${Date.now().toString(36)}`,
              target_id: body.target_id || 'tgt-alpha-001',
              asset_id: body.asset_id,
              endpoint: body.endpoint,
              contradiction_type: 'SECURITY_CONTROL_CONTRADICTION',
              status: 'CONFIRMED_DEVIATION',
              severity: 'HIGH',
              title: `Contradiction in ${exp.control_name || 'Security Control'}`,
              description: `Expected state was ${exp.expected_state}, but deterministic observation recorded ${observed}.`,
              expectation_id: exp.id,
              observed_state: observed,
              evidence_refs: body.evidence_refs || [],
              explanation: `Explicit expectation (${exp.source}) violated: Control was asserted to be PRESENT, but observation confirms absence.`,
              suggested_followup: ['Execute controlled non-destructive validation probe', 'Inspect proxy or routing topology'],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
            securityContradictionsStore.unshift(newCon);
            res.statusCode = 200;
            return res.end(JSON.stringify({ contradiction_found: true, contradiction: newCon }));
          }

          res.statusCode = 200;
          return res.end(JSON.stringify({ contradiction_found: false, message: 'Observed state conforms to expectation.' }));
        }

        // 41. GET /api/targets/:id/contradictions
        const tgtConMatch = url.match(/^\/api\/targets\/([^\/?]+)\/contradictions(\?.*)?$/);
        if (tgtConMatch && req.method === 'GET') {
          const targetId = tgtConMatch[1];
          const list = securityContradictionsStore.filter((c) => c.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ target_id: targetId, contradictions: list, count: list.length }));
        }

        // 42. PATCH /api/contradictions/:id/status
        const patchConMatch = url.match(/^\/api\/contradictions\/([^\/?]+)\/status$/);
        if (patchConMatch && req.method === 'PATCH') {
          const conId = patchConMatch[1];
          const body = await readBody();
          const con = securityContradictionsStore.find((c) => c.id === conId);
          if (!con) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Contradiction not found' } }));
          }
          con.status = body.status;
          con.updated_at = new Date().toISOString();
          res.statusCode = 200;
          return res.end(JSON.stringify({ status: 'updated', contradiction: con }));
        }

        // 43. GET /api/targets/:id/outliers
        const tgtOutMatch = url.match(/^\/api\/targets\/([^\/?]+)\/outliers(\?.*)?$/);
        if (tgtOutMatch && req.method === 'GET') {
          const targetId = tgtOutMatch[1];
          const list = securityOutliersStore.filter((o) => o.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ target_id: targetId, outliers: list, count: list.length }));
        }

        // 44. GET /api/targets/:id/assets/:assetId/interest
        const intMatch = url.match(/^\/api\/targets\/([^\/?]+)\/assets\/([^\/?]+)\/interest(\?.*)?$/);
        if (intMatch && req.method === 'GET') {
          const targetId = intMatch[1];
          const assetId = intMatch[2];
          const ast = assetsStore.find((a) => a.id === assetId);

          const summary = {
            asset_id: assetId,
            hostname: ast?.hostname || 'api.example.com',
            target_id: targetId,
            score: assetId === 'ast-02' ? 88 : 45,
            reasons: [
              {
                factor_name: 'Auth Boundary Contradiction',
                description: 'Active unauthenticated token reflection observed on /v1/auth/token',
                evidence_refs: ['ev-01'],
                weight: 40,
              },
              {
                factor_name: 'Peer Baseline Outlier',
                description: 'CORS wildcard policy deviates from standard internal origin whitelist across target peer group',
                evidence_refs: ['out-01'],
                weight: 25,
              },
              {
                factor_name: 'Direct Origin Exposure',
                description: 'Asset bypasses Cloudflare CDN edge infrastructure directly to nginx/1.24.0 origin daemon',
                evidence_refs: ['out-02'],
                weight: 23,
              },
            ],
            linked_evidence_ids: ['ev-01', 'ediff-01', 'con-01'],
            evaluated_at: new Date().toISOString(),
          };

          res.statusCode = 200;
          return res.end(JSON.stringify({ interest_summary: summary }));
        }

        // 45. GET /api/targets/:id/evidence-timeline
        const tlMatch = url.match(/^\/api\/targets\/([^\/?]+)\/evidence-timeline(\?.*)?$/);
        if (tlMatch && req.method === 'GET') {
          const targetId = tlMatch[1];
          const list = evidenceTimelineStore.filter((t) => t.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify({ target_id: targetId, events: list, count: list.length }));
        }

        // ==========================================
        // Phase 7 Endpoints: Reasoning & Investigations
        // ==========================================

        // 46. GET /api/signals
        const signalsMatch = url.match(/^\/api\/signals(\?.*)?$/);
        if (signalsMatch && req.method === 'GET') {
          const u = new URL(url, 'http://localhost');
          const targetId = u.searchParams.get('target_id');
          const assetId = u.searchParams.get('asset_id');
          let list = [...reasoningSignalsStore];
          if (targetId) list = list.filter((s) => s.target_id === targetId);
          if (assetId) list = list.filter((s) => s.asset_id === assetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(list));
        }

        // 47. GET /api/signals/:id
        const sigGetMatch = url.match(/^\/api\/signals\/([^\/?]+)$/);
        if (sigGetMatch && req.method === 'GET') {
          const sigId = sigGetMatch[1];
          const sig = reasoningSignalsStore.find((s) => s.id === sigId);
          if (!sig) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Signal not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(sig));
        }

        // 48. PATCH /api/signals/:id/status
        const sigStatusMatch = url.match(/^\/api\/signals\/([^\/?]+)\/status$/);
        if (sigStatusMatch && req.method === 'PATCH') {
          const sigId = sigStatusMatch[1];
          const body = await readBody();
          const sig = reasoningSignalsStore.find((s) => s.id === sigId);
          if (!sig) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Signal not found' } }));
          }
          if (!validateSignalTransition(sig.status, body.status)) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
              error: {
                code: 'INVALID_STATE_TRANSITION',
                message: `cannot transition signal from ${sig.status} to ${body.status}`,
              },
            }));
          }
          sig.status = body.status;
          sig.updated_at = new Date().toISOString();
          res.statusCode = 200;
          return res.end(JSON.stringify({ status: sig.status, updated_at: sig.updated_at }));
        }

        // 49. GET /api/hypotheses
        const hypothesesMatch = url.match(/^\/api\/hypotheses(\?.*)?$/);
        if (hypothesesMatch && req.method === 'GET') {
          const u = new URL(url, 'http://localhost');
          const targetId = u.searchParams.get('target_id');
          const groupId = u.searchParams.get('group_id');
          let list = [...hypothesesStore];
          if (targetId) list = list.filter((h) => h.target_id === targetId);
          if (groupId) list = list.filter((h) => h.group_id === groupId);
          res.statusCode = 200;
          return res.end(JSON.stringify(list));
        }

        // 50. POST /api/hypotheses
        if (url === '/api/hypotheses' && req.method === 'POST') {
          const body = await readBody();
          const newHyp = {
            id: body.id || `hyp-${Date.now().toString(36)}`,
            target_id: body.target_id || 'tgt-alpha-001',
            asset_id: body.asset_id || 'ast-02',
            group_id: body.group_id || 'hg-01',
            category: body.category || 'AUTH_POLICY_DIFF',
            title: body.title || 'Untitled Hypothesis',
            description: body.description || '',
            epistemic_status: body.epistemic_status || 'HYPOTHESIZED',
            status: body.status || 'HYPOTHESIZED',
            reasoning_method: body.reasoning_method || 'ABDUCTIVE',
            evidence_strength: body.evidence_strength || 3,
            investigation_priority: body.investigation_priority || 50,
            supporting_evidence: body.supporting_evidence || [],
            contradicting_evidence: body.contradicting_evidence || [],
            missing_evidence: body.missing_evidence || [],
            falsification_conditions: body.falsification_conditions || [],
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          };
          hypothesesStore.unshift(newHyp);
          res.statusCode = 201;
          return res.end(JSON.stringify(newHyp));
        }

        // 51. GET /api/hypotheses/:id
        const hypGetMatch = url.match(/^\/api\/hypotheses\/([^\/?]+)$/);
        if (hypGetMatch && req.method === 'GET') {
          const hypId = hypGetMatch[1];
          const hyp = hypothesesStore.find((h) => h.id === hypId);
          if (!hyp) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Hypothesis not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(hyp));
        }

        // 52. POST /api/hypotheses/:id/status
        const hypStatusMatch = url.match(/^\/api\/hypotheses\/([^\/?]+)\/status$/);
        if (hypStatusMatch && req.method === 'POST') {
          const hypId = hypStatusMatch[1];
          const body = await readBody();
          const hyp = hypothesesStore.find((h) => h.id === hypId);
          if (!hyp) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Hypothesis not found' } }));
          }
          if (!validateHypothesisTransition(hyp.status, body.status)) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
              error: {
                code: 'INVALID_STATE_TRANSITION',
                message: `cannot transition hypothesis from ${hyp.status} to ${body.status}`,
              },
            }));
          }
          hyp.status = body.status;
          hyp.updated_at = new Date().toISOString();
          res.statusCode = 200;
          return res.end(JSON.stringify({ status: hyp.status, updated_at: hyp.updated_at }));
        }

        // 53. GET /api/hypotheses/:id/evidence
        const hypEvMatch = url.match(/^\/api\/hypotheses\/([^\/?]+)\/evidence$/);
        if (hypEvMatch && req.method === 'GET') {
          const hypId = hypEvMatch[1];
          const hyp = hypothesesStore.find((h) => h.id === hypId);
          if (!hyp) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Hypothesis not found' } }));
          }
          const evList = (hyp.supporting_evidence || []).map((id: string) =>
            evidenceStore.find((e) => e.id === id)
          ).filter(Boolean);
          res.statusCode = 200;
          return res.end(JSON.stringify(evList));
        }

        // 54. GET /api/hypotheses/:id/alternatives
        const hypAltMatch = url.match(/^\/api\/hypotheses\/([^\/?]+)\/alternatives$/);
        if (hypAltMatch && req.method === 'GET') {
          const hypId = hypAltMatch[1];
          const hyp = hypothesesStore.find((h) => h.id === hypId);
          if (!hyp) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Hypothesis not found' } }));
          }
          const alts = hypothesesStore.filter((h) => h.group_id === hyp.group_id && h.id !== hyp.id);
          res.statusCode = 200;
          return res.end(JSON.stringify(alts));
        }

        // 55. GET /api/hypothesis-groups
        const grpMatch = url.match(/^\/api\/hypothesis-groups(\?.*)?$/);
        if (grpMatch && req.method === 'GET') {
          const u = new URL(url, 'http://localhost');
          const targetId = u.searchParams.get('target_id');
          let list = [...hypothesisGroupsStore];
          if (targetId) list = list.filter((g) => g.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(list));
        }

        // 56. GET /api/hypothesis-groups/:id
        const grpGetMatch = url.match(/^\/api\/hypothesis-groups\/([^\/?]+)$/);
        if (grpGetMatch && req.method === 'GET') {
          const grpId = grpGetMatch[1];
          const grp = hypothesisGroupsStore.find((g) => g.id === grpId);
          if (!grp) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Hypothesis group not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(grp));
        }

        // 57. GET /api/investigations
        const invListMatch = url.match(/^\/api\/investigations(\?.*)?$/);
        if (invListMatch && req.method === 'GET') {
          const u = new URL(url, 'http://localhost');
          const targetId = u.searchParams.get('target_id');
          let list = [...investigationsStore];
          if (targetId) list = list.filter((i) => i.target_id === targetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(list));
        }

        // 58. POST /api/investigations
        if (url === '/api/investigations' && req.method === 'POST') {
          const body = await readBody();
          const hypId = body.hypothesis_id;
          const hyp = hypothesesStore.find((h) => h.id === hypId);
          const newInv = {
            id: `inv-${Date.now().toString(36)}`,
            target_id: hyp?.target_id || body.target_id || 'tgt-alpha-001',
            asset_id: hyp?.asset_id || body.asset_id || 'ast-02',
            hypothesis_id: hypId || 'hyp-01',
            title: `Investigation: ${hyp?.title || 'Security Hypothesis'}`,
            status: 'PLANNED',
            safety_boundary: {
              is_non_destructive: true,
              requires_credential: false,
              max_requests_per_second: 2,
              max_total_requests: 10,
              read_only: true,
              allowed_endpoints: ['/v1/auth/token'],
            },
            steps: [
              {
                step_number: 1,
                name: 'Baseline Probe Acquisition',
                description: 'Collect non-destructive live telemetry matching hypothesis conditions',
                action_type: 'CAPTURE_BASELINE',
                status: 'PENDING',
              },
              {
                step_number: 2,
                name: 'Comparative Evaluation',
                description: 'Check differential response against expected access policy',
                action_type: 'COMPARE_CONTEXTS',
                status: 'PENDING',
              },
            ],
            generated_evidence: [],
            falsification_result: 'UNDETERMINED',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          };
          investigationsStore.unshift(newInv);
          res.statusCode = 201;
          return res.end(JSON.stringify(newInv));
        }

        // 59. GET /api/investigations/:id
        const invGetMatch = url.match(/^\/api\/investigations\/([^\/?]+)$/);
        if (invGetMatch && req.method === 'GET') {
          const invId = invGetMatch[1];
          const inv = investigationsStore.find((i) => i.id === invId);
          if (!inv) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Investigation not found' } }));
          }
          res.statusCode = 200;
          return res.end(JSON.stringify(inv));
        }

        // 60. POST /api/investigations/:id/cancel
        const invCancelMatch = url.match(/^\/api\/investigations\/([^\/?]+)\/cancel$/);
        if (invCancelMatch && req.method === 'POST') {
          const invId = invCancelMatch[1];
          const inv = investigationsStore.find((i) => i.id === invId);
          if (!inv) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Investigation not found' } }));
          }
          if (!validateInvestigationTransition(inv.status, 'CANCELLED')) {
            res.statusCode = 400;
            return res.end(JSON.stringify({
              error: {
                code: 'INVALID_STATE_TRANSITION',
                message: `cannot cancel investigation in state ${inv.status}`,
              },
            }));
          }
          inv.status = 'CANCELLED';
          inv.updated_at = new Date().toISOString();
          res.statusCode = 200;
          return res.end(JSON.stringify({ status: 'CANCELLED', id: inv.id }));
        }

        // 61. POST /api/investigations/:id/execute
        const invExecMatch = url.match(/^\/api\/investigations\/([^\/?]+)\/execute$/);
        if (invExecMatch && req.method === 'POST') {
          const invId = invExecMatch[1];
          const inv = investigationsStore.find((i) => i.id === invId);
          if (!inv) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'Investigation not found' } }));
          }
          if (inv.status === 'COMPLETED' || inv.status === 'CANCELLED') {
            res.statusCode = 400;
            return res.end(JSON.stringify({
              error: {
                code: 'INVALID_STATE_TRANSITION',
                message: `cannot execute steps on investigation in state ${inv.status}`,
              },
            }));
          }

          // Advance to RUNNING if PLANNED/QUEUED
          if (inv.status === 'PLANNED' || inv.status === 'QUEUED') {
            inv.status = 'RUNNING';
          }

          const pendingStep = inv.steps?.find((s: any) => s.status === 'PENDING');
          if (!pendingStep) {
            inv.status = 'COMPLETED';
            res.statusCode = 200;
            return res.end(JSON.stringify(inv));
          }

          pendingStep.status = 'COMPLETED';
          pendingStep.executed_at = new Date().toISOString();
          const generatedEvId = `ev-inv-${Date.now().toString(36)}`;
          pendingStep.result_evidence_id = generatedEvId;
          inv.generated_evidence = inv.generated_evidence || [];
          inv.generated_evidence.push(generatedEvId);

          // Add generated evidence to store
          evidenceStore.unshift({
            id: generatedEvId,
            target_id: inv.target_id,
            asset_id: inv.asset_id,
            source: 'CONTROLLED_VALIDATION',
            evidence_type: 'HTTP_REQUEST',
            summary: `Automated baseline telemetry from investigation step: ${pendingStep.name}`,
            captured_at: new Date().toISOString(),
            status_code: 200,
            request: {
              method: 'GET',
              url: `https://target-${inv.target_id.slice(0, 8)}.internal/baseline`,
              headers: { 'User-Agent': 'NexusHunter-InvestigationEngine/7.0' },
              body_length: 0,
              is_authenticated: false,
            },
            response: {
              status_code: 200,
              headers: { 'Content-Type': 'application/json' },
              body_snippet: '{"verified":true,"action_type":"' + pendingStep.action_type + '"}',
              body_length: 64,
              body_hash: 'sha256-inv-verified',
              content_type: 'application/json',
              response_time_ms: 45,
            },
            scope_decision: {
              is_in_scope: true,
              target_id: inv.target_id,
              evaluated_host: 'target.internal',
              rule_matched: 'STRICT_SCOPE_ALLOWLIST',
              reason: 'Authorized investigation step probe',
              evaluated_at: new Date().toISOString(),
            },
            redaction_status: {
              is_redacted: false,
              redacted_fields: [],
              sanitized_at: new Date().toISOString(),
            },
            sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            provenance: {
              source: 'CONTROLLED_VALIDATION',
              operation_id: inv.id,
              target_id: inv.target_id,
              asset_id: inv.asset_id,
              captured_at: new Date().toISOString(),
              initiator: 'InvestigationEngine',
            },
          });

          // Check if all steps completed
          const remainingPending = inv.steps?.some((s: any) => s.status === 'PENDING');
          if (!remainingPending) {
            inv.status = 'COMPLETED';
            inv.falsification_result = 'CONFIRMED_VIOLATION';
          }
          inv.updated_at = new Date().toISOString();
          res.statusCode = 200;
          return res.end(JSON.stringify(inv));
        }

        // 62. GET & POST /api/assets/:id/trust-boundaries
        const tbMatch = url.match(/^\/api\/assets\/([^\/?]+)\/trust-boundaries(\?.*)?$/);
        if (tbMatch && req.method === 'GET') {
          const assetId = tbMatch[1];
          const list = trustBoundariesStore.filter((t) => t.asset_id === assetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(list));
        }

        // 63. GET & POST /api/assets/:id/permission-matrix
        const pmMatch = url.match(/^\/api\/assets\/([^\/?]+)\/permission-matrix(\?.*)?$/);
        if (pmMatch) {
          const assetId = pmMatch[1];
          if (req.method === 'GET') {
            const list = permissionMatrixStore.filter((p) => p.asset_id === assetId);
            res.statusCode = 200;
            return res.end(JSON.stringify(list));
          }
          if (req.method === 'POST') {
            const body = await readBody();
            const newEntry = {
              id: `pm-${Date.now().toString(36)}`,
              asset_id: assetId,
              endpoint: body.endpoint || '/api',
              role: body.role || 'USER',
              expected_access: body.expected_access || 'ALLOWED',
              observed_access: body.observed_access || 'ALLOWED',
              has_anomaly: body.expected_access !== body.observed_access,
              last_verified: new Date().toISOString(),
            };
            permissionMatrixStore.push(newEntry);
            res.statusCode = 201;
            return res.end(JSON.stringify(newEntry));
          }
        }

        // 64. GET /api/assets/:id/security-controls
        const scMatch = url.match(/^\/api\/assets\/([^\/?]+)\/security-controls(\?.*)?$/);
        if (scMatch && req.method === 'GET') {
          const assetId = scMatch[1];
          const list = securityControlsStore.filter((s) => s.asset_id === assetId);
          res.statusCode = 200;
          return res.end(JSON.stringify(list));
        }

        // 65. GET & POST /api/auth-contexts
        const acMatch = url.match(/^\/api\/auth-contexts(\?.*)?$/);
        if (acMatch) {
          if (req.method === 'GET') {
            res.statusCode = 200;
            return res.end(JSON.stringify(authContextsStore));
          }
          if (req.method === 'POST') {
            const body = await readBody();
            const newAc = {
              id: `ac-${Date.now().toString(36)}`,
              target_id: body.target_id || 'tgt-alpha-001',
              name: body.name || 'Custom Context',
              auth_type: body.auth_type || 'NONE',
              headers: body.headers || {},
              is_active: true,
            };
            authContextsStore.push(newAc);
            res.statusCode = 201;
            return res.end(JSON.stringify(newAc));
          }
        }

        // 66. POST /api/reasoning/analyze (trigger reasoning cycle)
        if ((url === '/api/reasoning/analyze' || url === '/api/reasoning/cycle') && req.method === 'POST') {
          const body = await readBody();
          const targetId = body.target_id || 'tgt-alpha-001';
          const run = {
            id: `run-${Date.now().toString(36)}`,
            target_id: targetId,
            engine: 'NexusHunter-ReasoningEngine',
            engine_version: '7.0.0',
            input_count: evidenceStore.length + securityContradictionsStore.length,
            signals_count: reasoningSignalsStore.length,
            hypotheses_count: hypothesesStore.length,
            duration_ms: 142,
            status: 'SUCCESS',
            created_at: new Date().toISOString(),
          };
          res.statusCode = 200;
          return res.end(JSON.stringify(run));
        }

        // 67. POST /api/reasoning/ai-assist
        if (url === '/api/reasoning/ai-assist' && req.method === 'POST') {
          const body = await readBody();
          const resPayload = {
            hypothesis_id: body.hypothesis_id,
            reasoning_summary: 'Analysis grounded strictly in empirical evidence and falsification criteria.',
            epistemic_evaluation: 'Observed unauthenticated token issuance deviates from expected OAuth policy. However, per strict epistemic rule, absence of Authorization header validation does not conclusively prove privilege escalation until token scopes are empirically tested downstream.',
            suggested_falsifiers: [
              'Submit emitted token to /api/v1/user and record HTTP status code',
              'Verify JWKS public key signature offline',
            ],
            competing_theories: [
              'Intended guest token issuance with zero elevated permissions',
              'Internal debugging bypass deployed without WAF header filter',
            ],
            confidence_level: 'MODERATE_CONFIDENCE',
            evaluated_at: new Date().toISOString(),
          };
          res.statusCode = 200;
          return res.end(JSON.stringify(resPayload));
        }


        next();
      });
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), nexusApiPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
