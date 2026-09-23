import React, { useState, useEffect, useMemo } from 'react';
import {
  FileText,
  Shield,
  ShieldAlert,
  GitCompare,
  Fingerprint,
  Scale,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Eye,
  EyeOff,
  Filter,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Sparkles,
  Layers,
  Terminal,
  FileCode2,
  Binary,
  HelpCircle,
} from 'lucide-react';
import {
  Target,
  Evidence,
  EvidenceDiff,
  SecurityExpectation,
  SecurityContradiction,
  SecurityOutlier,
  AssetInterestSummary,
  EvidenceTimelineEvent,
  EpistemicObservationState,
  ContradictionStatus,
  EvidenceIntegrityResult,
} from '../../types';
import { api } from '../../lib/api';
import { useRuntime } from '../../context/RuntimeContext';
import { MetricCard } from '../MetricCard';
import { StatusBadge } from '../StatusBadge';
import { LoadingState } from '../LoadingState';
import { EmptyState } from '../EmptyState';

interface EvidenceIntelligenceViewProps {
  targets: Target[];
  selectedTargetId: string;
  onSelectTarget: (id: string) => void;
}

type SubTab = 'explorer' | 'diffs' | 'contradictions' | 'outliers' | 'interest' | 'timeline';

export const EvidenceIntelligenceView: React.FC<EvidenceIntelligenceViewProps> = ({
  targets,
  selectedTargetId,
  onSelectTarget,
}) => {
  const { mode, assertLiveOrThrow, showRuntimeError } = useRuntime();
  const [subTab, setSubTab] = useState<SubTab>('explorer');
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Data states
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [diffsList, setDiffsList] = useState<EvidenceDiff[]>([]);
  const [expectationsList, setExpectationsList] = useState<SecurityExpectation[]>([]);
  const [contradictionsList, setContradictionsList] = useState<SecurityContradiction[]>([]);
  const [outliersList, setOutliersList] = useState<SecurityOutlier[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<EvidenceTimelineEvent[]>([]);
  const [interestSummary, setInterestSummary] = useState<AssetInterestSummary | null>(null);

  // Detail drawers / selections
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [selectedDiff, setSelectedDiff] = useState<EvidenceDiff | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');

  // Interactive Differential Runner State
  const [diffEvidenceA, setDiffEvidenceA] = useState<string>('');
  const [diffEvidenceB, setDiffEvidenceB] = useState<string>('');
  const [filterNoise, setFilterNoise] = useState<boolean>(true);
  const [isDiffing, setIsDiffing] = useState<boolean>(false);

  // Interactive Contradiction Evaluator State
  const [evalExpectationId, setEvalExpectationId] = useState<string>('');
  const [evalObservedState, setEvalObservedState] = useState<EpistemicObservationState>('ABSENT');
  const [evalEvidenceRef, setEvalEvidenceRef] = useState<string>('');
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [evalResultNotice, setEvalResultNotice] = useState<string | null>(null);

  // Cryptographic Integrity Verification State
  const [verifyingIntegrityId, setVerifyingIntegrityId] = useState<string | null>(null);
  const [integrityResults, setIntegrityResults] = useState<Record<string, EvidenceIntegrityResult>>({});

  const handleVerifyIntegrity = async (evidenceId: string) => {
    setVerifyingIntegrityId(evidenceId);
    try {
      const res = await api.verifyEvidenceIntegrity(evidenceId);
      setIntegrityResults((prev) => ({ ...prev, [evidenceId]: res }));
    } catch (err: any) {
      console.error('Integrity audit failed:', err);
    } finally {
      setVerifyingIntegrityId(null);
    }
  };

  // Record New Evidence Modal
  const [showRecordModal, setShowRecordModal] = useState(false);
  const [recordForm, setRecordForm] = useState({
    summary: '',
    evidence_type: 'HTTP_RESPONSE',
    source: 'MANUAL_PROBE',
    url: 'https://api.example.com/v1/auth/token',
    method: 'GET',
    status_code: 200,
    headers: 'Content-Type: application/json\nAccess-Control-Allow-Origin: *',
    body: '{"status":"active"}',
  });

  const activeTarget = useMemo(
    () => targets.find((t) => t.id === selectedTargetId) || targets[0],
    [targets, selectedTargetId]
  );

  const loadAllData = async (targetId: string, silent = false) => {
    if (!targetId) return;
    if (!silent) setIsLoading(true);
    else setIsRefreshing(true);

    try {
      const [evs, diffs, exps, cons, outs, tl, interest] = await Promise.all([
        api.getTargetEvidence(targetId).catch(() => []),
        api.getTargetDiffs(targetId).catch(() => []),
        api.getTargetExpectations(targetId).catch(() => []),
        api.getTargetContradictions(targetId).catch(() => []),
        api.getTargetOutliers(targetId).catch(() => []),
        api.getEvidenceTimeline(targetId).catch(() => []),
        api.getAssetInterest(targetId, 'ast-02', 'api.example.com').catch(() => null),
      ]);

      setEvidenceList(evs || []);
      setDiffsList(diffs || []);
      setExpectationsList(exps || []);
      setContradictionsList(cons || []);
      setOutliersList(outs || []);
      setTimelineEvents(tl || []);
      setInterestSummary(interest || null);

      if (evs && evs.length >= 2) {
        setDiffEvidenceA(evs[0]?.id || '');
        setDiffEvidenceB(evs[1]?.id || '');
      }
      if (exps && exps.length > 0) {
        setEvalExpectationId(exps[0]?.id || '');
      }
      if (evs && evs.length > 0) {
        setEvalEvidenceRef(evs[0]?.id || '');
      }
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (activeTarget?.id) {
      loadAllData(activeTarget.id);
    }
  }, [activeTarget?.id]);

  // Handle Differential Comparison execution
  const handleRunDiff = async () => {
    if (!diffEvidenceA || !diffEvidenceB) return;
    setIsDiffing(true);
    try {
      assertLiveOrThrow('compute differential analysis');
      const res = await api.computeEvidenceDiff(diffEvidenceA, diffEvidenceB, filterNoise);
      if (res?.diff) {
        setDiffsList((prev) => [res.diff, ...prev]);
        setSelectedDiff(res.diff);
      }
    } catch (err: any) {
      showRuntimeError(err);
      console.error('Diff error:', err);
    } finally {
      setIsDiffing(false);
    }
  };

  // Handle Contradiction Evaluation
  const handleEvaluateContradiction = async () => {
    if (!evalExpectationId) return;
    setIsEvaluating(true);
    setEvalResultNotice(null);
    try {
      assertLiveOrThrow('evaluate security contradiction');
      const exp = expectationsList.find((e) => e.id === evalExpectationId);
      const res = await api.evaluateContradiction({
        target_id: activeTarget.id,
        asset_id: exp?.asset_id || 'ast-02',
        endpoint: exp?.endpoint || '/v1/auth/token',
        expectation: exp,
        observed_state: evalObservedState,
        evidence_refs: evalEvidenceRef ? [evalEvidenceRef] : [],
      });

      if (res?.contradiction_found && res?.contradiction) {
        setContradictionsList((prev) => [res.contradiction, ...prev]);
        setEvalResultNotice(`Contradiction confirmed and recorded: ${res.contradiction.title}`);
      } else {
        setEvalResultNotice(res?.message || 'Observed state conforms to expectation.');
      }
    } catch (err: any) {
      showRuntimeError(err);
      setEvalResultNotice(`Evaluation error: ${err.message}`);
    } finally {
      setIsEvaluating(false);
    }
  };

  // Handle Contradiction Status Update
  const handleUpdateContradictionStatus = async (id: string, status: ContradictionStatus) => {
    try {
      assertLiveOrThrow('update contradiction status');
      const res = await api.updateContradictionStatus(id, status);
      if (res?.contradiction) {
        setContradictionsList((prev) =>
          prev.map((c) => (c.id === id ? res.contradiction : c))
        );
      }
    } catch (err: any) {
      showRuntimeError(err);
      console.error('Failed to update contradiction status:', err);
    }
  };

  // Handle Record New Evidence
  const handleCreateEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recordForm.summary) return;

    let parsedHeaders: Record<string, string> = {};
    recordForm.headers.split('\n').forEach((line) => {
      const parts = line.split(':');
      if (parts.length >= 2) {
        parsedHeaders[parts[0].trim()] = parts.slice(1).join(':').trim();
      }
    });

    const payload = {
      target_id: activeTarget.id,
      asset_id: 'ast-02',
      source: recordForm.source,
      evidence_type: recordForm.evidence_type,
      summary: recordForm.summary,
      status_code: Number(recordForm.status_code),
      request: {
        method: recordForm.method,
        url: recordForm.url,
        headers: {
          'User-Agent': 'NexusHunter-Engine/6.0',
          Authorization: '[REDACTED_SECRET]',
        },
        body_length: 0,
        is_authenticated: false,
      },
      response: {
        status_code: Number(recordForm.status_code),
        headers: parsedHeaders,
        body_snippet: recordForm.body,
        body_length: recordForm.body.length,
        body_hash: 'sha256-demo-' + Math.random().toString(16).substring(2, 10),
        content_type: parsedHeaders['Content-Type'] || 'application/json',
        response_time_ms: 95,
      },
      relevant_headers: parsedHeaders,
    };

    try {
      assertLiveOrThrow('record evidence');
      const res = await api.recordEvidence(payload);
      if (res?.evidence) {
        setEvidenceList((prev) => [res.evidence, ...prev]);
        setShowRecordModal(false);
        setRecordForm({
          summary: '',
          evidence_type: 'HTTP_RESPONSE',
          source: 'MANUAL_PROBE',
          url: 'https://api.example.com/v1/auth/token',
          method: 'GET',
          status_code: 200,
          headers: 'Content-Type: application/json\nAccess-Control-Allow-Origin: *',
          body: '{"status":"active"}',
        });
      }
    } catch (err: any) {
      showRuntimeError(err);
      console.error('Failed to record evidence:', err);
    }
  };

  const filteredEvidence = useMemo(() => {
    return evidenceList.filter((ev) => {
      const matchesSearch =
        ev.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        ev.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (ev.request?.url && ev.request.url.toLowerCase().includes(searchQuery.toLowerCase()));
      const matchesType = filterType === 'ALL' || ev.evidence_type === filterType;
      return matchesSearch && matchesType;
    });
  }, [evidenceList, searchQuery, filterType]);

  return (
    <div className="space-y-6">
      {/* Top Header & Epistemic Rule Banner */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Evidence Intelligence & Reasoning
            </h1>
            <span className="rounded bg-indigo-500/20 px-2 py-0.5 text-xs font-semibold text-indigo-400 border border-indigo-500/30">
              Phase 6
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Cryptographic SHA-256 provenance, 3-level comparative differentials, and deterministic contradiction detection.
          </p>
        </div>

        {/* Target Selector & Refresh */}
        <div className="flex items-center gap-3">
          <select
            value={activeTarget?.id || ''}
            onChange={(e) => onSelectTarget(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-indigo-500 focus:outline-hidden"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.root_domain})
              </option>
            ))}
          </select>

          <button
            onClick={() => activeTarget && loadAllData(activeTarget.id, true)}
            disabled={isRefreshing}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800 focus:outline-hidden"
            title="Refresh Evidence Store"
          >
            <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin text-indigo-400' : ''}`} />
            <span className="hidden sm:inline">Refresh</span>
          </button>

          <button
            onClick={() => setShowRecordModal(true)}
            className="flex items-center gap-2 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500 focus:outline-hidden shadow-xs"
          >
            <FileText className="h-4 w-4" />
            <span>Record Evidence</span>
          </button>
        </div>
      </div>

      {/* Epistemic Discipline Mandate Card */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4 text-xs text-amber-200/90 leading-relaxed shadow-xs">
        <div className="flex items-center gap-2 font-semibold text-amber-300 mb-1">
          <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
          <span>Epistemic Discipline Protocol & Evidence Trust Architecture</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-2 text-slate-300">
          <div className="rounded border border-slate-800/80 bg-slate-900/60 p-2.5">
            <span className="font-semibold text-indigo-300 block mb-0.5">Strict Epistemic Classification</span>
            Observations are strictly distinguished: <code className="text-amber-300">OBSERVED</code>, <code className="text-cyan-300">DERIVED</code>, and <code className="text-rose-300">HYPOTHESIZED</code>. Hypotheses are never rendered as confirmed vulnerabilities.
          </div>
          <div className="rounded border border-slate-800/80 bg-slate-900/60 p-2.5">
            <span className="font-semibold text-emerald-300 block mb-0.5">Cryptographic Integrity</span>
            Every piece of evidence is canonicalized via deterministic key sorting and hashed with SHA-256 after automated PII/credential sanitization.
          </div>
          <div className="rounded border border-slate-800/80 bg-slate-900/60 p-2.5">
            <span className="font-semibold text-violet-300 block mb-0.5">Contradiction vs Silence</span>
            Absence of an observation (<code className="text-amber-300">NOT_OBSERVED</code>) is never equated with affirmative absence (<code className="text-rose-300">ABSENT</code>), preventing speculative false-positive alerts.
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Evidence Records"
          value={evidenceList.length}
          subtitle="Sanitized & SHA-256 Fingerprinted"
          icon={Fingerprint}
        />
        <MetricCard
          title="Security Contradictions"
          value={contradictionsList.length}
          subtitle="Model Expectations Violated"
          icon={Scale}
        />
        <MetricCard
          title="Comparative Diffs"
          value={diffsList.length}
          subtitle="3-Level Structural & Semantic"
          icon={GitCompare}
        />
        <MetricCard
          title="Peer Outliers"
          value={outliersList.length}
          subtitle="Behavioral Baseline Deviations"
          icon={AlertTriangle}
        />
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setSubTab('explorer')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            subTab === 'explorer'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="h-4 w-4" />
          <span>Evidence Explorer</span>
          <span className="ml-1.5 rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
            {evidenceList.length}
          </span>
        </button>

        <button
          onClick={() => setSubTab('diffs')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            subTab === 'diffs'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitCompare className="h-4 w-4" />
          <span>3-Level Differential Engine</span>
          <span className="ml-1.5 rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
            {diffsList.length}
          </span>
        </button>

        <button
          onClick={() => setSubTab('contradictions')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            subTab === 'contradictions'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Scale className="h-4 w-4" />
          <span>Contradiction Detector</span>
          <span className="ml-1.5 rounded-full bg-rose-500/20 text-rose-300 px-2 py-0.5 text-xs border border-rose-500/30">
            {contradictionsList.length}
          </span>
        </button>

        <button
          onClick={() => setSubTab('outliers')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            subTab === 'outliers'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="h-4 w-4" />
          <span>Peer Outliers</span>
          <span className="ml-1.5 rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
            {outliersList.length}
          </span>
        </button>

        <button
          onClick={() => setSubTab('interest')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            subTab === 'interest'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sparkles className="h-4 w-4" />
          <span>Asset Synthesis</span>
        </button>

        <button
          onClick={() => setSubTab('timeline')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            subTab === 'timeline'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Clock className="h-4 w-4" />
          <span>Evidence Timeline</span>
          <span className="ml-1.5 rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
            {timelineEvents.length}
          </span>
        </button>
      </div>

      {/* View Content */}
      {isLoading ? (
        <LoadingState message="Loading Evidence Intelligence & Reasoning Data..." />
      ) : (
        <>
          {/* TAB 1: EVIDENCE EXPLORER */}
          {subTab === 'explorer' && (
            <div className="space-y-4">
              {/* Search and Filters */}
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search by summary, URL, or SHA-256 hash..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full rounded-md border border-slate-700 bg-slate-950 py-2 pl-9 pr-4 text-sm text-slate-200 placeholder-slate-500 focus:border-indigo-500 focus:outline-hidden"
                  />
                </div>

                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4 text-slate-400" />
                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                  >
                    <option value="ALL">All Evidence Types</option>
                    <option value="HTTP_RESPONSE">HTTP Response</option>
                    <option value="HTTP_REQUEST">HTTP Request</option>
                    <option value="TLS_OBSERVATION">TLS Observation</option>
                    <option value="DNS_OBSERVATION">DNS Observation</option>
                    <option value="STATE_TRANSITION">State Transition</option>
                    <option value="DIFFERENTIAL_RESULT">Differential Result</option>
                  </select>
                </div>
              </div>

              {filteredEvidence.length === 0 ? (
                <EmptyState
                  title="No Evidence Records Found"
                  description="No evidence records matched your active query. Record new evidence or execute recon jobs to capture live telemetry."
                  action={{
                    label: 'Record Evidence',
                    onClick: () => setShowRecordModal(true),
                  }}
                />
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {filteredEvidence.map((ev) => (
                    <div
                      key={ev.id}
                      className={`rounded-xl border transition-all p-5 ${
                        selectedEvidence?.id === ev.id
                          ? 'border-indigo-500 bg-slate-900/90 shadow-md'
                          : 'border-slate-800 bg-slate-950 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                        <div className="space-y-1.5 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded bg-indigo-950/80 border border-indigo-700/50 px-2 py-0.5 text-xs font-semibold text-indigo-300">
                              {ev.evidence_type}
                            </span>
                            <span className="rounded bg-slate-800/80 px-2 py-0.5 text-xs text-slate-400">
                              {ev.source}
                            </span>
                            {ev.status_code && (
                              <span
                                className={`rounded px-2 py-0.5 text-xs font-mono font-semibold ${
                                  ev.status_code < 300
                                    ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40'
                                    : ev.status_code < 400
                                    ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/40'
                                    : ev.status_code < 500
                                    ? 'bg-amber-950/60 text-amber-300 border border-amber-800/40'
                                    : 'bg-rose-950/60 text-rose-300 border border-rose-800/40'
                                }`}
                              >
                                HTTP {ev.status_code}
                              </span>
                            )}
                            {ev.redaction_status?.is_redacted && (
                              <span className="flex items-center gap-1 rounded bg-amber-950/40 border border-amber-800/30 px-2 py-0.5 text-xs text-amber-300">
                                <Lock className="h-3 w-3" />
                                <span>Sanitized ({ev.redaction_status.redacted_fields.length} redacted)</span>
                              </span>
                            )}
                            {ev.scope_decision?.is_in_scope && (
                              <span className="flex items-center gap-1 rounded bg-emerald-950/40 border border-emerald-800/30 px-2 py-0.5 text-xs text-emerald-300">
                                <CheckCircle2 className="h-3 w-3" />
                                <span>In-Scope Verified</span>
                              </span>
                            )}
                          </div>

                          <h3 className="text-base font-semibold text-white">{ev.summary}</h3>

                          {ev.request?.url && (
                            <p className="text-xs font-mono text-slate-300 bg-slate-900/80 p-1.5 rounded border border-slate-800 inline-block">
                              <span className="font-bold text-indigo-400">{ev.request.method || 'GET'}</span> {ev.request.url}
                            </p>
                          )}
                        </div>

                        {/* Fingerprint & Timestamp */}
                        <div className="flex flex-col md:items-end gap-1.5 text-xs text-slate-400 shrink-0">
                          <div className="flex items-center gap-1.5">
                            <Fingerprint className="h-3.5 w-3.5 text-indigo-400" />
                            <span className="font-mono text-slate-300">
                              {ev.sha256 ? `${ev.sha256.substring(0, 16)}...` : 'N/A'}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <Clock className="h-3.5 w-3.5 text-slate-500" />
                            <span>{new Date(ev.captured_at).toLocaleString()}</span>
                          </div>
                          <button
                            onClick={() => setSelectedEvidence(selectedEvidence?.id === ev.id ? null : ev)}
                            className="mt-2 text-xs font-medium text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                          >
                            <span>{selectedEvidence?.id === ev.id ? 'Collapse Inspection' : 'Inspect Provenance & Payloads'}</span>
                            {selectedEvidence?.id === ev.id ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                          </button>
                        </div>
                      </div>

                      {/* Expandable Technical Drawer */}
                      {selectedEvidence?.id === ev.id && (
                        <div className="mt-5 space-y-4 border-t border-slate-800/80 pt-4 text-xs">
                          {/* Provenance and Scope Validation */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                              <span className="font-semibold text-slate-300 block mb-1">Provenance Tracking</span>
                              <div className="space-y-1 text-slate-400">
                                <div><strong className="text-slate-300">Operation ID:</strong> {ev.provenance?.operation_id || 'N/A'}</div>
                                <div><strong className="text-slate-300">Initiator:</strong> {ev.provenance?.initiator || 'N/A'}</div>
                                <div><strong className="text-slate-300">Captured At:</strong> {ev.provenance?.captured_at}</div>
                                {ev.provenance?.notes && <div><strong className="text-slate-300">Notes:</strong> {ev.provenance.notes}</div>}
                              </div>
                            </div>

                            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                              <span className="font-semibold text-slate-300 block mb-1">Scope Compliance Decision</span>
                              <div className="space-y-1 text-slate-400">
                                <div><strong className="text-slate-300">Evaluated Host:</strong> {ev.scope_decision?.evaluated_host}</div>
                                <div><strong className="text-slate-300">Matched Rule:</strong> {ev.scope_decision?.rule_matched}</div>
                                <div><strong className="text-slate-300">Compliance Reason:</strong> {ev.scope_decision?.reason}</div>
                                <div><strong className="text-slate-300">Evaluated At:</strong> {ev.scope_decision?.evaluated_at}</div>
                              </div>
                            </div>
                          </div>

                          {/* HTTP Request & Response Details */}
                          {ev.response && (
                            <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3 space-y-3">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-slate-200">HTTP Response Inspection</span>
                                <span className="text-slate-400">Latency: {ev.response.response_time_ms}ms | Body: {ev.response.body_length} bytes</span>
                              </div>

                              {/* Response Headers */}
                              {ev.response.headers && Object.keys(ev.response.headers).length > 0 && (
                                <div>
                                  <span className="text-slate-400 font-semibold block mb-1">Headers (Sanitized):</span>
                                  <pre className="overflow-x-auto rounded bg-slate-950 p-2 text-slate-300 font-mono text-[11px] border border-slate-800">
                                    {Object.entries(ev.response.headers).map(([k, v]) => `${k}: ${v}\n`)}
                                  </pre>
                                </div>
                              )}

                              {/* Body Snippet */}
                              {ev.response.body_snippet && (
                                <div>
                                  <span className="text-slate-400 font-semibold block mb-1">Body Snippet:</span>
                                  <pre className="overflow-x-auto rounded bg-slate-950 p-2 text-slate-300 font-mono text-[11px] border border-slate-800">
                                    {ev.response.body_snippet}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}

                          {/* TLS Metadata if present */}
                          {ev.tls_metadata && (
                            <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3 space-y-1">
                              <span className="font-semibold text-slate-200 block mb-1">TLS Parameters</span>
                              <div className="grid grid-cols-2 gap-2 text-slate-400">
                                <div><strong className="text-slate-300">Version:</strong> {ev.tls_metadata.version}</div>
                                <div><strong className="text-slate-300">Cipher:</strong> {ev.tls_metadata.cipher_suite}</div>
                                <div><strong className="text-slate-300">Subject:</strong> {ev.tls_metadata.subject}</div>
                                <div><strong className="text-slate-300">Issuer:</strong> {ev.tls_metadata.issuer}</div>
                                <div><strong className="text-slate-300">SANs:</strong> {ev.tls_metadata.sans?.join(', ')}</div>
                                <div><strong className="text-slate-300">Expires:</strong> {ev.tls_metadata.valid_until}</div>
                              </div>
                            </div>
                          )}

                          {/* Full SHA-256 Hash & Canonical Representation */}
                          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-3">
                            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                              <div>
                                <span className="font-semibold text-slate-300 block">Deterministic SHA-256 Canonical Fingerprint</span>
                                <span className="text-indigo-400 font-mono text-[11px] break-all">{ev.sha256}</span>
                              </div>
                              <button
                                onClick={() => handleVerifyIntegrity(ev.id)}
                                disabled={verifyingIntegrityId === ev.id}
                                className="inline-flex items-center gap-1.5 self-start sm:self-center rounded-md bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/60 px-2.5 py-1 text-xs font-medium text-indigo-300 transition-colors disabled:opacity-50"
                              >
                                <Shield className={`h-3.5 w-3.5 ${verifyingIntegrityId === ev.id ? 'animate-spin' : ''}`} />
                                <span>{verifyingIntegrityId === ev.id ? 'Auditing Hash...' : 'Audit Cryptographic Integrity'}</span>
                              </button>
                            </div>

                            {/* Cryptographic Integrity Result Card */}
                            {integrityResults[ev.id] && (
                              <div
                                className={`rounded-md p-2.5 text-xs border ${
                                  integrityResults[ev.id].is_tampered
                                    ? 'bg-rose-950/40 border-rose-800/60 text-rose-300'
                                    : 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                                }`}
                              >
                                <div className="flex items-start gap-2">
                                  {integrityResults[ev.id].is_tampered ? (
                                    <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
                                  ) : (
                                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
                                  )}
                                  <div className="space-y-1">
                                    <div className="font-semibold">
                                      {integrityResults[ev.id].is_tampered
                                        ? 'TAMPERING DETECTED: Computed hash does not match original stored record!'
                                        : 'Cryptographic Integrity Confirmed: Canonical SHA-256 matches stored record.'}
                                    </div>
                                    <div className="font-mono text-[11px] text-slate-400">
                                      <div>Stored: {integrityResults[ev.id].original_sha256}</div>
                                      <div>Computed: {integrityResults[ev.id].computed_sha256}</div>
                                      <div className="text-[10px] text-slate-500 mt-0.5">
                                        Audited at {new Date(integrityResults[ev.id].verified_at).toLocaleTimeString()}
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}

                            {ev.canonical_representation && (
                              <details className="text-slate-400 pt-1 border-t border-slate-800/60">
                                <summary className="cursor-pointer hover:text-slate-200 text-xs text-indigo-400">View Canonical JSON Payload</summary>
                                <pre className="mt-2 overflow-x-auto rounded bg-slate-900 p-2 text-slate-300 font-mono text-[10px]">
                                  {ev.canonical_representation}
                                </pre>
                              </details>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: 3-LEVEL DIFFERENTIAL ENGINE */}
          {subTab === 'diffs' && (
            <div className="space-y-6">
              {/* Interactive Differential Comparator Form */}
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <GitCompare className="h-5 w-5 text-indigo-400" />
                    <h3 className="text-base font-semibold text-white">Execute Comparative Differential</h3>
                  </div>
                  <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={filterNoise}
                      onChange={(e) => setFilterNoise(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-900 text-indigo-600 focus:ring-0"
                    />
                    <span>Filter Dynamic Noise (Timestamps, Session IDs, CSRF)</span>
                  </label>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">Baseline Context (Evidence A)</label>
                    <select
                      value={diffEvidenceA}
                      onChange={(e) => setDiffEvidenceA(e.target.value)}
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                    >
                      <option value="">Select Evidence A...</option>
                      {evidenceList.map((e) => (
                        <option key={e.id} value={e.id}>
                          [{e.id}] {e.summary.substring(0, 60)}...
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">Comparative Context (Evidence B)</label>
                    <select
                      value={diffEvidenceB}
                      onChange={(e) => setDiffEvidenceB(e.target.value)}
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                    >
                      <option value="">Select Evidence B...</option>
                      {evidenceList.map((e) => (
                        <option key={e.id} value={e.id}>
                          [{e.id}] {e.summary.substring(0, 60)}...
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={handleRunDiff}
                    disabled={isDiffing || !diffEvidenceA || !diffEvidenceB}
                    className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 focus:outline-hidden disabled:opacity-50"
                  >
                    <GitCompare className={`h-4 w-4 ${isDiffing ? 'animate-spin' : ''}`} />
                    <span>{isDiffing ? 'Computing 3-Level Diff...' : 'Compute Differential'}</span>
                  </button>
                </div>
              </div>

              {/* Diffs List */}
              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-slate-300">Computed Comparative Differentials</h3>
                {diffsList.length === 0 ? (
                  <EmptyState
                    title="No Differentials Computed"
                    description="Select two evidence items above and compute a differential to analyze raw, semantic, and security differences."
                  />
                ) : (
                  diffsList.map((diff) => (
                    <div
                      key={diff.id}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4 hover:border-slate-700"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-indigo-400 font-semibold">{diff.id}</span>
                          <span className="text-slate-400 text-xs">
                            Comparing <strong className="text-slate-200">{diff.evidence_a_id}</strong> vs{' '}
                            <strong className="text-slate-200">{diff.evidence_b_id}</strong>
                          </span>
                          {diff.is_security_relevant && (
                            <span className="rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 px-2 py-0.5 text-xs font-semibold">
                              Security Relevant
                            </span>
                          )}
                        </div>
                        <span className="text-xs text-slate-500">
                          {new Date(diff.computed_at).toLocaleString()}
                        </span>
                      </div>

                      {/* 3-Level Cards */}
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        {/* Level 1: Raw Structural */}
                        <div className="rounded-lg border border-slate-800/90 bg-slate-900/50 p-4 space-y-2">
                          <div className="flex items-center gap-1.5 text-indigo-400 font-semibold text-xs uppercase tracking-wider">
                            <Binary className="h-3.5 w-3.5" />
                            <span>Level 1: Raw Structural Diff</span>
                          </div>
                          <div className="text-xs text-slate-300 space-y-1">
                            <div>
                              Status:{' '}
                              <span className="font-mono text-slate-200">
                                {diff.raw_diff.status_from} → {diff.raw_diff.status_to}
                              </span>{' '}
                              ({diff.raw_diff.status_changed ? 'Changed' : 'Unchanged'})
                            </div>
                            <div>
                              Body Length Delta:{' '}
                              <span className="font-mono text-slate-200">
                                {diff.raw_diff.body_length_delta > 0 ? `+${diff.raw_diff.body_length_delta}` : diff.raw_diff.body_length_delta} bytes
                              </span>
                            </div>
                            <div>
                              Response Latency Delta:{' '}
                              <span className="font-mono text-slate-200">{diff.raw_diff.response_time_delta_ms}ms</span>
                            </div>
                            {diff.raw_diff.added_headers && Object.keys(diff.raw_diff.added_headers).length > 0 && (
                              <div className="pt-1">
                                <span className="text-emerald-400 font-semibold block">Added Headers:</span>
                                <pre className="text-[10px] text-emerald-300 font-mono bg-slate-950 p-1.5 rounded mt-0.5">
                                  {Object.entries(diff.raw_diff.added_headers).map(([k, v]) => `${k}: ${v}\n`)}
                                </pre>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Level 2: Semantic Diff */}
                        <div className="rounded-lg border border-slate-800/90 bg-slate-900/50 p-4 space-y-2">
                          <div className="flex items-center gap-1.5 text-cyan-400 font-semibold text-xs uppercase tracking-wider">
                            <Layers className="h-3.5 w-3.5" />
                            <span>Level 2: Semantic State Diff</span>
                          </div>
                          <div className="text-xs text-slate-300 space-y-1.5">
                            <div>
                              Category: <span className="font-semibold text-cyan-300">{diff.semantic_diff.category}</span>
                            </div>
                            <p className="text-slate-400 text-xs leading-relaxed">{diff.semantic_diff.meaning}</p>
                            <div className="flex flex-wrap gap-1.5 pt-1">
                              {diff.semantic_diff.auth_behavior_changed && (
                                <span className="rounded bg-rose-950/60 text-rose-300 border border-rose-800/40 px-1.5 py-0.5 text-[10px]">
                                  Auth State Shifted
                                </span>
                              )}
                              {diff.semantic_diff.content_type_changed && (
                                <span className="rounded bg-amber-950/60 text-amber-300 border border-amber-800/40 px-1.5 py-0.5 text-[10px]">
                                  MIME Transition
                                </span>
                              )}
                              {diff.semantic_diff.state_transition_detected && (
                                <span className="rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/40 px-1.5 py-0.5 text-[10px]">
                                  Boundary Cross
                                </span>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Level 3: Security-Relevant Diff */}
                        <div className="rounded-lg border border-slate-800/90 bg-slate-900/50 p-4 space-y-2">
                          <div className="flex items-center gap-1.5 text-rose-400 font-semibold text-xs uppercase tracking-wider">
                            <Shield className="h-3.5 w-3.5" />
                            <span>Level 3: Security Relevance</span>
                          </div>
                          <div className="text-xs text-slate-300 space-y-1.5">
                            <p className="text-slate-300 text-xs leading-relaxed font-medium">
                              {diff.security_diff.relevance_explanation}
                            </p>
                            {diff.security_diff.suggested_questions?.length > 0 && (
                              <div className="pt-1">
                                <span className="text-slate-400 font-semibold block mb-0.5">Researcher Questions:</span>
                                <ul className="list-disc pl-4 text-slate-400 space-y-0.5 text-[11px]">
                                  {diff.security_diff.suggested_questions.map((q, idx) => (
                                    <li key={idx}>{q}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 3: CONTRADICTION DETECTOR */}
          {subTab === 'contradictions' && (
            <div className="space-y-6">
              {/* Contradiction Evaluator Interactive Box */}
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
                <div className="flex items-center gap-2">
                  <Scale className="h-5 w-5 text-indigo-400" />
                  <h3 className="text-base font-semibold text-white">Evaluate Security Model Contradiction</h3>
                </div>
                <p className="text-xs text-slate-400">
                  Contrast a registered Security Expectation (explicit policy or peer baseline) against an observed state. Note: <code className="text-amber-300">NOT_OBSERVED</code> is epistemically distinct from <code className="text-rose-300">ABSENT</code>.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">Security Expectation</label>
                    <select
                      value={evalExpectationId}
                      onChange={(e) => setEvalExpectationId(e.target.value)}
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                    >
                      {expectationsList.map((exp) => (
                        <option key={exp.id} value={exp.id}>
                          {exp.control_name} ({exp.source})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">Observed Epistemic State</label>
                    <select
                      value={evalObservedState}
                      onChange={(e) => setEvalObservedState(e.target.value as EpistemicObservationState)}
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                    >
                      <option value="ABSENT">ABSENT (Affirmatively missing/bypassed)</option>
                      <option value="NOT_OBSERVED">NOT_OBSERVED (Not detected; silent)</option>
                      <option value="PRESENT">PRESENT (Control active)</option>
                      <option value="UNKNOWN">UNKNOWN (Indeterminate)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">Grounding Evidence Ref</label>
                    <select
                      value={evalEvidenceRef}
                      onChange={(e) => setEvalEvidenceRef(e.target.value)}
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                    >
                      {evidenceList.map((ev) => (
                        <option key={ev.id} value={ev.id}>
                          [{ev.id}] {ev.summary.substring(0, 40)}...
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {evalResultNotice && (
                  <div className="rounded-lg border border-indigo-500/30 bg-indigo-950/20 p-3 text-xs text-indigo-300">
                    {evalResultNotice}
                  </div>
                )}

                <div className="flex justify-end">
                  <button
                    onClick={handleEvaluateContradiction}
                    disabled={isEvaluating}
                    className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 focus:outline-hidden disabled:opacity-50"
                  >
                    <Scale className={`h-4 w-4 ${isEvaluating ? 'animate-spin' : ''}`} />
                    <span>{isEvaluating ? 'Evaluating Model...' : 'Evaluate Contradiction'}</span>
                  </button>
                </div>
              </div>

              {/* Contradictions List */}
              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-slate-300">Active Security Contradictions</h3>
                {contradictionsList.length === 0 ? (
                  <EmptyState
                    title="No Contradictions Observed"
                    description="All evaluated endpoints and services conform to the expected security model."
                  />
                ) : (
                  contradictionsList.map((con) => (
                    <div
                      key={con.id}
                      className="rounded-xl border border-rose-900/40 bg-slate-950 p-5 space-y-3 hover:border-rose-700/60 transition-all"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-rose-950/80 border border-rose-800/40 text-rose-300 px-2 py-0.5 text-xs font-semibold">
                            {con.contradiction_type}
                          </span>
                          <span
                            className={`rounded px-2 py-0.5 text-xs font-semibold ${
                              con.severity === 'HIGH' || con.severity === 'CRITICAL'
                                ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {con.severity}
                          </span>
                          <span className="text-xs font-mono text-slate-400">Endpoint: {con.endpoint || 'Global'}</span>
                        </div>

                        {/* Status update buttons */}
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs text-slate-400 mr-1">Status:</span>
                          {(['INVESTIGATING', 'CONFIRMED_DEVIATION', 'DISMISSED'] as ContradictionStatus[]).map(
                            (st) => (
                              <button
                                key={st}
                                onClick={() => handleUpdateContradictionStatus(con.id, st)}
                                className={`rounded px-2 py-1 text-[11px] font-medium transition-colors ${
                                  con.status === st
                                    ? 'bg-indigo-600 text-white'
                                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                                }`}
                              >
                                {st}
                              </button>
                            )
                          )}
                        </div>
                      </div>

                      <h4 className="text-base font-semibold text-white">{con.title}</h4>
                      <p className="text-xs text-slate-300 leading-relaxed">{con.description}</p>

                      <div className="rounded-lg bg-slate-900/80 p-3 text-xs text-slate-400 space-y-1.5 border border-slate-800">
                        <div>
                          <strong className="text-slate-300">Deterministic Explanation:</strong> {con.explanation}
                        </div>
                        <div>
                          <strong className="text-slate-300">Grounding Evidence References:</strong>{' '}
                          {con.evidence_refs?.map((ref) => (
                            <span key={ref} className="font-mono text-indigo-400 mr-2">
                              {ref}
                            </span>
                          ))}
                        </div>
                        {con.suggested_followup && con.suggested_followup.length > 0 && (
                          <div className="pt-1">
                            <strong className="text-slate-300 block mb-0.5">Recommended Follow-Up Steps:</strong>
                            <ul className="list-disc pl-4 text-slate-400 space-y-0.5 text-[11px]">
                              {con.suggested_followup.map((f, i) => (
                                <li key={i}>{f}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 4: PEER OUTLIERS */}
          {subTab === 'outliers' && (
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-slate-300">Peer Cohort Behavioral Outliers</h3>
              <p className="text-xs text-slate-400">
                Services and endpoints exhibiting statistically significant policy or behavioral deviations from target peer groups.
              </p>

              {outliersList.length === 0 ? (
                <EmptyState
                  title="No Peer Outliers Identified"
                  description="All services in the target scope match homogeneous configuration baselines."
                />
              ) : (
                outliersList.map((out) => (
                  <div
                    key={out.id}
                    className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-3 hover:border-slate-700"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 text-xs font-semibold">
                          {out.deviation_type}
                        </span>
                        <span className="text-xs text-slate-400">Group: {out.comparison_group}</span>
                      </div>
                      <span className="text-xs font-mono text-slate-400">
                        Confidence: {(out.confidence * 100).toFixed(0)}%
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs pt-2">
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <span className="text-slate-400 font-semibold block mb-1">Cohort Baseline Value:</span>
                        <div className="font-mono text-slate-200">{out.baseline_value}</div>
                      </div>

                      <div className="rounded-lg border border-rose-900/40 bg-rose-950/20 p-3">
                        <span className="text-rose-300 font-semibold block mb-1">Observed Outlier Value:</span>
                        <div className="font-mono text-rose-200">{out.observed_value}</div>
                      </div>
                    </div>

                    {out.details && (
                      <div className="text-xs text-slate-400 bg-slate-900/40 p-2.5 rounded border border-slate-800">
                        {out.details.notes || JSON.stringify(out.details)}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* TAB 5: WHY IS THIS INTERESTING? ASSET SYNTHESIS */}
          {subTab === 'interest' && (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-5 w-5 text-indigo-400" />
                    <div>
                      <h3 className="text-base font-semibold text-white">
                        Asset Curiosity Synthesis: {interestSummary?.hostname || 'api.example.com'}
                      </h3>
                      <p className="text-xs text-slate-400">
                        Multi-factor deterministic synthesis explaining why this asset warrants deep security research attention.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Curiosity Score:</span>
                    <span className="rounded-lg bg-indigo-600 px-3 py-1 text-sm font-bold text-white shadow-xs">
                      {interestSummary?.score || 88} / 100
                    </span>
                  </div>
                </div>

                <div className="space-y-3 pt-2">
                  {interestSummary?.reasons?.map((r, i) => (
                    <div
                      key={i}
                      className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-semibold text-indigo-300">{r.factor_name}</span>
                        <span className="text-xs font-semibold text-slate-400">Weight: +{r.weight}pts</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{r.description}</p>
                      <div className="text-[11px] text-slate-400 pt-1">
                        Linked Evidence:{' '}
                        {r.evidence_refs?.map((ref) => (
                          <span key={ref} className="font-mono text-indigo-400 mr-2">
                            {ref}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: EVIDENCE TIMELINE */}
          {subTab === 'timeline' && (
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-slate-300">Unified Evidence Chronological Stream</h3>
              <p className="text-xs text-slate-400">
                Audited timeline tracking every piece of evidence, differential, state transition, and contradiction.
              </p>

              <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                {timelineEvents.map((evt) => (
                  <div key={evt.id} className="relative group">
                    {/* Timeline Node Dot */}
                    <div className="absolute -left-6 top-1.5 h-3.5 w-3.5 rounded-full border-2 border-slate-950 bg-indigo-500" />

                    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-1.5 hover:border-slate-700 transition-colors">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-300">
                            {evt.event_type}
                          </span>
                          <span
                            className={`rounded px-2 py-0.5 text-[11px] font-semibold ${
                              evt.epistemic_status === 'OBSERVED'
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                : evt.epistemic_status === 'DERIVED'
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                                : evt.epistemic_status === 'CONFIRMED_DEVIATION'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {evt.epistemic_status}
                          </span>
                          {evt.reference_id && (
                            <span className="font-mono text-xs text-indigo-400">
                              Ref: {evt.reference_id}
                            </span>
                          )}
                        </div>
                        <span className="text-xs text-slate-500">
                          {new Date(evt.timestamp).toLocaleString()}
                        </span>
                      </div>

                      <p className="text-xs text-slate-200">{evt.summary}</p>
                      <div className="text-[11px] text-slate-400">
                        Initiator: <span className="text-slate-300">{evt.provenance?.initiator}</span> | Source: {evt.provenance?.source}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Record Evidence Modal */}
      {showRecordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-950 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-indigo-400" />
                <h3 className="text-lg font-bold text-white">Record Structured Evidence</h3>
              </div>
              <button
                onClick={() => setShowRecordModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateEvidence} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Summary Description</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. GET /v1/auth/token permits unauthenticated origin reflection"
                  value={recordForm.summary}
                  onChange={(e) => setRecordForm({ ...recordForm, summary: e.target.value })}
                  className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Evidence Type</label>
                  <select
                    value={recordForm.evidence_type}
                    onChange={(e) => setRecordForm({ ...recordForm, evidence_type: e.target.value })}
                    className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                  >
                    <option value="HTTP_RESPONSE">HTTP Response</option>
                    <option value="HTTP_REQUEST">HTTP Request</option>
                    <option value="TLS_OBSERVATION">TLS Observation</option>
                    <option value="STATE_TRANSITION">State Transition</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">HTTP Status Code</label>
                  <input
                    type="number"
                    value={recordForm.status_code}
                    onChange={(e) => setRecordForm({ ...recordForm, status_code: Number(e.target.value) })}
                    className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Target Endpoint URL</label>
                <input
                  type="text"
                  value={recordForm.url}
                  onChange={(e) => setRecordForm({ ...recordForm, url: e.target.value })}
                  className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Headers (Newline separated)</label>
                <textarea
                  rows={3}
                  value={recordForm.headers}
                  onChange={(e) => setRecordForm({ ...recordForm, headers: e.target.value })}
                  className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Response Body / Payload Snippet</label>
                <textarea
                  rows={2}
                  value={recordForm.body}
                  onChange={(e) => setRecordForm({ ...recordForm, body: e.target.value })}
                  className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-slate-200 focus:border-indigo-500 focus:outline-hidden"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRecordModal(false)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-slate-300 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-white font-medium hover:bg-indigo-500"
                >
                  Sanitize, Hash & Record
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
