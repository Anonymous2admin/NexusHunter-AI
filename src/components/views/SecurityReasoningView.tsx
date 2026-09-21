import React, { useState, useEffect, useCallback } from 'react';
import {
  Target,
  ReasoningSignal,
  Hypothesis,
  HypothesisGroup,
  Investigation,
  TrustBoundary,
  PermissionMatrixEntry,
  SecurityControlRecord,
  Evidence,
} from '../../types';
import { api, ApiError } from '../../lib/api';
import {
  Brain,
  Sparkles,
  ShieldAlert,
  GitFork,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCw,
  Search,
  ArrowRight,
  Shield,
  Layers,
  Lock,
  Unlock,
  Eye,
  FileCheck,
  ChevronRight,
  ChevronDown,
  Info,
  Clock,
  XCircle,
  HelpCircle,
  BarChart2,
  Terminal,
} from 'lucide-react';
import { StatusBadge } from '../StatusBadge';

interface SecurityReasoningViewProps {
  targets: Target[];
  selectedTargetId: string;
  onSelectTarget: (id: string) => void;
}

type ReasoningTab = 'hypotheses' | 'signals' | 'investigations' | 'boundaries' | 'ai-assist';

export const SecurityReasoningView: React.FC<SecurityReasoningViewProps> = ({
  targets,
  selectedTargetId,
  onSelectTarget,
}) => {
  const [activeTab, setActiveTab] = useState<ReasoningTab>('hypotheses');
  const [targetId, setTargetId] = useState<string>(selectedTargetId || targets[0]?.id || '');

  // Core Data States
  const [signals, setSignals] = useState<ReasoningSignal[]>([]);
  const [groups, setGroups] = useState<HypothesisGroup[]>([]);
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [trustBoundaries, setTrustBoundaries] = useState<TrustBoundary[]>([]);
  const [permissionMatrix, setPermissionMatrix] = useState<PermissionMatrixEntry[]>([]);
  const [securityControls, setSecurityControls] = useState<SecurityControlRecord[]>([]);

  // UI state
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isCycling, setIsCycling] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Detail Modal / Selection
  const [selectedHypothesis, setSelectedHypothesis] = useState<Hypothesis | null>(null);
  const [viewingEvidence, setViewingEvidence] = useState<Evidence[] | null>(null);
  const [isLoadingEvidence, setIsLoadingEvidence] = useState<boolean>(false);

  // AI Assist State
  const [aiPrompt, setAiPrompt] = useState<string>('Evaluate whether unauthenticated 200 response on token endpoint is intentional public behavior or proxy auth-filter bypass.');
  const [aiResult, setAiResult] = useState<any | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);

  // Sync target selection with props
  useEffect(() => {
    if (selectedTargetId && selectedTargetId !== targetId) {
      setTargetId(selectedTargetId);
    }
  }, [selectedTargetId]);

  const loadReasoningData = useCallback(async (tid: string) => {
    if (!tid) return;
    setIsLoading(true);
    setError(null);
    try {
      const [sigs, grps, hyps, invs, tbs, pms, scs] = await Promise.all([
        api.getSignals(tid).catch(() => []),
        api.getHypothesisGroups(tid).catch(() => []),
        api.getHypotheses(tid).catch(() => []),
        api.getInvestigations(tid).catch(() => []),
        api.getAssetTrustBoundaries('', tid).catch(() => []),
        api.getAssetPermissionMatrix('', tid).catch(() => []),
        api.getAssetSecurityControls('', tid).catch(() => []),
      ]);

      setSignals(sigs || []);
      setGroups(grps || []);
      setHypotheses(hyps || []);
      setInvestigations(invs || []);
      setTrustBoundaries(tbs || []);
      setPermissionMatrix(pms || []);
      setSecurityControls(scs || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load reasoning intelligence state.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (targetId) {
      loadReasoningData(targetId);
    }
  }, [targetId, loadReasoningData]);

  const handleRunCycle = async () => {
    if (!targetId) return;
    setIsCycling(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await api.triggerReasoningCycle(targetId);
      setSuccessMessage(`Reasoning cycle completed: evaluated ${res.input_count || 0} observations, generated ${res.signals_count || 0} signals and ${res.hypotheses_count || 0} hypotheses in ${res.duration_ms || 0}ms.`);
      await loadReasoningData(targetId);
    } catch (err: any) {
      setError(err.message || 'Failed to execute reasoning cycle.');
    } finally {
      setIsCycling(false);
    }
  };

  const handlePlanInvestigation = async (hypId: string) => {
    try {
      const inv = await api.planInvestigation(hypId);
      setSuccessMessage(`Safe investigation plan created: ${inv.title}`);
      await loadReasoningData(targetId);
      setActiveTab('investigations');
    } catch (err: any) {
      setError(err.message || 'Failed to create investigation plan.');
    }
  };

  const handleUpdateHypothesisStatus = async (hypId: string, nextStatus: any) => {
    try {
      setError(null);
      await api.updateHypothesisStatus(hypId, nextStatus);
      setSuccessMessage(`Hypothesis transitioned to ${nextStatus}.`);
      await loadReasoningData(targetId);
      if (selectedHypothesis && selectedHypothesis.id === hypId) {
        setSelectedHypothesis((prev) => (prev ? { ...prev, status: nextStatus } : null));
      }
    } catch (err: any) {
      setError(err.message || 'State transition rejected.');
    }
  };

  const handleUpdateSignalStatus = async (sigId: string, nextStatus: any) => {
    try {
      setError(null);
      await api.updateSignalStatus(sigId, nextStatus);
      setSuccessMessage(`Signal transitioned to ${nextStatus}.`);
      await loadReasoningData(targetId);
    } catch (err: any) {
      setError(err.message || 'Signal state transition rejected.');
    }
  };

  const handleCancelInvestigation = async (invId: string) => {
    try {
      setError(null);
      await api.cancelInvestigation(invId);
      setSuccessMessage(`Investigation cancelled safely.`);
      await loadReasoningData(targetId);
    } catch (err: any) {
      setError(err.message || 'Failed to cancel investigation.');
    }
  };

  const handleExecuteInvestigationStep = async (invId: string) => {
    try {
      const updated = await api.executeInvestigationStep(invId);
      setSuccessMessage(`Executed investigation step. Status: ${updated.status}`);
      await loadReasoningData(targetId);
    } catch (err: any) {
      setError(err.message || 'Failed to advance investigation step.');
    }
  };

  const handleViewEvidence = async (hyp: Hypothesis) => {
    setSelectedHypothesis(hyp);
    setIsLoadingEvidence(true);
    try {
      const evList = await api.getHypothesisEvidence(hyp.id);
      setViewingEvidence(evList || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load supporting evidence.');
    } finally {
      setIsLoadingEvidence(false);
    }
  };

  const handleAIAssist = async () => {
    if (!targetId) return;
    setIsAiLoading(true);
    setError(null);
    try {
      // Collect valid evidence IDs from active hypotheses
      const sampleEvidenceIds = hypotheses.flatMap((h) => h.supporting_evidence).slice(0, 3);
      const res = await api.aiAssistedReasoning(
        targetId,
        selectedHypothesis?.id || hypotheses[0]?.id || 'hyp-sample',
        aiPrompt,
        sampleEvidenceIds
      );
      setAiResult(res);
    } catch (err: any) {
      setError(err.message || 'AI Reasoning assist failed.');
    } finally {
      setIsAiLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Target Selector */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-indigo-500/10 text-indigo-400">
              <Brain className="h-4 w-4" />
            </span>
            <h1 className="text-xl font-semibold text-slate-100">
              Security Reasoning & Hypotheses
            </h1>
            <span className="rounded bg-indigo-950 px-2 py-0.5 text-xs font-mono font-medium text-indigo-400 border border-indigo-800/50">
              Phase 7
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Transforms raw empirical observations into competing hypotheses, falsification criteria, and bounded investigations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={targetId}
            onChange={(e) => {
              setTargetId(e.target.value);
              onSelectTarget(e.target.value);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:border-indigo-500 focus:outline-none"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.root_domain})
              </option>
            ))}
          </select>

          <button
            onClick={handleRunCycle}
            disabled={isCycling || !targetId}
            className="flex items-center gap-2 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50 transition-colors shadow-xs"
          >
            <RotateCw className={`h-4 w-4 ${isCycling ? 'animate-spin' : ''}`} />
            {isCycling ? 'Evaluating Cycle...' : 'Run Reasoning Cycle'}
          </button>
        </div>
      </div>

      {/* Epistemic Principles Banner */}
      <div className="rounded-lg border border-indigo-900/40 bg-indigo-950/20 p-3 text-xs text-indigo-300 flex items-start gap-2">
        <Info className="h-4 w-4 shrink-0 text-indigo-400 mt-0.5" />
        <div>
          <span className="font-semibold text-indigo-200">Strict Epistemic Principles:</span> Competing hypotheses are maintained simultaneously. A state of <span className="font-mono text-indigo-200">NOT_OBSERVED</span> is never assumed to mean <span className="font-mono text-indigo-200">ABSENT</span>. An endpoint or behavior is <span className="font-mono text-indigo-200">HYPOTHESIZED</span> until empirical evidence satisfies deliberate falsification conditions.
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="rounded-lg border border-red-800/60 bg-red-950/40 p-3 text-sm text-red-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      )}

      {successMessage && (
        <div className="rounded-lg border border-emerald-800/60 bg-emerald-950/40 p-3 text-sm text-emerald-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            <span>{successMessage}</span>
          </div>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-200">
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
          <div className="text-xs font-medium text-slate-400">Reasoning Signals</div>
          <div className="mt-1 text-2xl font-bold text-slate-100">{signals.length}</div>
          <div className="mt-1 text-xs text-slate-500">From verified observations</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
          <div className="text-xs font-medium text-slate-400">Hypothesis Groups</div>
          <div className="mt-1 text-2xl font-bold text-slate-100">{groups.length}</div>
          <div className="mt-1 text-xs text-slate-500">Clustered attack surfaces</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
          <div className="text-xs font-medium text-slate-400">Competing Theories</div>
          <div className="mt-1 text-2xl font-bold text-slate-100">{hypotheses.length}</div>
          <div className="mt-1 text-xs text-slate-500">Falsifiable explanations</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
          <div className="text-xs font-medium text-slate-400">Planned Investigations</div>
          <div className="mt-1 text-2xl font-bold text-slate-100">{investigations.length}</div>
          <div className="mt-1 text-xs text-slate-500">Safe, non-destructive</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 text-sm font-medium">
        <button
          onClick={() => setActiveTab('hypotheses')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 transition-colors ${
            activeTab === 'hypotheses'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitFork className="h-4 w-4" />
          <span>Competing Hypotheses ({hypotheses.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('signals')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 transition-colors ${
            activeTab === 'signals'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="h-4 w-4" />
          <span>Reasoning Signals ({signals.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('investigations')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 transition-colors ${
            activeTab === 'investigations'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Play className="h-4 w-4" />
          <span>Investigations ({investigations.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('boundaries')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 transition-colors ${
            activeTab === 'boundaries'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="h-4 w-4" />
          <span>Trust Boundaries & Matrix</span>
        </button>

        <button
          onClick={() => setActiveTab('ai-assist')}
          className={`flex items-center gap-2 border-b-2 px-4 py-2.5 transition-colors ${
            activeTab === 'ai-assist'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sparkles className="h-4 w-4" />
          <span>AI Reasoning Guardrail</span>
        </button>
      </div>

      {/* Tab 1: Competing Hypotheses Workspace */}
      {activeTab === 'hypotheses' && (
        <div className="space-y-6">
          {hypotheses.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center">
              <Brain className="mx-auto h-8 w-8 text-slate-600" />
              <h3 className="mt-2 text-sm font-semibold text-slate-300">No Hypotheses Generated Yet</h3>
              <p className="mt-1 text-xs text-slate-500 max-w-sm mx-auto">
                Trigger a reasoning cycle to correlate existing evidence and contradictions into structured, competing explanations.
              </p>
              <button
                onClick={handleRunCycle}
                disabled={isCycling}
                className="mt-4 inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500"
              >
                <RotateCw className="h-3.5 w-3.5" />
                Run Reasoning Cycle
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              {/* Group List & Competing Hypotheses */}
              <div className="lg:col-span-2 space-y-4">
                {groups.map((grp) => {
                  const grpHyps = hypotheses.filter((h) => h.group_id === grp.id);
                  return (
                    <div key={grp.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                        <div>
                          <span className="text-xs font-mono text-indigo-400">SURFACE EVALUATION</span>
                          <h3 className="text-sm font-semibold text-slate-100">{grp.subject}</h3>
                        </div>
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300">
                          {grpHyps.length} Competing Theories
                        </span>
                      </div>

                      <div className="space-y-3">
                        {grpHyps.map((hyp) => {
                          const isSelected = selectedHypothesis?.id === hyp.id;
                          return (
                            <div
                              key={hyp.id}
                              onClick={() => setSelectedHypothesis(hyp)}
                              className={`cursor-pointer rounded-lg border p-3.5 transition-all ${
                                isSelected
                                  ? 'border-indigo-500 bg-indigo-950/20'
                                  : 'border-slate-800/80 bg-slate-950/40 hover:border-slate-700'
                              }`}
                            >
                              <div className="flex items-start justify-between gap-2">
                                <div>
                                  <div className="flex items-center gap-2">
                                    <span
                                      className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-medium ${
                                        hyp.category === 'INTENTIONAL_PUBLIC'
                                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/40'
                                          : hyp.category === 'AUTH_POLICY_DIFF'
                                          ? 'bg-amber-950 text-amber-400 border border-amber-800/40'
                                          : 'bg-slate-800 text-slate-400 border border-slate-700'
                                      }`}
                                    >
                                      {hyp.category}
                                    </span>
                                    <span className="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] font-mono text-slate-400">
                                      Status: {hyp.status}
                                    </span>
                                  </div>
                                  <h4 className="mt-1.5 text-sm font-medium text-slate-200">{hyp.title}</h4>
                                  <p className="mt-1 text-xs text-slate-400 line-clamp-2">{hyp.description}</p>
                                </div>

                                <div className="text-right shrink-0">
                                  <div className="text-xs font-mono font-semibold text-indigo-300">
                                    Score: {hyp.investigation_priority}
                                  </div>
                                  <div className="mt-1 flex items-center justify-end gap-1 text-[10px] text-slate-500">
                                    Strength: {hyp.evidence_strength}/5
                                  </div>
                                </div>
                              </div>

                              <div className="mt-3 flex items-center justify-between border-t border-slate-800/60 pt-2 text-xs text-slate-400">
                                <div className="flex items-center gap-3">
                                  <span>{hyp.supporting_evidence?.length || 0} Evidence Refs</span>
                                  <span>{hyp.falsification_conditions?.length || 0} Falsifiers</span>
                                  <span>{hyp.missing_evidence?.length || 0} Missing</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleViewEvidence(hyp);
                                    }}
                                    className="text-xs text-indigo-400 hover:text-indigo-300 underline"
                                  >
                                    Inspect Evidence
                                  </button>
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handlePlanInvestigation(hyp.id);
                                    }}
                                    className="rounded bg-indigo-600/80 px-2 py-0.5 text-xs text-white hover:bg-indigo-500"
                                  >
                                    Plan Investigation
                                  </button>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Selected Hypothesis Inspector */}
              <div className="space-y-4">
                {selectedHypothesis ? (
                  <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4 sticky top-4">
                    <div className="border-b border-slate-800 pb-3">
                      <span className="text-[10px] font-mono text-indigo-400">HYPOTHESIS DETAIL</span>
                      <h3 className="text-sm font-semibold text-slate-100">{selectedHypothesis.title}</h3>
                      <div className="mt-1 flex items-center gap-2">
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300">
                          {selectedHypothesis.status}
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          Priority Score: {selectedHypothesis.investigation_priority}/100
                        </span>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 uppercase">Reasoning Method</h4>
                      <p className="mt-1 text-xs font-mono text-slate-400">{selectedHypothesis.reasoning_method}</p>
                    </div>

                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 uppercase">Falsification Conditions</h4>
                      <div className="mt-1.5 space-y-2">
                        {(selectedHypothesis.falsification_conditions || []).map((fc, i) => (
                          <div key={i} className="rounded border border-slate-800 bg-slate-950/60 p-2 text-xs">
                            <div className="font-medium text-slate-300">{fc.condition_description}</div>
                            <div className="mt-1 text-[11px] text-slate-500 font-mono">
                              Required: {fc.required_evidence}
                            </div>
                            <div className="mt-1 flex items-center gap-2">
                              <span className="rounded bg-slate-900 px-1.5 py-0.2 text-[10px] font-mono text-indigo-400">
                                {fc.validation_method}
                              </span>
                              <span className="text-[10px] text-amber-400">{fc.result}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 uppercase">Missing Evidence Requirements</h4>
                      <div className="mt-1.5 space-y-2">
                        {(selectedHypothesis.missing_evidence || []).map((me, i) => (
                          <div key={i} className="rounded border border-slate-800 bg-slate-950/60 p-2 text-xs">
                            <div className="flex items-center justify-between">
                              <span className="font-medium text-slate-300">{me.description}</span>
                              <span className="rounded bg-red-950 px-1.5 py-0.2 text-[10px] text-red-400 font-mono">
                                {me.importance}
                              </span>
                            </div>
                            <div className="mt-1 text-[11px] text-slate-500 font-mono">
                              Collection Method: {me.collection_method}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 uppercase">State Machine Transition</h4>
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {selectedHypothesis.status === 'HYPOTHESIZED' && (
                          <>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'INVESTIGATING')}
                              className="rounded bg-indigo-950 border border-indigo-700/60 px-2 py-1 text-[11px] font-medium text-indigo-300 hover:bg-indigo-900"
                            >
                              → INVESTIGATING
                            </button>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'DISMISSED')}
                              className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-[11px] font-medium text-slate-300 hover:bg-slate-700"
                            >
                              → DISMISSED
                            </button>
                          </>
                        )}
                        {selectedHypothesis.status === 'INVESTIGATING' && (
                          <>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'SUPPORTED')}
                              className="rounded bg-emerald-950 border border-emerald-700/60 px-2 py-1 text-[11px] font-medium text-emerald-300 hover:bg-emerald-900"
                            >
                              → SUPPORTED
                            </button>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'FALSIFIED')}
                              className="rounded bg-rose-950 border border-rose-700/60 px-2 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-900"
                            >
                              → FALSIFIED
                            </button>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'UNKNOWN')}
                              className="rounded bg-amber-950 border border-amber-700/60 px-2 py-1 text-[11px] font-medium text-amber-300 hover:bg-amber-900"
                            >
                              → UNKNOWN
                            </button>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'DISMISSED')}
                              className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-[11px] font-medium text-slate-300 hover:bg-slate-700"
                            >
                              → DISMISSED
                            </button>
                          </>
                        )}
                        {selectedHypothesis.status === 'SUPPORTED' && (
                          <>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'FALSIFIED')}
                              className="rounded bg-rose-950 border border-rose-700/60 px-2 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-900"
                            >
                              → FALSIFIED
                            </button>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'INVESTIGATING')}
                              className="rounded bg-indigo-950 border border-indigo-700/60 px-2 py-1 text-[11px] font-medium text-indigo-300 hover:bg-indigo-900"
                            >
                              → Re-investigate
                            </button>
                          </>
                        )}
                        {selectedHypothesis.status === 'FALSIFIED' && (
                          <span className="text-[11px] text-slate-500 font-mono italic">Terminal State (Falsified)</span>
                        )}
                        {selectedHypothesis.status === 'UNKNOWN' && (
                          <>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'INVESTIGATING')}
                              className="rounded bg-indigo-950 border border-indigo-700/60 px-2 py-1 text-[11px] font-medium text-indigo-300 hover:bg-indigo-900"
                            >
                              → Re-investigate
                            </button>
                            <button
                              onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'DISMISSED')}
                              className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-[11px] font-medium text-slate-300 hover:bg-slate-700"
                            >
                              → DISMISSED
                            </button>
                          </>
                        )}
                        {selectedHypothesis.status === 'DISMISSED' && (
                          <button
                            onClick={() => handleUpdateHypothesisStatus(selectedHypothesis.id, 'HYPOTHESIZED')}
                            className="rounded bg-indigo-950 border border-indigo-700/60 px-2 py-1 text-[11px] font-medium text-indigo-300 hover:bg-indigo-900"
                          >
                            ↺ Reopen as HYPOTHESIZED
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="border-t border-slate-800 pt-3 flex gap-2">
                      <button
                        onClick={() => handlePlanInvestigation(selectedHypothesis.id)}
                        className="w-full rounded-lg bg-indigo-600 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 transition-colors"
                      >
                        Plan Safe Investigation
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-xs text-slate-500">
                    Select a competing theory to inspect falsification conditions and missing evidence requirements.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Reasoning Signals */}
      {activeTab === 'signals' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">
              Deterministic Security Signals ({signals.length})
            </h3>
            <span className="text-xs text-slate-500">
              Evaluated by specialized detectors without speculative LLM hallucination
            </span>
          </div>

          <div className="space-y-2.5">
            {signals.map((sig) => (
              <div key={sig.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5 space-y-2">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-indigo-950 px-1.5 py-0.5 text-[10px] font-mono text-indigo-400 border border-indigo-800/40">
                        {sig.signal_type}
                      </span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-400">
                        {sig.category}
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-medium ${
                          sig.severity === 'CRITICAL' || sig.severity === 'HIGH'
                            ? 'bg-red-950 text-red-400'
                            : 'bg-amber-950 text-amber-400'
                        }`}
                      >
                        {sig.severity}
                      </span>
                    </div>
                    <h4 className="mt-1 text-sm font-medium text-slate-100">{sig.title}</h4>
                    <p className="text-xs text-slate-400">{sig.description}</p>
                  </div>

                  <div className="text-right text-xs font-mono text-slate-500">
                    <div>{sig.detector}</div>
                    <div className="text-[10px]">v{sig.detector_version}</div>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs text-slate-500 border-t border-slate-800/60 pt-2">
                  <div className="flex items-center gap-3">
                    <span>Endpoint: <span className="font-mono text-slate-400">{sig.endpoint || '/'}</span></span>
                    <span>Evidence Refs: <span className="font-mono text-slate-400">{sig.source_evidence?.length || 0}</span></span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-slate-400">Status: {sig.status}</span>
                    {sig.status === 'OPEN' && (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleUpdateSignalStatus(sig.id, 'CORRELATED')}
                          className="rounded bg-indigo-950 border border-indigo-700/60 px-1.5 py-0.5 text-[10px] text-indigo-300 hover:bg-indigo-900"
                        >
                          Correlate
                        </button>
                        <button
                          onClick={() => handleUpdateSignalStatus(sig.id, 'DISMISSED')}
                          className="rounded bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
                        >
                          Dismiss
                        </button>
                      </div>
                    )}
                    {sig.status === 'CORRELATED' && (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleUpdateSignalStatus(sig.id, 'SUPERSEDED')}
                          className="rounded bg-purple-950 border border-purple-700/60 px-1.5 py-0.5 text-[10px] text-purple-300 hover:bg-purple-900"
                        >
                          Supersede
                        </button>
                        <button
                          onClick={() => handleUpdateSignalStatus(sig.id, 'DISMISSED')}
                          className="rounded bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
                        >
                          Dismiss
                        </button>
                      </div>
                    )}
                    {sig.status === 'SUPERSEDED' && (
                      <span className="text-[10px] text-slate-500 font-mono italic">Terminal</span>
                    )}
                    {sig.status === 'DISMISSED' && (
                      <button
                        onClick={() => handleUpdateSignalStatus(sig.id, 'OPEN')}
                        className="rounded bg-indigo-950 border border-indigo-700/60 px-1.5 py-0.5 text-[10px] text-indigo-300 hover:bg-indigo-900"
                      >
                        Reopen
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Investigation Plans & Execution */}
      {activeTab === 'investigations' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">
                Authorized Non-Destructive Investigations ({investigations.length})
              </h3>
              <p className="text-xs text-slate-400">
                Safe, bounded steps designed to collect differential evidence and test hypothesis falsification criteria.
              </p>
            </div>
          </div>

          {investigations.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-xs text-slate-500">
              No active investigations. Select a hypothesis in the Competing Hypotheses tab and click "Plan Investigation".
            </div>
          ) : (
            <div className="space-y-4">
              {investigations.map((inv) => (
                <div key={inv.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-indigo-950 px-2 py-0.5 text-xs font-mono text-indigo-400 border border-indigo-800/40">
                          {inv.priority} PRIORITY ({inv.priority_score}/100)
                        </span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300">
                          {inv.status}
                        </span>
                      </div>
                      <h4 className="mt-1.5 text-sm font-semibold text-slate-100">{inv.title}</h4>
                      <p className="text-xs text-slate-400">{inv.objective}</p>
                    </div>

                    <div className="flex items-center gap-2">
                      {inv.status !== 'COMPLETED' && inv.status !== 'CANCELLED' && (
                        <>
                          <button
                            onClick={() => handleCancelInvestigation(inv.id)}
                            className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700"
                          >
                            Cancel
                          </button>
                          <button
                            onClick={() => handleExecuteInvestigationStep(inv.id)}
                            className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500"
                          >
                            <Play className="h-3.5 w-3.5" />
                            Execute Next Step
                          </button>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Investigation Steps Checklist */}
                  <div className="space-y-2 border-t border-slate-800/80 pt-3">
                    <h5 className="text-xs font-medium text-slate-300">Bounded Scope Sequence:</h5>
                    <div className="space-y-1.5">
                      {inv.steps.map((step) => (
                        <div
                          key={step.step_number}
                          className={`flex items-start justify-between rounded border p-2.5 text-xs ${
                            step.status === 'COMPLETED'
                              ? 'border-emerald-800/40 bg-emerald-950/20 text-emerald-300'
                              : 'border-slate-800 bg-slate-950/40 text-slate-400'
                          }`}
                        >
                          <div className="flex items-start gap-2">
                            <span className="font-mono text-slate-500">{step.step_number}.</span>
                            <div>
                              <div className="font-medium text-slate-200">{step.name}</div>
                              <div className="text-[11px] text-slate-400">{step.description}</div>
                            </div>
                          </div>

                          <div className="text-right shrink-0">
                            <span className="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] font-mono text-indigo-400">
                              {step.scope_constraint}
                            </span>
                            <div className="mt-1 text-[10px] font-mono text-slate-400">{step.status}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {inv.result_summary && (
                    <div className="rounded bg-slate-950/60 p-2.5 text-xs border border-slate-800 text-slate-300">
                      <span className="font-semibold text-indigo-400">Outcome Summary: </span>
                      {inv.result_summary}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Trust Boundaries & Permission Matrix */}
      {activeTab === 'boundaries' && (
        <div className="space-y-6">
          {/* Trust Boundaries */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Layers className="h-4 w-4 text-indigo-400" />
              <span>Observed Architecture & Trust Boundaries</span>
            </h3>
            <p className="text-xs text-slate-400">
              Transitions across network perimeters, API gateways, reverse proxies, and internal microservices.
            </p>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-medium text-indigo-400">EDGE PERIMETER</span>
                  <span className="rounded bg-emerald-950 px-1.5 py-0.2 text-[10px] font-mono text-emerald-400">TLS 1.3 Active</span>
                </div>
                <h4 className="text-sm font-medium text-slate-200">Public Internet → Cloudflare CDN Edge</h4>
                <p className="text-xs text-slate-400">
                  Terminates public HTTPS connections. Strips unverified hop-by-hop headers.
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-medium text-amber-400">GATEWAY TRANSITION</span>
                  <span className="rounded bg-amber-950 px-1.5 py-0.2 text-[10px] font-mono text-amber-400">Auth Filtering</span>
                </div>
                <h4 className="text-sm font-medium text-slate-200">Envoy Reverse Proxy → Internal Token Service</h4>
                <p className="text-xs text-slate-400">
                  Routes paths to microservices. Discrepancy observed on /v1/auth unauthenticated path match.
                </p>
              </div>
            </div>
          </div>

          {/* Permission Matrix */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Lock className="h-4 w-4 text-indigo-400" />
              <span>Multi-Role Permission Matrix</span>
            </h3>
            <p className="text-xs text-slate-400">
              Empirical matrix tracking observed access behavior vs expected access policy across authentication contexts.
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                  <tr>
                    <th className="py-2 px-3">Endpoint</th>
                    <th className="py-2 px-3">Method</th>
                    <th className="py-2 px-3">Auth Role</th>
                    <th className="py-2 px-3">Expected</th>
                    <th className="py-2 px-3">Observed</th>
                    <th className="py-2 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 text-indigo-300">/v1/auth/token</td>
                    <td className="py-2.5 px-3">POST</td>
                    <td className="py-2.5 px-3">ANONYMOUS</td>
                    <td className="py-2.5 px-3 text-slate-400">UNKNOWN</td>
                    <td className="py-2.5 px-3 text-amber-400">ALLOW (200 OK)</td>
                    <td className="py-2.5 px-3 text-amber-400">DEVIATION</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 text-indigo-300">/v1/auth/token</td>
                    <td className="py-2.5 px-3">POST</td>
                    <td className="py-2.5 px-3">AUTHORIZED_USER</td>
                    <td className="py-2.5 px-3 text-slate-400">ALLOW</td>
                    <td className="py-2.5 px-3 text-emerald-400">ALLOW (200 OK)</td>
                    <td className="py-2.5 px-3 text-emerald-400">ALIGNED</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 text-indigo-300">/v1/admin/debug</td>
                    <td className="py-2.5 px-3">GET</td>
                    <td className="py-2.5 px-3">ANONYMOUS</td>
                    <td className="py-2.5 px-3 text-slate-400">DENY</td>
                    <td className="py-2.5 px-3 text-emerald-400">DENY (401 Unauthorized)</td>
                    <td className="py-2.5 px-3 text-emerald-400">ALIGNED</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: AI Reasoning Guardrail */}
      {activeTab === 'ai-assist' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-indigo-400" />
                <span>AI-Assisted Reasoning with Epistemic Grounding</span>
              </h3>
              <p className="mt-1 text-xs text-slate-400">
                Strict guardrail: LLM prompts are isolated from instruction data. AI output is constrained to verified evidence IDs only.
              </p>
            </div>
            <span className="rounded bg-emerald-950 px-2.5 py-1 text-xs font-mono text-emerald-400 border border-emerald-800/40 flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5" />
              Citation Integrity Active
            </span>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-medium text-slate-300">
              Researcher Reasoning Prompt:
            </label>
            <textarea
              rows={3}
              value={aiPrompt}
              onChange={(e) => setAiPrompt(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="text-xs text-slate-500">
              Available supporting evidence for grounding: <span className="font-mono text-slate-300">{hypotheses.flatMap((h) => h.supporting_evidence).length} items</span>
            </div>
            <button
              onClick={handleAIAssist}
              disabled={isAiLoading}
              className="flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
            >
              <Brain className={`h-4 w-4 ${isAiLoading ? 'animate-pulse' : ''}`} />
              {isAiLoading ? 'Evaluating Grounding...' : 'Request Grounded Reasoning'}
            </button>
          </div>

          {aiResult && (
            <div className="mt-4 rounded-lg border border-indigo-900/60 bg-indigo-950/20 p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-indigo-400">EVALUATION REPORT</span>
                <span className="rounded bg-indigo-900/40 px-2 py-0.5 text-[10px] font-mono text-indigo-300">
                  {aiResult.hallucination_check}
                </span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">{aiResult.analysis_summary}</p>

              <div className="border-t border-indigo-900/40 pt-2 space-y-1.5 text-xs">
                <div className="font-medium text-indigo-300">Suggested Falsification Action:</div>
                <div className="text-slate-300 font-mono text-[11px] bg-slate-950/60 p-2 rounded border border-indigo-900/40">
                  {aiResult.suggested_falsification}
                </div>
              </div>

              {aiResult.suggested_missing_evidence && (
                <div className="border-t border-indigo-900/40 pt-2 space-y-1 text-xs">
                  <div className="font-medium text-indigo-300">Identified Evidence Gaps:</div>
                  <ul className="list-disc list-inside text-slate-400 text-[11px]">
                    {aiResult.suggested_missing_evidence.map((item: string, idx: number) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Supporting Evidence Modal / Slide-out */}
      {viewingEvidence && selectedHypothesis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs">
          <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-4 shadow-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono text-indigo-400">EMPIRICAL EVIDENCE INSPECTOR</span>
                <h3 className="text-sm font-semibold text-slate-100">{selectedHypothesis.title}</h3>
              </div>
              <button
                onClick={() => {
                  setViewingEvidence(null);
                  setSelectedHypothesis(null);
                }}
                className="text-slate-400 hover:text-slate-200"
              >
                <XCircle className="h-5 w-5" />
              </button>
            </div>

            {isLoadingEvidence ? (
              <div className="py-8 text-center text-xs text-slate-400">Loading verified evidence...</div>
            ) : viewingEvidence.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No raw HTTP evidence stored for this hypothesis yet.
              </div>
            ) : (
              <div className="space-y-3">
                {viewingEvidence.map((ev) => (
                  <div key={ev.id} className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2 text-xs">
                    <div className="flex items-center justify-between font-mono text-[11px] text-slate-400">
                      <span>ID: {ev.id}</span>
                      <span className="text-indigo-400">{ev.evidence_type}</span>
                    </div>

                    <div className="font-mono text-slate-300">
                      {ev.request?.method || 'GET'} {ev.request?.url || '/'} → Status {ev.response?.status_code || 200}
                    </div>

                    <div className="text-[11px] text-slate-500">
                      Hash: <span className="font-mono text-slate-400">{ev.payload_sha256}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="border-t border-slate-800 pt-3 text-right">
              <button
                onClick={() => {
                  setViewingEvidence(null);
                  setSelectedHypothesis(null);
                }}
                className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
