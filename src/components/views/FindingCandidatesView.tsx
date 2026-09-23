import React, { useState, useEffect } from 'react';
import {
  Target,
  FindingCandidate,
  CandidateState,
  SecuritySignal,
} from '../../types';
import { api } from '../../lib/api';
import { useRuntime } from '../../context/RuntimeContext';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  FileCheck,
  ChevronRight,
  ExternalLink,
  Sparkles,
  RefreshCw,
  Clock,
  Key,
  XCircle,
  Play,
  Layers,
  ArrowRight,
} from 'lucide-react';

interface FindingCandidatesViewProps {
  targets: Target[];
  selectedTargetId: string;
  onSelectTarget: (id: string) => void;
}

const STATE_BADGES: Record<CandidateState, { label: string; color: string; border: string; bg: string }> = {
  OBSERVATION: { label: 'Observation', color: 'text-slate-400', border: 'border-slate-700', bg: 'bg-slate-900/60' },
  SIGNAL: { label: 'Signal', color: 'text-sky-400', border: 'border-sky-800/80', bg: 'bg-sky-950/60' },
  ANALYSIS_CANDIDATE: { label: 'Analysis Candidate', color: 'text-indigo-400', border: 'border-indigo-800/80', bg: 'bg-indigo-950/60' },
  CANDIDATE: { label: 'Candidate', color: 'text-amber-400', border: 'border-amber-800/80', bg: 'bg-amber-950/60' },
  VALIDATING: { label: 'Validating', color: 'text-purple-400', border: 'border-purple-800/80', bg: 'bg-purple-950/60' },
  REPORTED: { label: 'Reported / Validated', color: 'text-emerald-400', border: 'border-emerald-800/80', bg: 'bg-emerald-950/60' },
  RESOLVED: { label: 'Resolved', color: 'text-teal-400', border: 'border-teal-800/80', bg: 'bg-teal-950/60' },
  DISMISSED: { label: 'Dismissed', color: 'text-rose-400', border: 'border-rose-800/80', bg: 'bg-rose-950/60' },
};

export const FindingCandidatesView: React.FC<FindingCandidatesViewProps> = ({
  targets,
  selectedTargetId,
  onSelectTarget,
}) => {
  const { mode, assertLiveOrThrow, showRuntimeError } = useRuntime();
  const [candidates, setCandidates] = useState<FindingCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<FindingCandidate | null>(null);
  const [filterState, setFilterState] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [dismissReason, setDismissReason] = useState('');
  const [showDismissModal, setShowDismissModal] = useState(false);
  const [validationSuccessMsg, setValidationSuccessMsg] = useState<string | null>(null);

  const activeTargetId = selectedTargetId || (targets[0]?.id ?? '');

  const loadCandidates = async () => {
    if (!activeTargetId) return;
    setIsLoading(true);
    try {
      const stateParam = filterState === 'ALL' ? undefined : filterState;
      const data = await api.getCandidates(activeTargetId, stateParam);
      setCandidates(data);
      if (selectedCandidate) {
        const refreshed = data.find((c: FindingCandidate) => c.id === selectedCandidate.id);
        if (refreshed) setSelectedCandidate(refreshed);
      } else if (data.length > 0) {
        setSelectedCandidate(data[0]);
      }
    } catch (err) {
      console.error('Failed to load finding candidates', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadCandidates();
  }, [activeTargetId, filterState]);

  const handleRunAIAnalysis = async () => {
    if (!activeTargetId) return;
    setIsAnalyzing(true);
    try {
      assertLiveOrThrow('run ai security analysis');
      await api.runAIAnalysis({ target_id: activeTargetId });
      await loadCandidates();
    } catch (err: any) {
      showRuntimeError(err);
      console.error('AI analysis run failed', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUpdateState = async (newState: CandidateState, reason?: string) => {
    if (!selectedCandidate) return;
    try {
      assertLiveOrThrow('update candidate state');
      const updated = await api.updateCandidateState(selectedCandidate.id, newState, reason);
      setSelectedCandidate(updated);
      setCandidates((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      setShowDismissModal(false);
      setDismissReason('');
    } catch (err: any) {
      showRuntimeError(err);
      console.error('Failed to update candidate state', err);
    }
  };

  const handleExecuteValidation = async () => {
    if (!selectedCandidate) return;
    setIsValidating(true);
    setValidationSuccessMsg(null);
    try {
      assertLiveOrThrow('execute safe validation probe');
      const result = await api.executeControlledValidation({
        target_id: activeTargetId,
        candidate_id: selectedCandidate.id,
      });
      setValidationSuccessMsg(result.output_fact || 'Safe validation executed successfully without side-effects.');
      await loadCandidates();
    } catch (err: any) {
      showRuntimeError(err);
      console.error('Safe validation failed', err);
    } finally {
      setIsValidating(false);
    }
  };

  const filteredCandidates = candidates.filter((c) => {
    const q = searchQuery.toLowerCase();
    return (
      c.title.toLowerCase().includes(q) ||
      c.category.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q)
    );
  });

  return (
    <div id="finding-candidates-view" className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs font-mono font-medium text-amber-400">
              <ShieldAlert className="h-3.5 w-3.5" />
              Hypothesis-to-Finding Engine
            </span>
            <span className="text-xs font-mono text-slate-500">• Fail-Closed Evidence Verification</span>
          </div>
          <h2 className="mt-2 text-xl font-bold text-white tracking-tight">Finding Candidates Pipeline</h2>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl leading-relaxed">
            AI inferences are strictly hypotheses until supported by reproducible raw evidence. Review the evidence chain,
            missing evidence criteria, and run controlled non-destructive validation steps.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleRunAIAnalysis}
            disabled={isAnalyzing}
            className="flex items-center gap-2 rounded-lg bg-sky-600 px-3.5 py-2 text-xs font-semibold text-white shadow-xs hover:bg-sky-500 disabled:opacity-50 transition-colors"
          >
            <Sparkles className={`h-4 w-4 ${isAnalyzing ? 'animate-spin' : ''}`} />
            <span>{isAnalyzing ? 'Analyzing Signals...' : 'Run AI Analysis'}</span>
          </button>
        </div>
      </div>

      {/* Target Selector & Filters */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center gap-3">
          <label htmlFor="target-select-cand" className="text-xs font-mono text-slate-400">
            Target Scope:
          </label>
          <select
            id="target-select-cand"
            value={activeTargetId}
            onChange={(e) => onSelectTarget(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-hidden"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.root_domain})
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search hypotheses..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 w-48 rounded-lg border border-slate-800 bg-slate-950 pl-8 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-hidden sm:w-64"
            />
          </div>

          <div className="flex items-center gap-1">
            <Filter className="h-3.5 w-3.5 text-slate-500 ml-2" />
            <select
              value={filterState}
              onChange={(e) => setFilterState(e.target.value)}
              className="h-8 rounded-lg border border-slate-800 bg-slate-950 px-2.5 text-xs text-slate-300 focus:border-sky-500 focus:outline-hidden"
            >
              <option value="ALL">All Lifecycle States</option>
              <option value="OBSERVATION">Observations</option>
              <option value="SIGNAL">Signals</option>
              <option value="ANALYSIS_CANDIDATE">Analysis Candidates</option>
              <option value="CANDIDATE">Candidates</option>
              <option value="VALIDATING">Validating</option>
              <option value="REPORTED">Reported</option>
              <option value="DISMISSED">Dismissed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Split View: Candidates List vs Candidate Evidence Detail */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Candidate Cards */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between px-1">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Hypotheses & Candidates ({filteredCandidates.length})
            </span>
            {isLoading && <RefreshCw className="h-3.5 w-3.5 text-sky-400 animate-spin" />}
          </div>

          {filteredCandidates.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center">
              <CheckCircle2 className="mx-auto h-8 w-8 text-slate-500" />
              <p className="mt-2 text-sm font-medium text-slate-300">No Finding Candidates</p>
              <p className="mt-1 text-xs text-slate-500">
                {filterState !== 'ALL'
                  ? `No candidates match the '${filterState}' filter.`
                  : 'Run an AI analysis cycle or perform an asset recon scan to correlate security signals.'}
              </p>
            </div>
          ) : (
            <div className="space-y-2.5 max-h-[720px] overflow-y-auto pr-1">
              {filteredCandidates.map((candidate) => {
                const badge = STATE_BADGES[candidate.state] || STATE_BADGES.OBSERVATION;
                const isSelected = selectedCandidate?.id === candidate.id;
                return (
                  <button
                    key={candidate.id}
                    type="button"
                    onClick={() => setSelectedCandidate(candidate)}
                    className={`w-full text-left rounded-xl border p-4 transition-all ${
                      isSelected
                        ? 'border-sky-500/80 bg-slate-900 shadow-md shadow-sky-950/20'
                        : 'border-slate-800/80 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/70'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span
                        className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-mono font-medium border ${badge.bg} ${badge.color} ${badge.border}`}
                      >
                        {badge.label}
                      </span>
                      <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                        <span>Confidence:</span>
                        <span className="font-semibold text-sky-400">
                          {Math.round(candidate.confidence_score * 100)}%
                        </span>
                      </div>
                    </div>

                    <h4 className="mt-2 text-sm font-semibold text-white leading-snug line-clamp-1">
                      {candidate.title}
                    </h4>

                    <p className="mt-1 text-xs text-slate-400 line-clamp-2 leading-relaxed">
                      {candidate.description}
                    </p>

                    <div className="mt-3 flex items-center justify-between border-t border-slate-800/60 pt-2 text-[11px] font-mono text-slate-500">
                      <span>Category: {candidate.category}</span>
                      <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Deep Evidence & Lifecycle Control Drawer */}
        <div className="lg:col-span-7">
          {selectedCandidate ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-6">
              {/* Header */}
              <div className="border-b border-slate-800 pb-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded-md px-2.5 py-1 text-xs font-mono font-semibold border ${
                        STATE_BADGES[selectedCandidate.state]?.bg
                      } ${STATE_BADGES[selectedCandidate.state]?.color} ${
                        STATE_BADGES[selectedCandidate.state]?.border
                      }`}
                    >
                      {STATE_BADGES[selectedCandidate.state]?.label}
                    </span>
                    <span className="text-xs font-mono text-slate-400">ID: {selectedCandidate.id}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-400">Confidence Score:</span>
                    <div className="flex items-center gap-1.5 rounded-md bg-slate-950 px-2 py-1 border border-slate-800 font-mono text-xs text-sky-400 font-bold">
                      {Math.round(selectedCandidate.confidence_score * 100)}%
                    </div>
                  </div>
                </div>

                <h3 className="mt-3 text-lg font-bold text-white tracking-tight">
                  {selectedCandidate.title}
                </h3>
                <p className="mt-1 text-xs text-slate-300 leading-relaxed">
                  {selectedCandidate.description}
                </p>
              </div>

              {/* State Transition Actions */}
              <div className="rounded-lg border border-slate-800/90 bg-slate-950 p-4">
                <p className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
                  Lifecycle Transitions (State Machine)
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedCandidate.state === 'OBSERVATION' && (
                    <button
                      type="button"
                      onClick={() => handleUpdateState('SIGNAL', 'Signal threshold met via correlation')}
                      className="flex items-center gap-1.5 rounded-lg bg-sky-900/60 border border-sky-700/80 px-3 py-1.5 text-xs font-medium text-sky-200 hover:bg-sky-800"
                    >
                      <ArrowRight className="h-3 w-3" />
                      <span>Promote to Signal</span>
                    </button>
                  )}

                  {selectedCandidate.state === 'SIGNAL' && (
                    <button
                      type="button"
                      onClick={() => handleUpdateState('ANALYSIS_CANDIDATE', 'Candidate for AI investigation')}
                      className="flex items-center gap-1.5 rounded-lg bg-indigo-900/60 border border-indigo-700/80 px-3 py-1.5 text-xs font-medium text-indigo-200 hover:bg-indigo-800"
                    >
                      <ArrowRight className="h-3 w-3" />
                      <span>Mark for Analysis</span>
                    </button>
                  )}

                  {selectedCandidate.state === 'ANALYSIS_CANDIDATE' && (
                    <button
                      type="button"
                      onClick={() => handleUpdateState('CANDIDATE', 'Verified hypothesis preconditions')}
                      className="flex items-center gap-1.5 rounded-lg bg-amber-900/60 border border-amber-700/80 px-3 py-1.5 text-xs font-medium text-amber-200 hover:bg-amber-800"
                    >
                      <ArrowRight className="h-3 w-3" />
                      <span>Advance to Candidate</span>
                    </button>
                  )}

                  {(selectedCandidate.state === 'CANDIDATE' || selectedCandidate.state === 'ANALYSIS_CANDIDATE') && (
                    <button
                      type="button"
                      onClick={handleExecuteValidation}
                      disabled={isValidating}
                      className="flex items-center gap-1.5 rounded-lg bg-purple-900/60 border border-purple-700/80 px-3 py-1.5 text-xs font-medium text-purple-200 hover:bg-purple-800 disabled:opacity-50"
                    >
                      <Play className={`h-3 w-3 ${isValidating ? 'animate-spin' : ''}`} />
                      <span>{isValidating ? 'Executing Safe Probe...' : 'Execute Controlled Validation'}</span>
                    </button>
                  )}

                  {selectedCandidate.state === 'VALIDATING' && (
                    <button
                      type="button"
                      onClick={() => handleUpdateState('REPORTED', 'Empirically confirmed through safe validation')}
                      className="flex items-center gap-1.5 rounded-lg bg-emerald-900/60 border border-emerald-700/80 px-3 py-1.5 text-xs font-medium text-emerald-200 hover:bg-emerald-800"
                    >
                      <CheckCircle2 className="h-3 w-3" />
                      <span>Confirm as Reported Finding</span>
                    </button>
                  )}

                  {selectedCandidate.state !== 'DISMISSED' && (
                    <button
                      type="button"
                      onClick={() => setShowDismissModal(true)}
                      className="flex items-center gap-1.5 rounded-lg bg-rose-950/40 border border-rose-800/60 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-900/60 ml-auto"
                    >
                      <XCircle className="h-3 w-3" />
                      <span>Dismiss (False Positive)</span>
                    </button>
                  )}
                </div>

                {validationSuccessMsg && (
                  <div className="mt-3 rounded-md bg-emerald-950/40 border border-emerald-800/80 p-2.5 text-xs text-emerald-300">
                    {validationSuccessMsg}
                  </div>
                )}
              </div>

              {/* AI Reasoning & Why Hypothesis was Formed */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Hypothesis Formulation & Reasoning
                </span>
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 text-xs font-mono text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {selectedCandidate.reasoning}
                </div>
              </div>

              {/* Missing Evidence Required for Confirmation */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  Missing Evidence (Hypothesis Precondition)
                </span>
                <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-3.5 text-xs text-amber-200 leading-relaxed">
                  {selectedCandidate.missing_evidence || 'All core observations verified. Controlled validation required for final verification.'}
                </div>
              </div>

              {/* Step-by-step verification commands */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <FileCheck className="h-3.5 w-3.5" />
                  Recommended Non-Destructive Verification Steps
                </span>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2">
                  {selectedCandidate.validation_steps?.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                      <span className="font-mono text-sky-400 font-semibold">{idx + 1}.</span>
                      <span>{step}</span>
                    </div>
                  ))}
                  {(!selectedCandidate.validation_steps || selectedCandidate.validation_steps.length === 0) && (
                    <p className="text-xs text-slate-500 italic">No automated validation steps defined.</p>
                  )}
                </div>
              </div>

              {/* Evidence References & Hashes */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Key className="h-3.5 w-3.5" />
                  Evidence Chain (SHA-256 Fingerprints)
                </span>
                <div className="space-y-2">
                  {selectedCandidate.evidence && selectedCandidate.evidence.length > 0 ? (
                    selectedCandidate.evidence.map((ev) => (
                      <div
                        key={ev.id}
                        className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <span className="text-sky-400 font-semibold">{ev.evidence_type}</span>
                          <span className="text-slate-500">Ref: {ev.reference_id}</span>
                        </div>
                        <p className="text-slate-300">{ev.summary}</p>
                        <p className="text-[10px] font-mono text-slate-500 truncate">
                          SHA256: {ev.sha256}
                        </p>
                      </div>
                    ))
                  ) : (
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
                      Linked to signal references: {selectedCandidate.evidence_references?.join(', ')}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center">
              <ShieldAlert className="mx-auto h-10 w-10 text-slate-600" />
              <p className="mt-3 text-sm font-medium text-slate-300">Select a Finding Candidate</p>
              <p className="mt-1 text-xs text-slate-500">
                Click any candidate on the left to inspect its evidence chain and execute safe verification.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Dismiss Reason Modal */}
      {showDismissModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-5 space-y-4">
            <h3 className="text-sm font-bold text-white">Dismiss Hypothesis / Candidate</h3>
            <p className="text-xs text-slate-400">
              NexusHunter enforces explicit accountability. Provide a justification for dismissing this hypothesis
              (e.g., intended architectural design, verified mitigating control, or out-of-scope route).
            </p>
            <textarea
              rows={3}
              placeholder="Enter dismissal justification..."
              value={dismissReason}
              onChange={(e) => setDismissReason(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-hidden"
            />
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowDismissModal(false)}
                className="rounded-lg px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => handleUpdateState('DISMISSED', dismissReason || 'Dismissed by security researcher')}
                className="rounded-lg bg-rose-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-rose-500"
              >
                Confirm Dismissal
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
