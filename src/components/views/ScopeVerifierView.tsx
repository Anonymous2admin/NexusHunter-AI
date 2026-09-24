import React, { useState, useEffect } from 'react';
import {
  Target,
  ScopeDecision,
  ScopeImportReview,
  JSAsset,
  JSReference,
  JSSecretIndicator,
  CloudReference,
  InvestigationPlan,
} from '../../types';
import { api } from '../../lib/api';
import { useRuntime } from '../../context/RuntimeContext';
import {
  CheckCircle2,
  XCircle,
  ShieldAlert,
  Search,
  ArrowRight,
  ShieldCheck,
  AlertOctagon,
  Sparkles,
  FileCode,
  Cloud,
  ListFilter,
  Layers,
  Upload,
  Play,
  Check,
  RefreshCw,
  ExternalLink,
  Lock,
  Eye,
  AlertTriangle,
  FileText,
} from 'lucide-react';

interface ScopeVerifierViewProps {
  targets: Target[];
  initialTarget?: Target | null;
}

type SubTab = 'scope-eval' | 'scope-import' | 'js-intel' | 'cloud-intel' | 'hunting-planner';

export const ScopeVerifierView: React.FC<ScopeVerifierViewProps> = ({
  targets,
  initialTarget,
}) => {
  const { mode, assertLiveOrThrow, showRuntimeError } = useRuntime();

  const [activeTab, setActiveTab] = useState<SubTab>('scope-eval');
  const [selectedTargetId, setSelectedTargetId] = useState(
    initialTarget?.id || (targets.length > 0 ? targets[0].id : '')
  );

  // Scope verification state
  const [hostname, setHostname] = useState('');
  const [url, setUrl] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [decision, setDecision] = useState<ScopeDecision | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Scope Import state
  const [importReviews, setImportReviews] = useState<ScopeImportReview[]>([]);
  const [importFileInput, setImportFileInput] = useState('');
  const [importFileName, setImportFileName] = useState('hackerone_scope.json');
  const [isImporting, setIsImporting] = useState(false);
  const [selectedReview, setSelectedReview] = useState<ScopeImportReview | null>(null);
  const [selectedRootCandidate, setSelectedRootCandidate] = useState<string>('');

  // JS Intelligence state
  const [jsAssets, setJsAssets] = useState<JSAsset[]>([]);
  const [jsReferences, setJsReferences] = useState<JSReference[]>([]);
  const [jsSecrets, setJsSecrets] = useState<JSSecretIndicator[]>([]);
  const [newJsUrl, setNewJsUrl] = useState('');
  const [isAnalyzingJs, setIsAnalyzingJs] = useState(false);

  // Cloud Intelligence state
  const [cloudRefs, setCloudRefs] = useState<CloudReference[]>([]);
  const [isValidatingCloud, setIsValidatingCloud] = useState<string | null>(null);

  // Hunting Planner state
  const [plans, setPlans] = useState<InvestigationPlan[]>([]);
  const [isGeneratingPlan, setIsGeneratingPlan] = useState(false);
  const [isApprovingStep, setIsApprovingStep] = useState<string | null>(null);

  const selectedTarget = targets.find((t) => t.id === selectedTargetId) || targets[0];

  // Fetch Phase 8 data when target or tab changes
  useEffect(() => {
    if (!selectedTargetId) return;

    if (activeTab === 'scope-import') {
      api.getScopeImports()
        .then((res) => {
          setImportReviews(res);
          if (res.length > 0 && !selectedReview) setSelectedReview(res[0]);
        })
        .catch(() => {});
    } else if (activeTab === 'js-intel') {
      Promise.all([
        api.getJSAssets(selectedTargetId).catch(() => []),
        api.getJSReferences(selectedTargetId).catch(() => []),
        api.getJSSecrets(selectedTargetId).catch(() => []),
      ]).then(([assets, refs, secrets]) => {
        setJsAssets(assets);
        setJsReferences(refs);
        setJsSecrets(secrets);
      });
    } else if (activeTab === 'cloud-intel') {
      api.getCloudReferences(selectedTargetId)
        .then(setCloudRefs)
        .catch(() => {});
    } else if (activeTab === 'hunting-planner') {
      api.getInvestigationPlans(selectedTargetId)
        .then(setPlans)
        .catch(() => {});
    }
  }, [selectedTargetId, activeTab]);

  // Handler: Interactive Scope Verification
  const handleVerify = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!selectedTargetId) {
      setError('Please select an authorized target.');
      return;
    }
    if (!hostname.trim() && !url.trim()) {
      setError('Please enter a hostname or URL to verify.');
      return;
    }

    setError(null);
    setIsVerifying(true);
    setDecision(null);

    try {
      assertLiveOrThrow('verify target scope');
      const res = await api.verifyScope({
        target_id: selectedTargetId,
        hostname: hostname.trim(),
        url: url.trim() || undefined,
      });
      setDecision(res);
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'Scope verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  // Handler: Import Scope File
  const handleImportScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importFileInput.trim()) {
      setError('Please paste JSON scope configuration content.');
      return;
    }
    setError(null);
    setSuccessMsg(null);
    setIsImporting(true);

    try {
      assertLiveOrThrow('import scope file');
      const review = await api.importScopeFile(importFileInput.trim(), importFileName.trim());
      setImportReviews((prev) => [review, ...prev]);
      setSelectedReview(review);
      setSelectedRootCandidate(''); // No silent selection; explicit choice mandatory
      setSuccessMsg(`Scope file ${review.file_name} successfully normalized with ${review.rules_discovered} rules.`);
      setImportFileInput('');
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'Scope import failed');
    } finally {
      setIsImporting(false);
    }
  };

  // Handler: Confirm Scope Import
  const handleConfirmImport = async (importId: string) => {
    if (!selectedRootCandidate) {
      setError('Please select a verified root domain before confirming scope import.');
      return;
    }
    setError(null);
    setSuccessMsg(null);

    try {
      assertLiveOrThrow('confirm scope import');
      const updated = await api.confirmScopeImport(importId, selectedRootCandidate);
      setImportReviews((prev) => prev.map((r) => (r.id === importId ? updated : r)));
      setSelectedReview(updated);
      setSuccessMsg(`Scope import confirmed for root domain ${updated.selected_root_domain}. Target program boundary established.`);
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'Failed to confirm scope import');
    }
  };

  // Handler: Trigger JS Analysis
  const handleTriggerJSAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newJsUrl.trim()) return;
    setError(null);
    setSuccessMsg(null);
    setIsAnalyzingJs(true);

    try {
      assertLiveOrThrow('trigger JS analysis');
      const res = await api.triggerJSAnalysis(selectedTargetId, {
        script_url: newJsUrl.trim(),
      });
      if (res?.asset) {
        setJsAssets((prev) => [res.asset, ...prev]);
      }
      setSuccessMsg(`Analyzed JavaScript asset ${newJsUrl}`);
      setNewJsUrl('');
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'JS Analysis failed');
    } finally {
      setIsAnalyzingJs(false);
    }
  };

  // Handler: Validate Cloud Reference
  const handleValidateCloud = async (cloudRefId: string) => {
    setError(null);
    setSuccessMsg(null);
    setIsValidatingCloud(cloudRefId);

    try {
      assertLiveOrThrow('validate cloud reference');
      const res = await api.validateCloudReference(cloudRefId);
      if (res?.reference) {
        setCloudRefs((prev) => prev.map((c) => (c.id === cloudRefId ? res.reference : c)));
      }
      setSuccessMsg(`Cloud asset ${cloudRefId} probed safely without destructive actions.`);
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'Cloud reference validation failed');
    } finally {
      setIsValidatingCloud(null);
    }
  };

  // Handler: Generate Hunting Plan
  const handleGeneratePlan = async () => {
    setError(null);
    setSuccessMsg(null);
    setIsGeneratingPlan(true);

    try {
      assertLiveOrThrow('generate investigation plan');
      const plan = await api.generateHuntingPlan(selectedTargetId);
      setPlans((prev) => [plan, ...prev]);
      setSuccessMsg(`Created bounded investigation plan ${plan.id} with ${plan.steps.length} authorization gates.`);
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'Failed to generate investigation plan');
    } finally {
      setIsGeneratingPlan(false);
    }
  };

  // Handler: Approve Investigation Step
  const handleApproveStep = async (planId: string, stepNumber: number) => {
    setError(null);
    setSuccessMsg(null);
    setIsApprovingStep(`${planId}-${stepNumber}`);

    try {
      assertLiveOrThrow('approve investigation step');
      const updatedPlan = await api.approveInvestigationStep(planId, stepNumber);
      setPlans((prev) => prev.map((p) => (p.id === planId ? updatedPlan : p)));
      setSuccessMsg(`Authorized Step #${stepNumber} on Plan ${planId}.`);
    } catch (err: any) {
      showRuntimeError(err);
      setError(err.message || 'Failed to approve plan step');
    } finally {
      setIsApprovingStep(null);
    }
  };

  const applyPreset = (presetHost: string, presetUrl: string) => {
    setHostname(presetHost);
    setUrl(presetUrl);
    setDecision(null);
    setError(null);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold tracking-tight text-white sm:text-xl flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-sky-400" />
            Phase 8 Scope & Asset Intelligence Engine
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Fail-closed boundary verification, RFC 1123 scope normalization, JavaScript asset indexing & bounded multi-step hunting plans.
          </p>
        </div>

        {/* Target Selector */}
        {targets.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Target:</span>
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs text-slate-200 font-mono focus:border-sky-500 focus:outline-none"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.root_domain})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto text-xs font-mono">
        <button
          type="button"
          onClick={() => setActiveTab('scope-eval')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${
            activeTab === 'scope-eval'
              ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <ShieldCheck className="h-3.5 w-3.5" /> Scope Policy Inspector
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('scope-import')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${
            activeTab === 'scope-import'
              ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Upload className="h-3.5 w-3.5" /> Scope Import & Normalization
          {importReviews.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {importReviews.length}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('js-intel')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${
            activeTab === 'js-intel'
              ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <FileCode className="h-3.5 w-3.5" /> JavaScript Intelligence
          {jsAssets.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {jsAssets.length}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('cloud-intel')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${
            activeTab === 'cloud-intel'
              ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Cloud className="h-3.5 w-3.5" /> Cloud & Storage Discovery
          {cloudRefs.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {cloudRefs.length}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('hunting-planner')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${
            activeTab === 'hunting-planner'
              ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Layers className="h-3.5 w-3.5" /> Bounded Hunting Planner
          {plans.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {plans.length}
            </span>
          )}
        </button>
      </div>

      {/* Alert Notices */}
      {error && (
        <div className="rounded-lg border border-rose-800/60 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button type="button" onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
            ×
          </button>
        </div>
      )}

      {successMsg && (
        <div className="rounded-lg border border-emerald-800/60 bg-emerald-950/40 p-3 text-xs text-emerald-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button type="button" onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            ×
          </button>
        </div>
      )}

      {/* TAB 1: Scope Policy Inspector */}
      {activeTab === 'scope-eval' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Query Form (2 cols) */}
          <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
            <form onSubmit={handleVerify} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Selected Target Program
                </label>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs font-mono text-slate-300">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">{selectedTarget?.name || 'No Target Selected'}</span>
                    <span className="text-sky-400 font-bold">{selectedTarget?.root_domain || '—'}</span>
                  </div>
                  {selectedTarget && (
                    <div className="mt-2 text-[11px] text-slate-500 space-y-1">
                      <div>Allowed Domains: {selectedTarget.allowed_domains?.join(', ') || 'None'}</div>
                      <div>Exclusion Patterns: {selectedTarget.excluded_patterns?.join(', ') || 'None'}</div>
                    </div>
                  )}
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Hostname to Verify
                </label>
                <input
                  type="text"
                  placeholder="e.g. sub.example.com or internal.example.com"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Target URL (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. https://api.example.com/v1/auth"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="submit"
                  disabled={isVerifying}
                  className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-500 disabled:opacity-50"
                >
                  <Search className="h-4 w-4" />
                  {isVerifying ? 'Evaluating Scope...' : 'Evaluate Scope Policy'}
                </button>
              </div>
            </form>

            {/* Presets */}
            {selectedTarget && (
              <div className="pt-4 border-t border-slate-800/80">
                <span className="text-[11px] font-mono text-slate-400 block mb-2">
                  Fail-Closed Verification Test Cases:
                </span>
                <div className="flex flex-wrap gap-2 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => applyPreset(selectedTarget.root_domain, `https://${selectedTarget.root_domain}/api`)}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Exact Root Domain
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset(`api.${selectedTarget.root_domain}`, '')}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Subdomain
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('evil-phishing-domain.com', 'https://evil-phishing-domain.com/login')}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Foreign Domain (Out of Scope)
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('bad..host..name', '')}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Malformed Hostname
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Decision Outcome Card (1 col) */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 flex flex-col justify-between">
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
                Evaluation Decision
              </h3>

              {!decision ? (
                <div className="py-12 text-center text-slate-500 text-xs font-mono">
                  Awaiting query evaluation...
                </div>
              ) : decision.in_scope ? (
                <div className="space-y-4 font-mono text-xs">
                  <div className="rounded-lg border border-emerald-800 bg-emerald-950/40 p-4 flex items-start gap-3">
                    <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-sm font-bold text-emerald-400">IN SCOPE (AUTHORIZED)</div>
                      <p className="mt-1 text-xs text-emerald-300/80">
                        Target matches explicit inclusion rules and passes fail-closed constraints.
                      </p>
                    </div>
                  </div>

                  {decision.matched_rule && (
                    <div className="rounded bg-slate-950 p-3 border border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">
                        Matched Rule
                      </span>
                      <span className="text-sky-400 font-semibold">{decision.matched_rule}</span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-4 font-mono text-xs">
                  <div className="rounded-lg border border-rose-800 bg-rose-950/40 p-4 flex items-start gap-3">
                    <XCircle className="h-6 w-6 text-rose-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-sm font-bold text-rose-400">OUT OF SCOPE (DENIED)</div>
                      <p className="mt-1 text-xs text-rose-300/80">
                        Fail-closed enforcement blocked testing on this target.
                      </p>
                    </div>
                  </div>

                  <div className="rounded bg-slate-950 p-3 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block mb-1">
                      Denial Reason
                    </span>
                    <span className="text-rose-400 font-semibold">{decision.reason}</span>
                  </div>
                </div>
              )}
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-500">
              NexusHunter Scope Engine • RFC 1123 Standard
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Scope Import & Normalization */}
      {activeTab === 'scope-import' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Import Form */}
            <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Upload className="h-4 w-4 text-sky-400" />
                Import Scope Manifest
              </h3>
              <p className="text-xs text-slate-400">
                Paste JSON scope rules (Burp Suite configuration, HackerOne, Bugcrowd, or raw domains).
              </p>

              <form onSubmit={handleImportScope} className="space-y-3">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    File Name
                  </label>
                  <input
                    type="text"
                    value={importFileName}
                    onChange={(e) => setImportFileName(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-100 focus:border-sky-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Scope Manifest (JSON / Domain List)
                  </label>
                  <textarea
                    rows={8}
                    value={importFileInput}
                    onChange={(e) => setImportFileInput(e.target.value)}
                    placeholder={`{\n  "target": {\n    "scope": {\n      "include": [\n        { "prefix": "https://api.example.com", "enabled": true }\n      ]\n    }\n  }\n}`}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 p-2.5 text-xs font-mono text-slate-100 placeholder-slate-600 focus:border-sky-500 focus:outline-none"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isImporting}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
                >
                  <Upload className="h-4 w-4" />
                  {isImporting ? 'Sanitizing & Normalizing...' : 'Import & Sanitize Scope'}
                </button>
              </form>
            </div>

            {/* Imported Reviews List & Normalization Details */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white flex items-center justify-between">
                <span>Discovered Scope Manifests</span>
                <span className="text-xs font-mono text-slate-400 font-normal">
                  {importReviews.length} manifest(s)
                </span>
              </h3>

              {importReviews.length === 0 ? (
                <div className="py-12 text-center text-xs font-mono text-slate-500">
                  No scope files imported yet. Import a manifest to review RFC 1123 normalizations.
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Select Review */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {importReviews.map((r) => (
                      <button
                        key={r.id}
                        type="button"
                        onClick={() => {
                          setSelectedReview(r);
                          setSelectedRootCandidate(''); // require explicit candidate selection
                        }}
                        className={`p-3 rounded-lg border text-left font-mono text-xs transition-colors ${
                          selectedReview?.id === r.id
                            ? 'border-sky-500 bg-sky-950/20 text-sky-200'
                            : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <div className="font-semibold text-white truncate">{r.file_name}</div>
                        <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            r.status === 'CONFIRMED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                          }`}>
                            {r.status}
                          </span>
                          <span>{r.rules_discovered} rules</span>
                        </div>
                      </button>
                    ))}
                  </div>

                  {/* Selected Review Details */}
                  {selectedReview && (
                    <div className="border-t border-slate-800 pt-4 space-y-4 font-mono text-xs">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-500 uppercase block">Include Hosts</span>
                          <span className="text-sm font-bold text-white">{selectedReview.include_hosts_count}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-500 uppercase block">Exclude Hosts</span>
                          <span className="text-sm font-bold text-rose-400">{selectedReview.exclude_hosts_count}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-500 uppercase block">Regex Rules</span>
                          <span className="text-sm font-bold text-slate-200">{selectedReview.regex_rules_count}</span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-500 uppercase block">Discovered Roots</span>
                          <span className="text-sm font-bold text-sky-400">{selectedReview.root_domains?.length || 0}</span>
                        </div>
                      </div>

                      {/* Root Domain Selection for Target Creation */}
                      {selectedReview.status !== 'CONFIRMED' && selectedReview.root_domains && selectedReview.root_domains.length > 0 && (
                        <div className="rounded-lg border border-sky-900/60 bg-sky-950/30 p-4 space-y-3">
                          <div className="text-xs font-semibold text-sky-300 flex items-center gap-1.5">
                            <ShieldAlert className="h-4 w-4" />
                            {selectedReview.root_domains.length > 1
                              ? 'Multiple Root Domains Detected'
                              : 'Discovered Root Domain Candidate'}
                          </div>
                          <p className="text-[11px] text-slate-400">
                            {selectedReview.root_domains.length > 1
                              ? 'Select Primary Root Domain to establish target authorization boundary:'
                              : 'Explicit confirmation required. Click to verify the candidate root domain:'}
                          </p>
                          <div className="space-y-2">
                            {selectedReview.root_domains.map((rd) => (
                              <div
                                key={rd.id}
                                onClick={() => setSelectedRootCandidate(rd.normalized_domain)}
                                className={`flex items-center gap-2.5 p-2 rounded border cursor-pointer font-mono text-xs transition-colors ${
                                  selectedRootCandidate === rd.normalized_domain
                                    ? 'bg-sky-950/70 border-sky-500 text-sky-200'
                                    : 'bg-slate-900 border-slate-700 text-slate-300 hover:border-slate-600'
                                }`}
                              >
                                <span className="text-sm">
                                  {selectedRootCandidate === rd.normalized_domain ? '◉' : '○'}
                                </span>
                                <span className="font-semibold">{rd.normalized_domain}</span>
                                <span className="text-[10px] text-slate-500 ml-auto">
                                  Confidence: {rd.confidence}
                                </span>
                              </div>
                            ))}
                          </div>
                          <div className="flex items-center justify-between pt-2">
                            <span className="text-[10px] text-slate-400">
                              {selectedRootCandidate
                                ? `Selected: ${selectedRootCandidate}`
                                : 'No root domain selected — Confirmation disabled'}
                            </span>
                            <button
                              type="button"
                              disabled={!selectedRootCandidate}
                              onClick={() => handleConfirmImport(selectedReview.id)}
                              className="inline-flex items-center gap-2 rounded bg-emerald-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                              <Check className="h-3.5 w-3.5" />
                              Confirm Scope & Establish Target Boundary
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Normalizations Applied */}
                      {selectedReview.normalizations && selectedReview.normalizations.length > 0 && (
                        <div>
                          <div className="text-xs font-semibold text-slate-300 mb-2">
                            RFC 1123 Normalization Manifest
                          </div>
                          <div className="space-y-1.5 max-h-48 overflow-y-auto">
                            {selectedReview.normalizations.map((n, idx) => (
                              <div key={idx} className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[11px]">
                                <div className="text-slate-400">
                                  <span className="text-rose-400 line-through">{n.original}</span>
                                  {' → '}
                                  <span className="text-emerald-400 font-semibold">{n.normalized}</span>
                                </div>
                                <div className="text-[10px] text-slate-500 mt-0.5">{n.reason}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: JavaScript Intelligence */}
      {activeTab === 'js-intel' && (
        <div className="space-y-6">
          {/* Analyze URL Bar */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
            <form onSubmit={handleTriggerJSAnalysis} className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                placeholder="https://api.example.com/static/js/bundle.js"
                value={newJsUrl}
                onChange={(e) => setNewJsUrl(e.target.value)}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={isAnalyzingJs || !newJsUrl.trim()}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
              >
                <FileCode className="h-4 w-4" />
                {isAnalyzingJs ? 'Extracting...' : 'Index JavaScript Asset'}
              </button>
            </form>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* JS Assets List */}
            <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center justify-between">
                <span>Discovered JS Files</span>
                <span className="text-xs font-mono text-slate-400 font-normal">
                  {jsAssets.length} assets
                </span>
              </h3>
              {jsAssets.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-slate-500">
                  No JavaScript assets recorded for this target.
                </div>
              ) : (
                <div className="space-y-2">
                  {jsAssets.map((asset) => (
                    <div key={asset.id} className="p-3 rounded-lg border border-slate-800 bg-slate-950 font-mono text-xs space-y-1">
                      <div className="text-sky-400 font-semibold truncate">{asset.url}</div>
                      <div className="text-[11px] text-slate-400 flex items-center justify-between">
                        <span>{(asset.byte_size / 1024).toFixed(1)} KB</span>
                        <span className="text-emerald-400">{asset.fetch_status}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 truncate">
                        SHA: {asset.content_sha256.substring(0, 16)}...
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Extracted References & Secrets */}
            <div className="lg:col-span-2 space-y-6">
              {/* Secret Indicators */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Lock className="h-4 w-4 text-amber-400" />
                  Redacted Secret Indicators (Hash Verified)
                </h3>
                <p className="text-xs text-slate-400">
                  Raw secret tokens are strictly never stored; previews are masked and correlated by SHA-256 only.
                </p>
                {jsSecrets.length === 0 ? (
                  <div className="py-4 text-center text-xs font-mono text-slate-500">
                    No secret indicators observed.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {jsSecrets.map((sec) => (
                      <div key={sec.id} className="p-3 rounded-lg border border-amber-900/40 bg-amber-950/20 font-mono text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-amber-400">{sec.secret_type}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                            {sec.confidence} CONFIDENCE
                          </span>
                        </div>
                        <div className="text-slate-300">{sec.masked_preview}</div>
                        <div className="text-[10px] text-slate-500">{sec.location}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* API Endpoints & References */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <FileText className="h-4 w-4 text-sky-400" />
                  Extracted API Routes & References
                </h3>
                {jsReferences.length === 0 ? (
                  <div className="py-4 text-center text-xs font-mono text-slate-500">
                    No structural references indexed.
                  </div>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {jsReferences.map((ref) => (
                      <div key={ref.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-xs space-y-0.5">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-sky-300">{ref.extracted_value}</span>
                          <span className="text-[10px] text-slate-400">{ref.category}</span>
                        </div>
                        {ref.source_fragment && (
                          <div className="text-[10px] text-slate-500 truncate">{ref.source_fragment}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Cloud Infrastructure Intelligence */}
      {activeTab === 'cloud-intel' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Cloud className="h-4 w-4 text-sky-400" />
                Cloud Storage & Takeover Exposure
              </span>
              <span className="text-xs font-mono text-slate-400 font-normal">
                {cloudRefs.length} referenced bucket(s)
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Correlated cloud buckets, CDN origins, and storage endpoints observed during research. Safe non-destructive HEAD probing verifies public accessibility.
            </p>

            {cloudRefs.length === 0 ? (
              <div className="py-12 text-center text-xs font-mono text-slate-500">
                No cloud infrastructure references recorded for this target program.
              </div>
            ) : (
              <div className="divide-y divide-slate-800 font-mono text-xs">
                {cloudRefs.map((c) => (
                  <div key={c.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{c.normalized_target}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-sky-400">
                          {c.provider} • {c.resource_type}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 truncate max-w-xl">
                        {c.raw_reference}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Origin: {c.source_origin} ({c.source_location})
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        c.public_accessible
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}>
                        {c.validation_status} {c.status_code ? `(HTTP ${c.status_code})` : ''}
                      </span>

                      <button
                        type="button"
                        disabled={isValidatingCloud === c.id}
                        onClick={() => handleValidateCloud(c.id)}
                        className="inline-flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1.5 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50"
                      >
                        <RefreshCw className={`h-3 w-3 ${isValidatingCloud === c.id ? 'animate-spin' : ''}`} />
                        Safe Probe
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: Bounded Hunting Planner */}
      {activeTab === 'hunting-planner' && (
        <div className="space-y-6">
          {/* Header Action */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Layers className="h-4 w-4 text-sky-400" />
                Bounded Multi-Step Investigation Plans
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Plans strictly enforce human-in-the-loop authorization gates before executing each step.
              </p>
            </div>

            <button
              type="button"
              disabled={isGeneratingPlan}
              onClick={handleGeneratePlan}
              className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
            >
              <Sparkles className="h-4 w-4" />
              {isGeneratingPlan ? 'Synthesizing...' : 'Generate Bounded Plan'}
            </button>
          </div>

          {plans.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center text-xs font-mono text-slate-500">
              No investigation plans generated for this target yet. Click above to synthesize a plan.
            </div>
          ) : (
            <div className="space-y-4">
              {plans.map((p) => (
                <div key={p.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4 font-mono text-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                    <div>
                      <div className="text-sm font-bold text-white">{p.title}</div>
                      <div className="text-xs text-slate-400 mt-0.5">{p.hypothesis}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-sky-400 border border-slate-700">
                        {p.epistemic_status}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        p.status === 'APPROVED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {p.status}
                      </span>
                    </div>
                  </div>

                  {/* Falsification conditions */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">Safe Validation Rationale</span>
                      <span className="text-slate-300">{p.safe_validation}</span>
                    </div>
                    <div className="p-3 rounded bg-slate-950 border border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">Stop Condition</span>
                      <span className="text-amber-400">{p.stop_condition}</span>
                    </div>
                  </div>

                  {/* Steps with Human-in-the-loop Approval Gate */}
                  <div className="space-y-2 pt-2">
                    <div className="text-xs font-semibold text-slate-300">
                      Investigation Steps & Approval Gates:
                    </div>
                    {p.steps.map((step) => (
                      <div
                        key={step.step_number}
                        className="p-3 rounded-lg border border-slate-800 bg-slate-950 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sky-400">Step #{step.step_number}:</span>
                            <span className="text-white font-semibold">{step.description}</span>
                          </div>
                          <div className="text-[11px] text-slate-400">
                            Action: <span className="text-sky-300">{step.action_type}</span> • URL: {step.target_url}
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          {step.approved_by_human ? (
                            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400">
                              <Check className="h-3.5 w-3.5" /> Approved
                            </span>
                          ) : (
                            <button
                              type="button"
                              disabled={isApprovingStep === `${p.id}-${step.step_number}`}
                              onClick={() => handleApproveStep(p.id, step.step_number)}
                              className="inline-flex items-center gap-1.5 rounded bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-600 disabled:opacity-50 shadow-sm"
                            >
                              <Check className="h-3.5 w-3.5" />
                              {isApprovingStep === `${p.id}-${step.step_number}` ? 'Authorizing...' : 'Authorize Step'}
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
