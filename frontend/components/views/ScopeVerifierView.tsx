import React, { useState } from 'react';
import { Target, ScopeDecision } from '../../types';
import { api } from '../../lib/api';
import {
  CheckCircle2,
  XCircle,
  ShieldAlert,
  Search,
  ArrowRight,
  ShieldCheck,
  AlertOctagon,
  Sparkles,
} from 'lucide-react';

interface ScopeVerifierViewProps {
  targets: Target[];
  initialTarget?: Target | null;
}

export const ScopeVerifierView: React.FC<ScopeVerifierViewProps> = ({
  targets,
  initialTarget,
}) => {
  const [selectedTargetId, setSelectedTargetId] = useState(
    initialTarget?.id || (targets.length > 0 ? targets[0].id : '')
  );
  const [hostname, setHostname] = useState('');
  const [url, setUrl] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [decision, setDecision] = useState<ScopeDecision | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedTarget = targets.find((t) => t.id === selectedTargetId) || targets[0];

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
      const res = await api.verifyScope({
        target_id: selectedTargetId,
        hostname: hostname.trim(),
        url: url.trim() || undefined,
      });
      setDecision(res);
    } catch (err: any) {
      setError(err.message || 'Scope verification failed');
    } finally {
      setIsVerifying(false);
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
      <div>
        <h2 className="text-lg font-bold tracking-tight text-white sm:text-xl flex items-center gap-2">
          <CheckCircle2 className="h-5 w-5 text-sky-400" />
          Interactive Scope Authorization Inspector
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Verify whether hostnames and endpoints pass the strict fail-closed boundary rules before scanning.
        </p>
      </div>

      {targets.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8 text-center">
          <ShieldAlert className="mx-auto h-8 w-8 text-slate-500" />
          <h3 className="mt-3 text-sm font-semibold text-slate-300">No Targets Available</h3>
          <p className="mt-1 text-xs text-slate-500">
            Please register an authorized target program in the Targets tab first.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Query Form (2 cols) */}
          <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
            <form onSubmit={handleVerify} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Selected Target Program
                </label>
                <select
                  value={selectedTargetId}
                  onChange={(e) => {
                    setSelectedTargetId(e.target.value);
                    setDecision(null);
                  }}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-white font-mono focus:border-sky-500 focus:outline-none"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} (Root: {t.root_domain})
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Hostname to Check
                  </label>
                  <input
                    type="text"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    placeholder="e.g. api.example.com"
                    className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-white font-mono focus:border-sky-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Target URL (Optional)
                  </label>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="e.g. https://api.example.com/api/v1"
                    className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-white font-mono focus:border-sky-500 focus:outline-none"
                  />
                </div>
              </div>

              {error && (
                <div className="rounded-lg border border-rose-900 bg-rose-950/40 p-3 text-xs font-mono text-rose-300">
                  {error}
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <button
                  type="submit"
                  disabled={isVerifying}
                  className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50 transition-colors"
                >
                  <Search className="h-3.5 w-3.5" />
                  {isVerifying ? 'Evaluating Scope...' : 'Evaluate Scope Policy'}
                </button>
              </div>
            </form>

            {/* Test Presets */}
            {selectedTarget && (
              <div className="border-t border-slate-800 pt-4">
                <span className="text-[11px] font-mono text-slate-400 block mb-2">
                  Test Case Presets for {selectedTarget.root_domain}:
                </span>
                <div className="flex flex-wrap gap-2 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => applyPreset(selectedTarget.root_domain, `https://${selectedTarget.root_domain}/`)}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Exact Domain
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset(`api.${selectedTarget.root_domain}`, `https://api.${selectedTarget.root_domain}/api/v1`)}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Subdomain (api)
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('unauthorized-host.org', 'https://unauthorized-host.org/test')}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Unrelated Domain
                  </button>
                  {selectedTarget.excluded_patterns.length > 0 && (
                    <button
                      type="button"
                      onClick={() => applyPreset(selectedTarget.excluded_patterns[0].replace('*.', 'test.'), '')}
                      className="px-2.5 py-1 rounded bg-rose-950/60 text-rose-300 border border-rose-900/60 hover:bg-rose-900"
                    >
                      Excluded Host
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => applyPreset('bad..host..name', '')}
                    className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white"
                  >
                    Malformed Host
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
    </div>
  );
};
