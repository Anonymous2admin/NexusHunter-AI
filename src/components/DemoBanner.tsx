import React from 'react';
import { useRuntime } from '../context/RuntimeContext';
import { FlaskConical, AlertCircle, ShieldAlert, X, ShieldCheck, ToggleLeft, ToggleRight } from 'lucide-react';

export const DemoBanner: React.FC = () => {
  const {
    mode,
    isDemo,
    isOffline,
    runtimeError,
    clearRuntimeError,
    allowDemoMutations,
    setAllowDemoMutations,
  } = useRuntime();

  return (
    <div className="flex flex-col w-full">
      {/* Active Runtime Warning Banner */}
      {(isDemo || isOffline) && (
        <div
          id="runtime-demo-banner"
          role="alert"
          aria-label="Runtime demonstration mode notice"
          className={`w-full border-b px-4 py-2 text-xs font-mono transition-colors flex flex-wrap items-center justify-between gap-3 ${
            isDemo
              ? 'bg-amber-950/90 border-amber-800 text-amber-200'
              : 'bg-rose-950/90 border-rose-800 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            {isDemo ? (
              <FlaskConical className="h-4 w-4 shrink-0 text-amber-400" />
            ) : (
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
            )}
            <div className="truncate">
              <span className="font-bold uppercase tracking-wider mr-2">
                {isDemo ? 'DEMO / SYNTHETIC MODE' : 'BACKEND OFFLINE'}
              </span>
              <span className="text-slate-300 font-sans hidden md:inline">
                {isDemo
                  ? 'Displaying simulated fixtures. Live target mutations and active probes are isolated.'
                  : 'Cannot connect to NexusHunter Core API (port 8081). Operating in degraded offline view.'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {isDemo && (
              <button
                type="button"
                onClick={() => setAllowDemoMutations(!allowDemoMutations)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-sans border transition-colors ${
                  allowDemoMutations
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700 hover:bg-emerald-900'
                    : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200'
                }`}
                title="Toggle whether demo sandbox operations can write synthetic mock records"
              >
                {allowDemoMutations ? (
                  <>
                    <ShieldCheck className="h-3 w-3 text-emerald-400" />
                    <span>Sandbox Writes: ENABLED</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert className="h-3 w-3 text-amber-400" />
                    <span>Sandbox Writes: GUARDED</span>
                  </>
                )}
              </button>
            )}

            <span
              className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                isDemo
                  ? 'bg-amber-900/60 text-amber-300 border border-amber-700/50'
                  : 'bg-rose-900/60 text-rose-300 border border-rose-700/50'
              }`}
            >
              {mode}
            </span>
          </div>
        </div>
      )}

      {/* High-Visibility Runtime Rejection Alert */}
      {runtimeError && (
        <div
          id="runtime-error-alert"
          role="alert"
          className="w-full border-b border-rose-700 bg-rose-950 px-4 py-2 text-xs font-mono text-rose-100 flex items-center justify-between gap-3 shadow-md animate-in fade-in"
        >
          <div className="flex items-center gap-2 min-w-0">
            <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" />
            <div className="text-rose-200">
              <span className="font-bold text-white mr-2">[RUNTIME POLICY BLOCKED]:</span>
              <span>{runtimeError}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={clearRuntimeError}
            className="p-1 rounded text-rose-400 hover:bg-rose-900 hover:text-white transition-colors"
            title="Dismiss error"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </div>
  );
};
