import React from 'react';
import { useRuntime } from '../context/RuntimeContext';
import {
  FlaskConical,
  AlertCircle,
  ShieldAlert,
  X,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
} from 'lucide-react';

export const DemoBanner: React.FC = () => {
  const {
    mode,
    isDemo,
    isOffline,
    isPartial,
    isUnknown,
    runtimeError,
    clearRuntimeError,
    allowDemoMutations,
    setAllowDemoMutations,
  } = useRuntime();

  // If fully LIVE and no errors, do not show any warning banner
  const showBanner = isDemo || isOffline || isPartial || isUnknown;

  const getBannerStyle = () => {
    if (isUnknown) return 'bg-purple-950/90 border-purple-800 text-purple-200';
    if (isOffline) return 'bg-rose-950/90 border-rose-800 text-rose-200';
    if (isPartial) return 'bg-orange-950/90 border-orange-800 text-orange-200';
    return 'bg-amber-950/90 border-amber-800 text-amber-200';
  };

  const getBannerIcon = () => {
    if (isUnknown) return <HelpCircle className="h-4 w-4 shrink-0 text-purple-400" />;
    if (isOffline) return <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />;
    if (isPartial) return <AlertTriangle className="h-4 w-4 shrink-0 text-orange-400" />;
    return <FlaskConical className="h-4 w-4 shrink-0 text-amber-400" />;
  };

  const getTitle = () => {
    if (isUnknown) return 'RUNTIME UNKNOWN';
    if (isOffline) return 'BACKEND OFFLINE';
    if (isPartial) return 'PARTIAL DEGRADATION';
    return 'DEMO / SYNTHETIC MODE';
  };

  const getSubtitle = () => {
    if (isUnknown) return 'Malformed or unverified health response. All mutations fail-closed.';
    if (isOffline) return 'Cannot connect to NexusHunter Core API (port 8081). Operating in offline view.';
    if (isPartial) return 'Some backend subsystems are unavailable. Mutations are suspended.';
    return 'Displaying simulated fixtures. Live target mutations and active probes are isolated.';
  };

  const getBadgeStyle = () => {
    if (isUnknown) return 'bg-purple-900/60 text-purple-300 border-purple-700/50';
    if (isOffline) return 'bg-rose-900/60 text-rose-300 border-rose-700/50';
    if (isPartial) return 'bg-orange-900/60 text-orange-300 border-orange-700/50';
    return 'bg-amber-900/60 text-amber-300 border-amber-700/50';
  };

  return (
    <div className="flex flex-col w-full overflow-hidden">
      {/* Active Runtime Warning Banner */}
      {showBanner && (
        <div
          id="runtime-demo-banner"
          role="alert"
          aria-label="Runtime operational mode notice"
          className={`w-full border-b px-3 sm:px-4 py-2 text-xs font-mono transition-colors flex flex-wrap items-center justify-between gap-2 sm:gap-3 ${getBannerStyle()}`}
        >
          <div className="flex items-center gap-2 min-w-0 flex-1">
            {getBannerIcon()}
            <div className="truncate min-w-0">
              <span className="font-bold uppercase tracking-wider mr-1.5 whitespace-nowrap">
                {getTitle()}
              </span>
              <span className="text-slate-300 font-sans hidden sm:inline text-[11px] truncate">
                {getSubtitle()}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {isDemo && (
              <button
                type="button"
                onClick={() => setAllowDemoMutations(!allowDemoMutations)}
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded text-[10px] sm:text-[11px] font-sans border transition-colors ${
                  allowDemoMutations
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700 hover:bg-emerald-900'
                    : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200'
                }`}
                title="Toggle whether demo sandbox operations can write synthetic mock records"
              >
                {allowDemoMutations ? (
                  <>
                    <ShieldCheck className="h-3 w-3 text-emerald-400" />
                    <span className="hidden xs:inline">Sandbox Writes:</span> ENABLED
                  </>
                ) : (
                  <>
                    <ShieldAlert className="h-3 w-3 text-amber-400" />
                    <span className="hidden xs:inline">Sandbox Writes:</span> GUARDED
                  </>
                )}
              </button>
            )}

            <span
              className={`rounded px-1.5 sm:px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider border ${getBadgeStyle()}`}
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
          className="w-full border-b border-rose-700 bg-rose-950 px-3 sm:px-4 py-2 text-xs font-mono text-rose-100 flex items-center justify-between gap-3 shadow-md animate-in fade-in"
        >
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" />
            <div className="text-rose-200 truncate">
              <span className="font-bold text-white mr-2 whitespace-nowrap">[POLICY BLOCKED]:</span>
              <span className="break-words">{runtimeError}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={clearRuntimeError}
            className="p-1 rounded text-rose-400 hover:text-rose-100 hover:bg-rose-900/50 shrink-0"
            title="Dismiss error notice"
            aria-label="Dismiss error"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
};
