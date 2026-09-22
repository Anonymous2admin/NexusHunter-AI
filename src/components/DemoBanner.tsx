import React from 'react';
import { useRuntime } from '../context/RuntimeContext';
import { FlaskConical, AlertCircle, ShieldAlert } from 'lucide-react';

export const DemoBanner: React.FC = () => {
  const { mode, isDemo, isOffline } = useRuntime();

  if (!isDemo && !isOffline) {
    return null;
  }

  return (
    <div
      id="runtime-demo-banner"
      role="alert"
      aria-label="Runtime demonstration mode notice"
      className={`w-full border-b px-4 py-2 text-xs font-mono transition-colors flex items-center justify-between gap-3 ${
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
          <span className="text-slate-300 font-sans hidden sm:inline">
            {isDemo
              ? 'Displaying simulated fixtures for platform inspection. Mutations and network probes are isolated.'
              : 'Cannot connect to NexusHunter Core API (port 8081). Operating in degraded offline view.'}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
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
  );
};
