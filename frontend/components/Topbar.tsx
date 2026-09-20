import React from 'react';
import { Menu, ShieldCheck, Cpu, RefreshCw } from 'lucide-react';
import { HealthResponse } from '../types';

interface TopbarProps {
  id?: string;
  onToggleSidebar: () => void;
  title: string;
  subtitle?: string;
  health: HealthResponse | null;
  onRefresh: () => void;
  isRefreshing?: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({
  id,
  onToggleSidebar,
  title,
  subtitle,
  health,
  onRefresh,
  isRefreshing = false,
}) => {
  return (
    <header
      id={id}
      className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800 bg-slate-950/80 px-4 backdrop-blur-md sm:px-6 lg:px-8"
    >
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onToggleSidebar}
          className="rounded-lg p-2 text-slate-400 hover:bg-slate-900 hover:text-white lg:hidden"
          aria-label="Toggle navigation menu"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div>
          <h1 className="text-base font-semibold tracking-tight text-white sm:text-lg">{title}</h1>
          {subtitle && <p className="hidden text-xs text-slate-400 sm:block">{subtitle}</p>}
        </div>
      </div>

      <div className="flex items-center gap-3 font-mono text-xs">
        {/* Health status pill */}
        <div className="hidden sm:flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900/80 px-3 py-1 text-slate-300">
          <span
            className={`h-2 w-2 rounded-full ${
              health?.status === 'ok' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'
            }`}
          />
          <span className="text-[11px]">API: {health?.status === 'ok' ? 'HEALTHY' : 'CONNECTING'}</span>
        </div>

        {/* Environment Tag */}
        <div className="hidden md:flex items-center gap-1.5 rounded-full border border-sky-900/60 bg-sky-950/40 px-2.5 py-1 text-sky-400 text-[11px]">
          <Cpu className="h-3 w-3" />
          <span>Local-First</span>
        </div>

        {/* Refresh button */}
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white transition-colors disabled:opacity-50"
          title="Refresh telemetry & targets"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
          <span className="hidden sm:inline">Sync</span>
        </button>
      </div>
    </header>
  );
};
