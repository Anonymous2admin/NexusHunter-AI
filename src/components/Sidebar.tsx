import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Target,
  Radar,
  CheckCircle2,
  Activity,
  Terminal,
  X,
  FileCode2,
  Cpu,
  ShieldAlert,
  Network,
  Brain,
} from 'lucide-react';

export type NavTab = 'dashboard' | 'targets' | 'scans' | 'intel' | 'candidates' | 'investigations' | 'evidence' | 'reasoning' | 'scope-verifier';

interface SidebarProps {
  id?: string;
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isOpen: boolean;
  onClose: () => void;
  targetCount: number;
  jobCount: number;
  candidateCount?: number;
  evidenceCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  id,
  activeTab,
  onSelectTab,
  isOpen,
  onClose,
  targetCount,
  jobCount,
  candidateCount = 2,
  evidenceCount = 3,
}) => {
  const navItems = [
    {
      id: 'dashboard' as NavTab,
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'targets' as NavTab,
      label: 'Authorized Targets',
      icon: Target,
      badge: targetCount > 0 ? targetCount : null,
    },
    {
      id: 'scans' as NavTab,
      label: 'Scan Lifecycle',
      icon: Radar,
      badge: jobCount > 0 ? jobCount : null,
    },
    {
      id: 'intel' as NavTab,
      label: 'Asset Intelligence',
      icon: Cpu,
      badge: 'Assets',
    },
    {
      id: 'candidates' as NavTab,
      label: 'Finding Pipeline',
      icon: ShieldAlert,
      badge: candidateCount > 0 ? candidateCount : 'Hypothesis',
    },
    {
      id: 'investigations' as NavTab,
      label: 'Investigation Graph',
      icon: Network,
      badge: 'Intel',
    },
    {
      id: 'evidence' as NavTab,
      label: 'Evidence & Comparative Analysis',
      icon: FileCode2,
      badge: evidenceCount > 0 ? evidenceCount : 'Verified',
    },
    {
      id: 'reasoning' as NavTab,
      label: 'Security Reasoning & Investigation',
      icon: Brain,
      badge: 'Logic',
    },
    {
      id: 'scope-verifier' as NavTab,
      label: 'Scope Inspector',
      icon: CheckCircle2,
      badge: 'Fail-Closed',
    },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs lg:hidden"
        />
      )}

      {/* Sidebar Container */}
      <aside
        id={id}
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-slate-800 bg-slate-950 px-4 py-5 transition-transform duration-200 ease-in-out lg:static lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="flex items-center justify-between px-2">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-mono text-sm font-bold tracking-tight text-white">NexusHunter</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800/60 font-semibold">AI</span>
              </div>
              <p className="text-[10px] font-mono text-slate-400">Security Research Engine</p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white lg:hidden"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scope Governance Pill */}
        <div className="mt-6 rounded-lg border border-slate-800/90 bg-slate-900/60 p-3">
          <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Scope Policy Active</span>
          </div>
          <p className="mt-1 text-[10px] text-slate-400 leading-tight">
            Strict authorization mode. Probing unauthorized hosts fails closed.
          </p>
        </div>

        {/* Main Navigation */}
        <nav className="mt-6 flex-1 space-y-1">
          <p className="px-2 text-[10px] font-mono font-semibold tracking-wider text-slate-400 uppercase">
            Platform Modules
          </p>
          <div className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    onSelectTab(item.id);
                    onClose();
                  }}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`h-4 w-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== null && (
                    <span
                      className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                        isActive
                          ? 'bg-sky-950 text-sky-300 border border-sky-800/80'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Footer Meta */}
        <div className="border-t border-slate-800/80 pt-4 px-2 space-y-2">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5 text-slate-400" />
              Go Core API
            </span>
            <span className="text-emerald-400 font-semibold">v0.1.0-alpha</span>
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-slate-400" />
              PostgreSQL
            </span>
            <span>Connected</span>
          </div>
        </div>
      </aside>
    </>
  );
};
