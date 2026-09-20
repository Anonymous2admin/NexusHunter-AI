import React from 'react';
import { Target, ScanJob, SystemEvent } from '../../types';
import { MetricCard } from '../MetricCard';
import { StatusBadge } from '../StatusBadge';
import { DataTable, Column } from '../DataTable';
import { EmptyState } from '../EmptyState';
import {
  Target as TargetIcon,
  Radar,
  CheckCircle2,
  AlertOctagon,
  Clock,
  ExternalLink,
  ShieldCheck,
  Flame,
} from 'lucide-react';

interface DashboardViewProps {
  targets: Target[];
  jobs: ScanJob[];
  events: SystemEvent[];
  onNavigateToTargets: () => void;
  onNavigateToScans: () => void;
  onNavigateToVerifier: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  targets,
  jobs,
  events,
  onNavigateToTargets,
  onNavigateToScans,
  onNavigateToVerifier,
}) => {
  const activeTargets = targets.filter((t) => t.status === 'ACTIVE').length;
  const runningJobs = jobs.filter((j) => j.status === 'RUNNING').length;
  const completedJobs = jobs.filter((j) => j.status === 'COMPLETED').length;
  const failedJobs = jobs.filter((j) => j.status === 'FAILED').length;

  const jobColumns: Column<ScanJob>[] = [
    {
      header: 'Job ID',
      accessor: (j) => <span className="text-sky-400 font-semibold">{j.id}</span>,
    },
    {
      header: 'Target ID',
      accessor: (j) => <span className="text-slate-400">{j.target_id}</span>,
    },
    {
      header: 'Type',
      accessor: (j) => <span className="text-slate-200">{j.type}</span>,
    },
    {
      header: 'Status',
      accessor: (j) => <StatusBadge status={j.status} />,
    },
    {
      header: 'Created',
      accessor: (j) => (
        <span className="text-slate-400 font-mono text-[11px]">
          {new Date(j.created_at).toLocaleTimeString()}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          id="metric-authorized-targets"
          title="Authorized Targets"
          value={targets.length}
          subtitle={`${activeTargets} actively authorized for testing`}
          icon={TargetIcon}
          accent="sky"
        />
        <MetricCard
          id="metric-running-jobs"
          title="Active Scans"
          value={runningJobs}
          subtitle="Scoped non-destructive reconnaissance"
          icon={Radar}
          accent="amber"
        />
        <MetricCard
          id="metric-completed-jobs"
          title="Completed Jobs"
          value={completedJobs}
          subtitle="Evidence recorded and verifiable"
          icon={CheckCircle2}
          accent="emerald"
        />
        <MetricCard
          id="metric-scope-enforcement"
          title="Scope Engine"
          value="Fail-Closed"
          subtitle="Strict boundary verification active"
          icon={ShieldCheck}
          accent="slate"
        />
      </div>

      {/* Safety Mandate Banner */}
      <div className="rounded-xl border border-sky-900/40 bg-gradient-to-r from-sky-950/40 via-slate-900/60 to-slate-950 p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400 mt-0.5">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                NexusHunter-AI Safety & Authorization Invariants
              </h3>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed max-w-2xl">
                Every probe requires attributable scope. Broad wildcards, credential theft, persistence,
                and destructive exploitation are architecturally banned. All telemetry is reproducible and auditable.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onNavigateToVerifier}
            className="inline-flex items-center gap-2 rounded-lg border border-sky-700/60 bg-sky-900/40 px-3.5 py-2 text-xs font-medium text-sky-300 hover:bg-sky-800/50 hover:text-white transition-colors whitespace-nowrap self-start sm:self-auto"
          >
            <CheckCircle2 className="h-4 w-4 text-sky-400" />
            Test Scope Rules
          </button>
        </div>
      </div>

      {/* Two Column Section: Recent Scans & Scope Targets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans (2 Cols on lg) */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radar className="h-4 w-4 text-sky-400" />
              <h2 className="text-sm font-semibold tracking-tight text-white uppercase tracking-wider font-mono">
                Recent Scan Jobs
              </h2>
            </div>
            <button
              type="button"
              onClick={onNavigateToScans}
              className="text-xs font-mono text-sky-400 hover:text-sky-300 inline-flex items-center gap-1"
            >
              View All <ExternalLink className="h-3 w-3" />
            </button>
          </div>

          {jobs.length === 0 ? (
            <EmptyState
              id="empty-jobs-dashboard"
              title="No Scan Jobs Initialized"
              description="Configure an authorized target to enqueue passive reconnaissance jobs and track lifecycle events."
              icon={Radar}
              actionLabel="Go to Targets"
              onAction={onNavigateToTargets}
            />
          ) : (
            <DataTable
              id="dashboard-jobs-table"
              columns={jobColumns}
              data={jobs.slice(0, 5)}
              keyExtractor={(j) => j.id}
            />
          )}
        </div>

        {/* System & Audit Telemetry Feed (1 Col on lg) */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-slate-400" />
            <h2 className="text-sm font-semibold tracking-tight text-white uppercase tracking-wider font-mono">
              Event Telemetry
            </h2>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            {events.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono text-center py-6">
                No events recorded yet.
              </p>
            ) : (
              <div className="space-y-3 max-h-[320px] overflow-y-auto pr-1">
                {events.slice(0, 8).map((evt) => (
                  <div
                    key={evt.event_id}
                    className="border-b border-slate-800/60 pb-2.5 last:border-b-0 last:pb-0"
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <span className="text-sky-400 font-semibold">{evt.event_type}</span>
                      <span className="text-slate-500 text-[10px]">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    {evt.job_id && (
                      <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                        job: {evt.job_id}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
