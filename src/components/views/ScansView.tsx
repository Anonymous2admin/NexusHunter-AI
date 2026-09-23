import React, { useState } from 'react';
import { ScanJob, Target } from '../../types';
import { useRuntime } from '../../context/RuntimeContext';
import { StatusBadge } from '../StatusBadge';
import { DataTable, Column } from '../DataTable';
import { EmptyState } from '../EmptyState';
import {
  Radar,
  Plus,
  Play,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Clock,
  X,
  FileJson,
} from 'lucide-react';

interface ScansViewProps {
  jobs: ScanJob[];
  targets: Target[];
  onCreateJob: (payload: { target_id: string; type: string; metadata?: any }) => Promise<void>;
  onStartJob?: (id: string) => Promise<void>;
  onCompleteJob?: (id: string) => Promise<void>;
  onFailJob?: (id: string, error: string) => Promise<void>;
  onCancelJob?: (id: string) => Promise<void>;
}

export const ScansView: React.FC<ScansViewProps> = ({
  jobs,
  targets,
  onCreateJob,
  onStartJob,
  onCompleteJob,
  onFailJob,
  onCancelJob,
}) => {
  const { mode, assertLiveOrThrow, showRuntimeError } = useRuntime();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [jobType, setJobType] = useState('HIGH_SPEED_RECON');
  const [depth, setDepth] = useState('1');
  const [reconOptions, setReconOptions] = useState({
    subdomain_discovery: true,
    dns_resolution: true,
    http_probe: true,
    crawl: true,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null);

  const availableTypes = [
    { value: 'HIGH_SPEED_RECON', label: 'High-Speed Recon Engine (Full Pipeline)' },
    { value: 'PASSIVE_DNS_ENUMERATION', label: 'Passive DNS & Subdomain Recon' },
    { value: 'CERT_TRANSPARENCY_LOGS', label: 'Certificate Transparency Query (SANs)' },
    { value: 'WHOIS_AND_ASN_LOOKUP', label: 'WHOIS & Autonomous System Lookup' },
    { value: 'PASSIVE_TECH_FINGERPRINT', label: 'Passive Web Technology Fingerprint' },
  ];

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTargetId) return;

    setIsSubmitting(true);
    try {
      assertLiveOrThrow('create scan job');
      await onCreateJob({
        target_id: selectedTargetId,
        type: jobType,
        metadata: {
          depth: parseInt(depth, 10) || 1,
          mode: 'safe_passive_non_destructive',
          attribution_verified: true,
          options: reconOptions,
        },
      });
      setIsModalOpen(false);
    } catch (err: any) {
      showRuntimeError(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const columns: Column<ScanJob>[] = [
    {
      header: 'Job Identifier',
      accessor: (j) => (
        <div>
          <span className="font-semibold text-sky-400">{j.id}</span>
          <div className="text-[10px] text-slate-400 font-mono">tgt: {j.target_id}</div>
        </div>
      ),
    },
    {
      header: 'Scan Type',
      accessor: (j) => <span className="text-slate-200 font-mono text-xs">{j.type}</span>,
    },
    {
      header: 'Status',
      accessor: (j) => <StatusBadge status={j.status} />,
    },
    {
      header: 'Timestamps',
      accessor: (j) => (
        <div className="font-mono text-[10px] text-slate-400 space-y-0.5">
          <div>Queued: {new Date(j.created_at).toLocaleTimeString()}</div>
          {j.started_at && <div className="text-sky-400/80">Start: {new Date(j.started_at).toLocaleTimeString()}</div>}
          {j.completed_at && <div className="text-emerald-400/80">End: {new Date(j.completed_at).toLocaleTimeString()}</div>}
        </div>
      ),
    },
    {
      header: 'Lifecycle Actions',
      accessor: (j) => (
        <div className="flex items-center gap-1.5 font-mono text-[10px]">
          {j.status === 'QUEUED' && onStartJob && (
            <button
              type="button"
              onClick={async (e) => {
                e.stopPropagation();
                try {
                  assertLiveOrThrow('start scan job');
                  await onStartJob(j.id);
                } catch (err: any) {
                  showRuntimeError(err);
                }
              }}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-sky-950 text-sky-400 border border-sky-800 hover:bg-sky-900"
            >
              <Play className="h-3 w-3" /> Start
            </button>
          )}

          {j.status === 'RUNNING' && (
            <>
              {onCompleteJob && (
                <button
                  type="button"
                  onClick={async (e) => {
                    e.stopPropagation();
                    try {
                      assertLiveOrThrow('complete scan job');
                      await onCompleteJob(j.id);
                    } catch (err: any) {
                      showRuntimeError(err);
                    }
                  }}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 hover:bg-emerald-900"
                >
                  <CheckCircle2 className="h-3 w-3" /> Complete
                </button>
              )}
              {onFailJob && (
                <button
                  type="button"
                  onClick={async (e) => {
                    e.stopPropagation();
                    const reason = prompt('Enter failure reason:', 'Handshake timeout');
                    if (reason) {
                      try {
                        assertLiveOrThrow('fail scan job');
                        await onFailJob(j.id, reason);
                      } catch (err: any) {
                        showRuntimeError(err);
                      }
                    }
                  }}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded bg-rose-950 text-rose-400 border border-rose-800 hover:bg-rose-900"
                >
                  <AlertCircle className="h-3 w-3" /> Fail
                </button>
              )}
            </>
          )}

          {(j.status === 'QUEUED' || j.status === 'RUNNING') && onCancelJob && (
            <button
              type="button"
              onClick={async (e) => {
                e.stopPropagation();
                try {
                  assertLiveOrThrow('cancel scan job');
                  await onCancelJob(j.id);
                } catch (err: any) {
                  showRuntimeError(err);
                }
              }}
              className="px-2 py-1 rounded bg-slate-800 text-slate-400 hover:bg-slate-700"
            >
              Cancel
            </button>
          )}

          <button
            type="button"
            onClick={() => setSelectedJob(j)}
            className="px-2 py-1 rounded text-slate-400 hover:text-white"
            title="Inspect Metadata"
          >
            <FileJson className="h-3.5 w-3.5" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold tracking-tight text-white sm:text-xl">
            Scan Jobs & Lifecycle Management
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Scoped reconnaissance tasks strictly attributable to authorized target programs.
          </p>
        </div>

        <button
          type="button"
          disabled={targets.length === 0}
          onClick={() => {
            if (targets.length > 0) {
              setSelectedTargetId(targets[0].id);
              setIsModalOpen(true);
            }
          }}
          className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50 transition-colors self-start sm:self-auto"
        >
          <Plus className="h-4 w-4" />
          Enqueue Scoped Scan
        </button>
      </div>

      {/* Notice if no targets */}
      {targets.length === 0 && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-xs text-amber-300 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 shrink-0 text-amber-400" />
          <span>You must create at least one authorized target before enqueuing scan jobs.</span>
        </div>
      )}

      {/* Jobs Table or Empty State */}
      {jobs.length === 0 ? (
        <EmptyState
          id="empty-scans"
          title="No Active or Historic Scans"
          description="Enqueue a scoped reconnaissance pass to observe DNS records, Certificate Transparency logs, or ASN affiliations."
          icon={Radar}
          actionLabel={targets.length > 0 ? 'Enqueue First Scan' : 'Configure Targets'}
          onAction={() => {
            if (targets.length > 0) {
              setSelectedTargetId(targets[0].id);
              setIsModalOpen(true);
            }
          }}
        />
      ) : (
        <DataTable
          id="scans-table"
          columns={columns}
          data={jobs}
          keyExtractor={(j) => j.id}
          onRowClick={(j) => setSelectedJob(j)}
        />
      )}

      {/* Metadata Detail Modal */}
      {selectedJob && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Radar className="h-5 w-5 text-sky-400" />
                <h3 className="text-sm font-semibold text-white">Job Details: {selectedJob.id}</h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedJob(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="mt-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Target ID:</span>
                <span className="text-sky-400">{selectedJob.target_id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Status:</span>
                <StatusBadge status={selectedJob.status} />
              </div>
              {selectedJob.error && (
                <div className="p-2 rounded bg-rose-950/60 border border-rose-900 text-rose-300 text-[11px]">
                  Error: {selectedJob.error}
                </div>
              )}
              <div>
                <span className="text-slate-400 block mb-1">Metadata:</span>
                <pre className="rounded bg-slate-950 p-3 text-[11px] text-slate-300 border border-slate-800 overflow-x-auto">
                  {JSON.stringify(selectedJob.metadata || {}, null, 2)}
                </pre>
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedJob(null)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Enqueue Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-semibold text-white">Enqueue Scoped Scan Job</h3>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreate} className="mt-4 space-y-4 text-xs font-sans">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Target Program *
                </label>
                <select
                  required
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white font-mono focus:border-sky-500 focus:outline-none"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.root_domain})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Reconnaissance Type *
                </label>
                <select
                  value={jobType}
                  onChange={(e) => setJobType(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white focus:border-sky-500 focus:outline-none"
                >
                  {availableTypes.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>

              {jobType === 'HIGH_SPEED_RECON' && (
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2">
                  <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Engine Pipeline Stages
                  </span>
                  <div className="grid grid-cols-2 gap-2 text-slate-300 text-[11px]">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reconOptions.subdomain_discovery}
                        onChange={(e) =>
                          setReconOptions((prev) => ({ ...prev, subdomain_discovery: e.target.checked }))
                        }
                        className="rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-0"
                      />
                      Subdomain Discovery
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reconOptions.dns_resolution}
                        onChange={(e) =>
                          setReconOptions((prev) => ({ ...prev, dns_resolution: e.target.checked }))
                        }
                        className="rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-0"
                      />
                      DNS Resolution
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reconOptions.http_probe}
                        onChange={(e) =>
                          setReconOptions((prev) => ({ ...prev, http_probe: e.target.checked }))
                        }
                        className="rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-0"
                      />
                      HTTP Probing
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={reconOptions.crawl}
                        onChange={(e) =>
                          setReconOptions((prev) => ({ ...prev, crawl: e.target.checked }))
                        }
                        className="rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-0"
                      />
                      Scoped Web Crawl
                    </label>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Recursion Depth
                </label>
                <input
                  type="number"
                  min={1}
                  max={3}
                  value={depth}
                  onChange={(e) => setDepth(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white font-mono focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div className="mt-6 flex justify-end gap-3 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
                >
                  {isSubmitting ? 'Enqueueing...' : 'Enqueue Scan'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
