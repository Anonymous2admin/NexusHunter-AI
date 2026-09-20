import React, { useState } from 'react';
import { Target } from '../../types';
import { StatusBadge } from '../StatusBadge';
import { DataTable, Column } from '../DataTable';
import { EmptyState } from '../EmptyState';
import { Plus, Target as TargetIcon, Trash2, Shield, AlertTriangle, X, Check } from 'lucide-react';

interface TargetsViewProps {
  targets: Target[];
  onCreateTarget: (payload: {
    name: string;
    root_domain: string;
    allowed_domains: string[];
    allowed_url_patterns: string[];
    excluded_patterns: string[];
  }) => Promise<void>;
  onDeleteTarget: (id: string) => Promise<void>;
  onSelectTargetForVerify?: (target: Target) => void;
  onSelectTargetForIntel?: (target: Target) => void;
}

export const TargetsView: React.FC<TargetsViewProps> = ({
  targets,
  onCreateTarget,
  onDeleteTarget,
  onSelectTargetForVerify,
  onSelectTargetForIntel,
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null);

  // Form states
  const [name, setName] = useState('');
  const [rootDomain, setRootDomain] = useState('');
  const [allowedDomains, setAllowedDomains] = useState('');
  const [allowedURLPatterns, setAllowedURLPatterns] = useState('');
  const [excludedPatterns, setExcludedPatterns] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError('Target program name is required.');
      return;
    }
    if (!rootDomain.trim()) {
      setFormError('Root domain is required (e.g. example.com).');
      return;
    }

    const parseList = (str: string) =>
      str
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean);

    setIsSubmitting(true);
    try {
      await onCreateTarget({
        name: name.trim(),
        root_domain: rootDomain.trim(),
        allowed_domains: parseList(allowedDomains),
        allowed_url_patterns: parseList(allowedURLPatterns),
        excluded_patterns: parseList(excludedPatterns),
      });

      // Reset and close
      setName('');
      setRootDomain('');
      setAllowedDomains('');
      setAllowedURLPatterns('');
      setExcludedPatterns('');
      setIsModalOpen(false);
    } catch (err: any) {
      setFormError(err.message || 'Failed to register target.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const columns: Column<Target>[] = [
    {
      header: 'Program Name',
      accessor: (t) => (
        <div className="font-sans">
          <div className="font-semibold text-white">{t.name}</div>
          <div className="font-mono text-[11px] text-slate-400">{t.root_domain}</div>
        </div>
      ),
    },
    {
      header: 'Allowed Domains',
      accessor: (t) => (
        <div className="max-w-[200px] truncate text-slate-300">
          {t.allowed_domains.length > 0 ? t.allowed_domains.join(', ') : t.root_domain}
        </div>
      ),
    },
    {
      header: 'Excluded Patterns',
      accessor: (t) => (
        <div className="max-w-[180px] truncate text-rose-400">
          {t.excluded_patterns.length > 0 ? t.excluded_patterns.join(', ') : 'None'}
        </div>
      ),
    },
    {
      header: 'Status',
      accessor: (t) => <StatusBadge status={t.status} />,
    },
    {
      header: 'Actions',
      accessor: (t) => (
        <div className="flex items-center gap-2">
          {onSelectTargetForIntel && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onSelectTargetForIntel(t);
              }}
              className="px-2 py-1 text-[11px] font-mono rounded bg-purple-950/60 text-purple-300 border border-purple-800/60 hover:bg-purple-900 transition-colors"
            >
              Intel
            </button>
          )}
          {onSelectTargetForVerify && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onSelectTargetForVerify(t);
              }}
              className="px-2 py-1 text-[11px] font-mono rounded bg-sky-950 text-sky-400 border border-sky-800/60 hover:bg-sky-900 transition-colors"
            >
              Verify Scope
            </button>
          )}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              if (confirm(`Delete authorized target '${t.name}'? All attributable scan history will remain.`)) {
                onDeleteTarget(t.id);
              }
            }}
            className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 transition-colors"
            title="Delete target"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header and Add Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold tracking-tight text-white sm:text-xl">
            Authorized Target Inventory
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure explicit bug bounty domains, URL path restrictions, and out-of-scope exclusions.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setIsModalOpen(true)}
          className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-500 transition-colors self-start sm:self-auto"
        >
          <Plus className="h-4 w-4" />
          Authorize New Target
        </button>
      </div>

      {/* Target Table or Empty State */}
      {targets.length === 0 ? (
        <EmptyState
          id="empty-targets"
          title="No Authorized Targets Configured"
          description="NexusHunter-AI operates under a strict fail-closed authorization model. Add a verified target domain to begin security testing."
          icon={TargetIcon}
          actionLabel="Add Target Program"
          onAction={() => setIsModalOpen(true)}
        />
      ) : (
        <DataTable
          id="targets-table"
          columns={columns}
          data={targets}
          keyExtractor={(t) => t.id}
          onRowClick={(t) => setSelectedTarget(t)}
        />
      )}

      {/* Target Detail Drawer Modal */}
      {selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-sky-400" />
                <h3 className="text-base font-semibold text-white">{selectedTarget.name}</h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedTarget(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="mt-4 space-y-3 font-mono text-xs">
              <div>
                <span className="text-slate-500 uppercase text-[10px] tracking-wider">Target ID</span>
                <div className="text-slate-200 mt-0.5">{selectedTarget.id}</div>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] tracking-wider">Root Domain</span>
                <div className="text-sky-400 mt-0.5">{selectedTarget.root_domain}</div>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] tracking-wider">Allowed Domains</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selectedTarget.allowed_domains.length > 0 ? (
                    selectedTarget.allowed_domains.map((d, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
                        {d}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-400">{selectedTarget.root_domain}</span>
                  )}
                </div>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] tracking-wider">Allowed URL Patterns</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selectedTarget.allowed_url_patterns.length > 0 ? (
                    selectedTarget.allowed_url_patterns.map((p, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800 text-[11px]">
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-400">All paths allowed under in-scope domains</span>
                  )}
                </div>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] tracking-wider">Excluded Patterns</span>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selectedTarget.excluded_patterns.length > 0 ? (
                    selectedTarget.excluded_patterns.map((p, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800 text-[11px]">
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-400">None explicitly excluded</span>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedTarget(null)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Target Creation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs overflow-y-auto">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-semibold text-white">Authorize Target Program</h3>
                <p className="text-xs text-slate-400">Establish cryptographic and scoped testing boundaries.</p>
              </div>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="mt-4 space-y-4 text-xs font-sans">
              {formError && (
                <div className="rounded-lg border border-rose-900/80 bg-rose-950/40 p-3 text-rose-400 font-mono text-[11px]">
                  {formError}
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Program / Target Name *
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Acme Corp Bug Bounty"
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white placeholder-slate-600 focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Root Domain *
                </label>
                <input
                  type="text"
                  required
                  value={rootDomain}
                  onChange={(e) => setRootDomain(e.target.value)}
                  placeholder="e.g. acme.com"
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white placeholder-slate-600 font-mono focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Allowed Domains (comma or newline separated)
                </label>
                <textarea
                  rows={2}
                  value={allowedDomains}
                  onChange={(e) => setAllowedDomains(e.target.value)}
                  placeholder="e.g. acme.com, *.acme.com, api.partner-acme.net"
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white placeholder-slate-600 font-mono text-[11px] focus:border-sky-500 focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">
                  Explicit wildcards like *.acme.com are permitted. Broad wildcards (*) are forbidden.
                </span>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Allowed URL Patterns (optional)
                </label>
                <input
                  type="text"
                  value={allowedURLPatterns}
                  onChange={(e) => setAllowedURLPatterns(e.target.value)}
                  placeholder="e.g. /api/*, /v1/*"
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white placeholder-slate-600 font-mono text-[11px] focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Excluded Patterns (optional, takes highest precedence)
                </label>
                <input
                  type="text"
                  value={excludedPatterns}
                  onChange={(e) => setExcludedPatterns(e.target.value)}
                  placeholder="e.g. admin.acme.com, *.corp.acme.com, /api/destructive"
                  className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-white placeholder-slate-600 font-mono text-[11px] focus:border-sky-500 focus:outline-none"
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
                  {isSubmitting ? 'Validating Scope...' : 'Confirm & Authorize'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
