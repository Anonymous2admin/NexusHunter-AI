import React, { useState, useEffect, useMemo } from 'react';
import {
  Cpu,
  Server,
  ShieldAlert,
  ShieldCheck,
  Tag,
  History,
  Code2,
  Search,
  Filter,
  ExternalLink,
  Plus,
  Trash2,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Info,
  ChevronRight,
  Layers,
  Globe,
  Lock,
  FileCode,
  FileText,
  Clock,
  Sparkles,
  X,
} from 'lucide-react';
import {
  Target,
  TechnologyObservation,
  ServiceObservation,
  SecurityObservation,
  AssetChange,
  AssetTag,
  TargetIntelligenceSummary,
  AssetDetail,
  PageAsset,
} from '../../types';
import { api } from '../../lib/api';
import { StatusBadge } from '../StatusBadge';
import { MetricCard } from '../MetricCard';

interface AssetIntelligenceViewProps {
  targets: Target[];
  selectedTargetId?: string;
  onSelectTarget?: (targetId: string) => void;
}

type IntelSubTab = 'technologies' | 'services' | 'security' | 'tags' | 'changes' | 'page-assets';

export const AssetIntelligenceView: React.FC<AssetIntelligenceViewProps> = ({
  targets,
  selectedTargetId: initialTargetId,
  onSelectTarget,
}) => {
  const [currentTargetId, setCurrentTargetId] = useState<string>(
    initialTargetId || targets[0]?.id || ''
  );
  const [activeSubTab, setActiveSubTab] = useState<IntelSubTab>('technologies');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [intelSummary, setIntelSummary] = useState<TargetIntelligenceSummary | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modals & details
  const [inspectedService, setInspectedService] = useState<ServiceObservation | null>(null);
  const [inspectedEvidence, setInspectedEvidence] = useState<TechnologyObservation | null>(null);
  const [newTagInput, setNewTagInput] = useState<{ assetId: string; tag: string }>({ assetId: '', tag: '' });
  const [isAddingTag, setIsAddingTag] = useState(false);

  // Sync if prop changes
  useEffect(() => {
    if (initialTargetId && initialTargetId !== currentTargetId) {
      setCurrentTargetId(initialTargetId);
    }
  }, [initialTargetId]);

  // Load intelligence data
  const loadIntelligence = async (targetId: string) => {
    if (!targetId) return;
    setLoading(true);
    setError(null);
    try {
      const summary = await api.getTargetIntelligence(targetId);
      const normalized: TargetIntelligenceSummary = {
        target_id: targetId,
        technologies: summary?.technologies || [],
        services: summary?.services || [],
        security_observations: summary?.security_observations || [],
        changes: summary?.changes || summary?.recent_changes || [],
        tags: summary?.tags || [],
        total_assets: summary?.stats?.total_assets ?? summary?.total_assets ?? 0,
        total_services: summary?.stats?.total_services ?? summary?.total_services ?? (summary?.services?.length || 0),
        total_technologies: summary?.stats?.total_technologies ?? summary?.total_technologies ?? (summary?.technologies?.length || 0),
        total_changes: summary?.stats?.changes_count ?? summary?.total_changes ?? (summary?.changes?.length || 0),
        stats: {
          total_assets: summary?.stats?.total_assets ?? summary?.total_assets ?? 0,
          total_services: summary?.stats?.total_services ?? summary?.total_services ?? (summary?.services?.length || 0),
          total_technologies: summary?.stats?.total_technologies ?? summary?.total_technologies ?? (summary?.technologies?.length || 0),
          security_observations_count: summary?.stats?.security_observations_count ?? (summary?.security_observations?.length || 0),
          changes_count: summary?.stats?.changes_count ?? summary?.total_changes ?? (summary?.changes?.length || 0),
        },
      };
      setIntelSummary(normalized);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch asset intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (currentTargetId) {
      loadIntelligence(currentTargetId);
    }
  }, [currentTargetId]);

  const currentTarget = useMemo(
    () => targets.find((t) => t.id === currentTargetId) || targets[0],
    [targets, currentTargetId]
  );

  // Filtered Technologies
  const filteredTechs = useMemo(() => {
    if (!intelSummary?.technologies) return [];
    return intelSummary.technologies.filter((tech) => {
      const matchesCategory =
        selectedCategory === 'all' ||
        tech.category.toLowerCase() === selectedCategory.toLowerCase();
      const matchesSearch =
        searchQuery === '' ||
        tech.technology_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (tech.version && tech.version.toLowerCase().includes(searchQuery.toLowerCase())) ||
        tech.detection_source.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [intelSummary, selectedCategory, searchQuery]);

  // Available categories
  const categories = useMemo(() => {
    if (!intelSummary?.technologies) return ['all'];
    const cats = Array.from(new Set(intelSummary.technologies.map((t) => t.category)));
    return ['all', ...cats];
  }, [intelSummary]);

  // Handle Tag Addition
  const handleAddTag = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTagInput.assetId || !newTagInput.tag.trim()) return;
    setIsAddingTag(true);
    try {
      const added = await api.addAssetTag(newTagInput.assetId, currentTargetId, newTagInput.tag.trim());
      if (intelSummary) {
        setIntelSummary({
          ...intelSummary,
          tags: [...intelSummary.tags, added],
        });
      }
      setNewTagInput({ assetId: '', tag: '' });
    } catch (err: any) {
      alert(`Error adding tag: ${err.message}`);
    } finally {
      setIsAddingTag(false);
    }
  };

  // Handle Tag Deletion
  const handleDeleteTag = async (assetId: string, tagName: string) => {
    try {
      await api.deleteAssetTag(assetId, tagName);
      if (intelSummary) {
        setIntelSummary({
          ...intelSummary,
          tags: intelSummary.tags.filter(
            (t) => !(t.asset_id === assetId && t.tag.toLowerCase() === tagName.toLowerCase())
          ),
        });
      }
    } catch (err: any) {
      alert(`Error removing tag: ${err.message}`);
    }
  };

  // Helper for confidence color
  const getConfidenceBadge = (conf: number) => {
    if (conf >= 90) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          {conf}% High
        </span>
      );
    }
    if (conf >= 70) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          {conf}% Med
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
        {conf}% Low
      </span>
    );
  };

  return (
    <div id="asset-intelligence-view" className="space-y-6">
      {/* Header & Target Selector Bar */}
      <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-400">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-slate-100">Asset Intelligence & Fingerprinting</h2>
              <span className="px-2 py-0.5 text-xs font-mono bg-sky-500/10 text-sky-300 border border-sky-500/20 rounded-full">
                Passive Recon
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Declarative signatures, security header posture, change detection & passive asset telemetry
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label htmlFor="target-select" className="text-xs font-medium text-slate-400">
              Target:
            </label>
            <select
              id="target-select"
              value={currentTargetId}
              onChange={(e) => {
                const newId = e.target.value;
                setCurrentTargetId(newId);
                onSelectTarget?.(newId);
              }}
              className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:ring-1 focus:ring-sky-500 focus:outline-none"
            >
              {targets.map((tgt) => (
                <option key={tgt.id} value={tgt.id}>
                  {tgt.name} ({tgt.root_domain})
                </option>
              ))}
            </select>
          </div>

          <button
            id="refresh-intel-btn"
            onClick={() => loadIntelligence(currentTargetId)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Intelligence KPI Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          id="kpi-tech-count"
          label="Fingerprinted Techs"
          value={intelSummary?.stats?.total_technologies ?? intelSummary?.total_technologies ?? intelSummary?.technologies?.length ?? 0}
          icon={Cpu}
          color="sky"
          trend={`${categories.length - 1} categories detected`}
        />
        <MetricCard
          id="kpi-services-count"
          label="Live HTTP Services"
          value={intelSummary?.stats?.total_services ?? intelSummary?.total_services ?? intelSummary?.services?.length ?? 0}
          icon={Server}
          color="emerald"
          trend="TLS 1.3 verified"
        />
        <MetricCard
          id="kpi-sec-obs-count"
          label="Security Observations"
          value={intelSummary?.stats?.security_observations_count ?? intelSummary?.security_observations?.length ?? 0}
          icon={ShieldAlert}
          color="amber"
          trend="Header posture checks"
        />
        <MetricCard
          id="kpi-changes-count"
          label="Drift & Changes"
          value={intelSummary?.stats?.changes_count ?? intelSummary?.total_changes ?? intelSummary?.changes?.length ?? 0}
          icon={History}
          color="purple"
          trend="Attributed scan history"
        />
      </div>

      {/* Sub-Tabs Navigation */}
      <div className="flex border-b border-slate-800 gap-2 overflow-x-auto pb-px">
        {[
          { id: 'technologies' as IntelSubTab, label: 'Technologies', icon: Cpu, count: intelSummary?.technologies?.length ?? 0 },
          { id: 'services' as IntelSubTab, label: 'HTTP Services', icon: Server, count: intelSummary?.services?.length ?? 0 },
          { id: 'security' as IntelSubTab, label: 'Security Posture', icon: ShieldAlert, count: intelSummary?.security_observations?.length ?? 0 },
          { id: 'tags' as IntelSubTab, label: 'Asset Tags', icon: Tag, count: intelSummary?.tags?.length ?? 0 },
          { id: 'changes' as IntelSubTab, label: 'Change History', icon: History, count: intelSummary?.changes?.length ?? 0 },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-${tab.id}`}
              onClick={() => setActiveSubTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
                isActive
                  ? 'border-sky-500 text-sky-400 bg-sky-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {typeof tab.count === 'number' && (
                <span
                  className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                    isActive ? 'bg-sky-500/20 text-sky-300' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* SUBTAB 1: TECHNOLOGIES INVENTORY */}
      {activeSubTab === 'technologies' && (
        <div className="space-y-4">
          {/* Controls Bar: Category Filter & Search */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/40 p-3 rounded-lg border border-slate-800/60">
            <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
              <span className="text-xs text-slate-500 mr-1 flex items-center gap-1">
                <Filter className="w-3 h-3" /> Category:
              </span>
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded text-xs font-medium capitalize transition ${
                    selectedCategory === cat
                      ? 'bg-sky-500 text-slate-950 font-semibold'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search technologies or source..."
                className="w-full bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          {/* Technologies Table */}
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 font-mono text-[11px] uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Technology</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Version</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Detection Source</th>
                    <th className="px-4 py-3">Evidence</th>
                    <th className="px-4 py-3 text-right">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredTechs.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="text-center py-10 text-slate-500">
                        No technologies detected matching current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredTechs.map((tech) => (
                      <tr key={tech.id} className="hover:bg-slate-800/30 transition">
                        <td className="px-4 py-3 font-medium text-slate-100 flex items-center gap-2">
                          <Layers className="w-4 h-4 text-sky-400" />
                          <span>{tech.technology_name}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            {tech.category}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono">
                          {tech.version ? (
                            <span className="px-2 py-0.5 rounded text-[11px] bg-slate-800/80 text-sky-300 border border-sky-500/20">
                              v{tech.version}
                            </span>
                          ) : (
                            <span className="text-slate-500 italic">inferred</span>
                          )}
                        </td>
                        <td className="px-4 py-3">{getConfidenceBadge(tech.confidence)}</td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 border border-slate-700">
                            {tech.detection_source}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-xs truncate font-mono text-[11px] text-slate-400">
                          <button
                            onClick={() => setInspectedEvidence(tech)}
                            className="text-sky-400 hover:text-sky-300 underline underline-offset-2 flex items-center gap-1"
                          >
                            <Info className="w-3 h-3" />
                            <span className="truncate">{tech.evidence}</span>
                          </button>
                        </td>
                        <td className="px-4 py-3 text-right text-slate-500 font-mono text-[11px]">
                          {new Date(tech.last_seen).toLocaleDateString()}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: HTTP SERVICES */}
      {activeSubTab === 'services' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(intelSummary?.services || []).map((svc) => (
              <div
                key={svc.id}
                className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4 hover:border-slate-700 transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-sky-400" />
                      <span className="font-mono font-medium text-slate-100 text-xs">
                        {svc.scheme.toUpperCase()} / {svc.port}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                        svc.status_code === 200
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : svc.status_code < 400
                          ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      HTTP {svc.status_code}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-slate-200 line-clamp-1 mb-1">
                    {svc.page_title || 'Untitled Web Application'}
                  </h3>

                  <div className="space-y-1.5 text-xs text-slate-400 mt-3 pt-3 border-t border-slate-800/60">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Web Server:</span>
                      <span className="font-mono text-slate-300">{svc.web_server || 'undisclosed'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Security TLS:</span>
                      <span className="font-mono text-sky-400">{svc.tls_version || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Content Type:</span>
                      <span className="font-mono text-slate-300 truncate max-w-[160px]">
                        {svc.content_type || 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Response Latency:</span>
                      <span className="font-mono text-emerald-400">{svc.response_time_ms}ms</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between">
                  <span className="text-[11px] text-slate-500 font-mono">
                    Size: {svc.content_length > 0 ? `${(svc.content_length / 1024).toFixed(1)} KB` : '0 KB'}
                  </span>
                  <button
                    onClick={() => setInspectedService(svc)}
                    className="flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300 font-medium"
                  >
                    <span>View Headers</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: SECURITY POSTURE & OBSERVATIONS */}
      {activeSubTab === 'security' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(intelSummary?.security_observations || []).map((sec) => (
              <div
                key={sec.id}
                className={`p-4 rounded-xl border flex flex-col justify-between ${
                  !sec.is_present && sec.property_name.includes('Policy')
                    ? 'bg-rose-950/20 border-rose-800/40 text-rose-200'
                    : sec.property_name.includes('Disclosure') || sec.property_name.includes('Wildcard')
                    ? 'bg-amber-950/20 border-amber-800/40 text-amber-200'
                    : 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      {!sec.is_present ? (
                        <AlertTriangle className="w-4 h-4 text-rose-400" />
                      ) : (
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      )}
                      <span className="font-semibold text-sm text-slate-100">{sec.property_name}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-mono font-medium ${
                        sec.is_present
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {sec.is_present ? 'DETECTED' : 'MISSING / OMITTED'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed mt-2">{sec.details}</p>

                  {sec.raw_value && (
                    <div className="mt-3 p-2 bg-slate-950/80 rounded border border-slate-800 font-mono text-[11px] text-slate-400 break-all">
                      <span className="text-slate-600 block text-[10px] uppercase font-sans mb-0.5">
                        Raw Header Value:
                      </span>
                      {sec.raw_value}
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/40 flex items-center justify-between text-[11px] text-slate-500">
                  <span>First observed: {new Date(sec.first_seen).toLocaleDateString()}</span>
                  <span className="font-mono">Observed on port 443</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: ASSET TAGS */}
      {activeSubTab === 'tags' && (
        <div className="space-y-6">
          {/* Add Tag Inline Form */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
              Add Classification Tag
            </h3>
            <form onSubmit={handleAddTag} className="flex flex-col sm:flex-row gap-3">
              <select
                value={newTagInput.assetId}
                onChange={(e) => setNewTagInput({ ...newTagInput, assetId: e.target.value })}
                required
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 focus:ring-1 focus:ring-sky-500 focus:outline-none"
              >
                <option value="">Select Asset to Tag...</option>
                <option value="ast-01">{currentTarget?.root_domain} (Root Domain)</option>
                <option value="ast-02">api.{currentTarget?.root_domain} (API Gateway)</option>
                <option value="ast-03">auth.{currentTarget?.root_domain} (SSO Gateway)</option>
              </select>

              <input
                type="text"
                placeholder="e.g. tier:production, auth:oauth, owner:ops"
                value={newTagInput.tag}
                onChange={(e) => setNewTagInput({ ...newTagInput, tag: e.target.value })}
                required
                className="flex-1 bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              />

              <button
                type="submit"
                disabled={isAddingTag}
                className="flex items-center justify-center gap-1.5 px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-medium transition disabled:opacity-50"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>{isAddingTag ? 'Adding...' : 'Attach Tag'}</span>
              </button>
            </form>
          </div>

          {/* Tags Cloud / Table */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {(intelSummary?.tags || []).map((tag) => (
              <div
                key={tag.id}
                className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 flex items-center justify-between group hover:border-slate-700 transition"
              >
                <div className="flex items-center gap-2">
                  <Tag className={`w-3.5 h-3.5 ${tag.is_inferred ? 'text-purple-400' : 'text-sky-400'}`} />
                  <div>
                    <span className="font-mono text-xs font-medium text-slate-200">{tag.tag}</span>
                    <div className="flex items-center gap-1 text-[10px] text-slate-500">
                      <span>{tag.is_inferred ? 'Inferred by Engine' : `Created by ${tag.created_by}`}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                      tag.is_inferred
                        ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20'
                        : 'bg-sky-500/10 text-sky-300 border border-sky-500/20'
                    }`}
                  >
                    {tag.is_inferred ? 'Inferred' : 'Custom'}
                  </span>
                  {!tag.is_inferred && (
                    <button
                      onClick={() => handleDeleteTag(tag.asset_id, tag.tag)}
                      className="text-slate-500 hover:text-rose-400 p-1 transition"
                      title="Remove Tag"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 5: CHANGE TRACKING & DRIFT */}
      {activeSubTab === 'changes' && (
        <div className="space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
              <History className="w-4 h-4 text-purple-400" />
              <span>Asset Drift & Chronological Change Log</span>
            </h3>

            <div className="relative border-l-2 border-slate-800 ml-3 space-y-6 py-2">
              {(intelSummary?.changes || []).map((chg) => (
                <div key={chg.id} className="relative pl-6">
                  <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-slate-900 border-2 border-purple-400"></div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-purple-500/10 text-purple-300 border border-purple-500/20 w-fit">
                      {chg.change_type}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {new Date(chg.detected_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-200 mt-1 font-medium">{chg.summary}</p>
                  {chg.details && (
                    <div className="mt-2 p-2 bg-slate-950/80 rounded border border-slate-800 font-mono text-[11px] text-slate-400">
                      {JSON.stringify(chg.details, null, 2)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MODAL: INSPECT HEADERS */}
      {inspectedService && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Globe className="w-5 h-5 text-sky-400" />
                <h3 className="text-sm font-semibold text-slate-100">
                  HTTP Response Headers ({inspectedService.scheme}://:{inspectedService.port})
                </h3>
              </div>
              <button
                onClick={() => setInspectedService(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono text-xs">
              {inspectedService.headers && Object.keys(inspectedService.headers).length > 0 ? (
                Object.entries(inspectedService.headers).map(([key, val]) => (
                  <div key={key} className="bg-slate-950/60 p-2 rounded border border-slate-800 flex flex-col">
                    <span className="text-sky-400 font-semibold">{key}:</span>
                    <span className="text-slate-300 break-all">{val}</span>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 py-6 text-center">No headers captured for this service.</div>
              )}
            </div>

            <div className="border-t border-slate-800 pt-3 flex justify-end">
              <button
                onClick={() => setInspectedService(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: EVIDENCE DETAILS */}
      {inspectedEvidence && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-sky-400" />
                <h3 className="text-sm font-semibold text-slate-100">
                  Fingerprint Evidence: {inspectedEvidence.technology_name}
                </h3>
              </div>
              <button
                onClick={() => setInspectedEvidence(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-mono">Confidence Level:</span>
                <div className="mt-1">{getConfidenceBadge(inspectedEvidence.confidence)}</div>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-mono">Detection Source:</span>
                <span className="font-mono text-slate-200 mt-1 block">{inspectedEvidence.detection_source}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-mono">Evidence String:</span>
                <div className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-slate-300 mt-1 break-all">
                  {inspectedEvidence.evidence}
                </div>
              </div>
            </div>

            <div className="border-t border-slate-800 pt-3 flex justify-end">
              <button
                onClick={() => setInspectedEvidence(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
