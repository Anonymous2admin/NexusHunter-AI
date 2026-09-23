import React, { useState, useEffect } from 'react';
import {
  Target,
  GraphData,
  GraphNode,
  GraphEdge,
  TemporalChangeRecord,
  InvariantSignal,
  BehaviorDifference,
  InvestigationCluster,
  ResearchMemory,
} from '../../types';
import { api } from '../../lib/api';
import { useRuntime } from '../../context/RuntimeContext';
import {
  Network,
  History,
  GitCompare,
  Layers,
  Sparkles,
  Shield,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Play,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  Clock,
  Search,
  Filter,
  RefreshCw,
  Database,
  Sliders,
} from 'lucide-react';

interface InvestigationEngineViewProps {
  targets: Target[];
  selectedTargetId: string;
  onSelectTarget: (id: string) => void;
}

type SubTab = 'clusters' | 'graph' | 'temporal' | 'invariants' | 'behavior' | 'memory';

export const InvestigationEngineView: React.FC<InvestigationEngineViewProps> = ({
  targets,
  selectedTargetId,
  onSelectTarget,
}) => {
  const { mode, assertLiveOrThrow, showRuntimeError } = useRuntime();
  const [activeSubTab, setActiveSubTab] = useState<SubTab>('clusters');
  const [isLoading, setIsLoading] = useState(false);

  // Core Data
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [temporalChanges, setTemporalChanges] = useState<TemporalChangeRecord[]>([]);
  const [invariants, setInvariants] = useState<InvariantSignal[]>([]);
  const [behaviorDiffs, setBehaviorDiffs] = useState<BehaviorDifference[]>([]);
  const [clusters, setClusters] = useState<InvestigationCluster[]>([]);
  const [researchMemory, setResearchMemory] = useState<ResearchMemory | null>(null);
  const [selectedCluster, setSelectedCluster] = useState<InvestigationCluster | null>(null);

  // Validation State
  const [validatingClusterId, setValidatingClusterId] = useState<string | null>(null);
  const [validationFact, setValidationFact] = useState<string | null>(null);

  const activeTargetId = selectedTargetId || (targets[0]?.id ?? '');

  const loadAllIntelligence = async () => {
    if (!activeTargetId) return;
    setIsLoading(true);
    try {
      const [g, t, inv, diff, cl, mem] = await Promise.all([
        api.getTargetGraph(activeTargetId).catch(() => null),
        api.getTemporalChanges(activeTargetId).catch(() => []),
        api.getInvariants(activeTargetId).catch(() => []),
        api.getBehaviorDifferences(activeTargetId).catch(() => []),
        api.getInvestigationClusters(activeTargetId).catch(() => []),
        api.getResearchMemory(activeTargetId).catch(() => null),
      ]);

      setGraphData(g);
      setTemporalChanges(t);
      setInvariants(inv);
      setBehaviorDiffs(diff);
      setClusters(cl);
      setResearchMemory(mem);

      if (cl.length > 0 && !selectedCluster) {
        setSelectedCluster(cl[0]);
      }
      if (g && g.nodes.length > 0 && !selectedNode) {
        setSelectedNode(g.nodes[0]);
      }
    } catch (err) {
      console.error('Failed to load intelligence components', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAllIntelligence();
  }, [activeTargetId]);

  const handleExecuteValidation = async (cluster: InvestigationCluster) => {
    setValidatingClusterId(cluster.id);
    setValidationFact(null);
    try {
      assertLiveOrThrow('execute controlled cluster validation');
      const res = await api.executeControlledValidation({
        target_id: activeTargetId,
        cluster_id: cluster.id,
      });
      setValidationFact(res.output_fact || 'Safe probe confirmed expected behavior.');
      await api.updateClusterStatus(cluster.id, 'VALIDATING');
      await loadAllIntelligence();
    } catch (err: any) {
      showRuntimeError(err);
      console.error('Failed to validate cluster', err);
    } finally {
      setValidatingClusterId(null);
    }
  };

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'TARGET':
        return '#0284c7'; // sky-600
      case 'DOMAIN':
        return '#3b82f6'; // blue-500
      case 'SUBDOMAIN':
        return '#6366f1'; // indigo-500
      case 'IP':
        return '#8b5cf6'; // purple-500
      case 'HTTP_SERVICE':
        return '#10b981'; // emerald-500
      case 'TECHNOLOGY':
        return '#f59e0b'; // amber-500
      case 'AUTH_BOUNDARY':
        return '#ec4899'; // pink-500
      case 'CANDIDATE':
        return '#ef4444'; // red-500
      default:
        return '#64748b'; // slate-500
    }
  };

  return (
    <div id="investigation-engine-view" className="space-y-6">
      {/* Top Banner & Target Selector */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-1 text-xs font-mono font-medium text-indigo-400">
              <Network className="h-3.5 w-3.5" />
              Security Investigation Engine
            </span>
            <span className="text-xs font-mono text-slate-500">• Asset Graph & Temporal State</span>
          </div>
          <h2 className="mt-2 text-xl font-bold text-white tracking-tight">Differentiated Security Intelligence</h2>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl leading-relaxed">
            Multi-factor relationship graphing, chronological difference detection, state-machine invariant tracking,
            and prioritized investigation clusters.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label htmlFor="target-select-invest" className="text-xs font-mono text-slate-400">
            Target:
          </label>
          <select
            id="target-select-invest"
            value={activeTargetId}
            onChange={(e) => onSelectTarget(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-hidden"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.root_domain})
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={loadAllIntelligence}
            disabled={isLoading}
            className="rounded-lg border border-slate-700 bg-slate-800 p-2 text-slate-300 hover:text-white"
            title="Refresh Intelligence"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 pb-2">
        <button
          type="button"
          onClick={() => setActiveSubTab('clusters')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
            activeSubTab === 'clusters'
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <Layers className="h-4 w-4" />
          <span>Investigation Clusters ({clusters.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('graph')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
            activeSubTab === 'graph'
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <Network className="h-4 w-4" />
          <span>Asset Graph ({graphData?.total_nodes || 0} nodes)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('temporal')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
            activeSubTab === 'temporal'
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <History className="h-4 w-4" />
          <span>What Changed ({temporalChanges.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('invariants')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
            activeSubTab === 'invariants'
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="h-4 w-4" />
          <span>State Invariants ({invariants.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('behavior')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
            activeSubTab === 'behavior'
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <GitCompare className="h-4 w-4" />
          <span>Differential Probing ({behaviorDiffs.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('memory')}
          className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
            activeSubTab === 'memory'
              ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
          }`}
        >
          <Database className="h-4 w-4" />
          <span>Research Memory</span>
        </button>
      </div>

      {/* 1. INVESTIGATION CLUSTERS VIEW (Priority Scoring & Actionable Queues) */}
      {activeSubTab === 'clusters' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Left: Cluster List */}
            <div className="lg:col-span-5 space-y-3">
              <div className="flex items-center justify-between px-1">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Prioritized Clusters
                </span>
                <span className="text-[11px] font-mono text-slate-500">Sorted by Priority Score</span>
              </div>

              {clusters.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center">
                  <CheckCircle2 className="mx-auto h-8 w-8 text-slate-500" />
                  <p className="mt-2 text-sm font-medium text-slate-300">No Investigation Clusters</p>
                  <p className="mt-1 text-xs text-slate-500">Run a recon scan to detect candidate correlations.</p>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {clusters.map((c) => {
                    const isSelected = selectedCluster?.id === c.id;
                    return (
                      <button
                        key={c.id}
                        type="button"
                        onClick={() => setSelectedCluster(c)}
                        className={`w-full text-left rounded-xl border p-4 transition-all ${
                          isSelected
                            ? 'border-indigo-500 bg-slate-900 shadow-md shadow-indigo-950/20'
                            : 'border-slate-800/80 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/70'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="rounded-md bg-indigo-950/60 border border-indigo-800 px-2 py-0.5 text-[10px] font-mono font-medium text-indigo-300">
                            {c.category}
                          </span>
                          <div className="flex items-center gap-1.5 font-mono text-xs">
                            <span className="text-slate-400">Priority:</span>
                            <span
                              className={`font-bold px-1.5 py-0.5 rounded text-xs ${
                                c.priority_score >= 80
                                  ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                  : 'bg-amber-950 text-amber-400 border border-amber-800'
                              }`}
                            >
                              {c.priority_score}/100
                            </span>
                          </div>
                        </div>

                        <h4 className="mt-2 text-sm font-semibold text-white leading-snug line-clamp-1">
                          {c.title}
                        </h4>
                        <p className="mt-1 text-xs text-slate-400 line-clamp-2 leading-relaxed">
                          {c.priority_explanation}
                        </p>

                        <div className="mt-3 flex items-center justify-between border-t border-slate-800/60 pt-2 text-[11px] font-mono text-slate-500">
                          <span>Status: {c.status}</span>
                          <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Right: Cluster Deep Breakdown & Score Factors */}
            <div className="lg:col-span-7">
              {selectedCluster ? (
                <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-6">
                  <div className="border-b border-slate-800 pb-4">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="rounded-md bg-indigo-950/80 border border-indigo-800 px-2.5 py-1 text-xs font-mono font-semibold text-indigo-300">
                          {selectedCluster.category}
                        </span>
                        <span className="text-xs font-mono text-slate-400">ID: {selectedCluster.id}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-slate-400">Compound Score:</span>
                        <span className="rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 font-mono text-sm font-bold text-rose-400">
                          {selectedCluster.priority_score} / 100
                        </span>
                      </div>
                    </div>

                    <h3 className="mt-3 text-lg font-bold text-white tracking-tight">
                      {selectedCluster.title}
                    </h3>
                    <p className="mt-1 text-xs text-slate-300 leading-relaxed">
                      {selectedCluster.reason}
                    </p>
                  </div>

                  {/* Priority Factor Breakdown Table */}
                  <div className="space-y-3">
                    <span className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                      <Sliders className="h-3.5 w-3.5 text-sky-400" />
                      Priority Score Factor Breakdown
                    </span>
                    <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
                      <table className="w-full text-left text-xs">
                        <thead className="border-b border-slate-800 bg-slate-900/50 font-mono text-slate-400">
                          <tr>
                            <th className="px-3 py-2">Factor</th>
                            <th className="px-3 py-2">Score</th>
                            <th className="px-3 py-2">Weight</th>
                            <th className="px-3 py-2">Contextual Justification</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                          {selectedCluster.priority_factors?.map((f, i) => (
                            <tr key={i} className="hover:bg-slate-900/30">
                              <td className="px-3 py-2.5 text-white font-medium">{f.name}</td>
                              <td className="px-3 py-2.5 text-sky-400 font-bold">{f.score}</td>
                              <td className="px-3 py-2.5 text-slate-400">{Math.round(f.weight * 100)}%</td>
                              <td className="px-3 py-2.5 text-slate-400 font-sans">{f.explanation}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Recommended Controlled Validation */}
                  <div className="space-y-3">
                    <span className="text-xs font-mono uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Controlled Non-Destructive Validation Steps
                    </span>
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 space-y-3">
                      <ul className="space-y-2 text-xs text-slate-300">
                        {selectedCluster.recommended_validation?.map((v, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <span className="font-mono text-emerald-400 font-bold">•</span>
                            <span>{v}</span>
                          </li>
                        ))}
                      </ul>

                      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                        <span className="text-[11px] font-mono text-slate-400">
                          Status: <span className="text-white font-semibold">{selectedCluster.status}</span>
                        </span>
                        <button
                          type="button"
                          onClick={() => handleExecuteValidation(selectedCluster)}
                          disabled={validatingClusterId === selectedCluster.id}
                          className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
                        >
                          <Play className={`h-3 w-3 ${validatingClusterId === selectedCluster.id ? 'animate-spin' : ''}`} />
                          <span>{validatingClusterId === selectedCluster.id ? 'Verifying...' : 'Execute Safe Verification'}</span>
                        </button>
                      </div>

                      {validationFact && (
                        <div className="rounded-md bg-emerald-950/40 border border-emerald-800 p-2.5 text-xs text-emerald-300">
                          {validationFact}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Associated Endpoints and Assets */}
                  <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <span className="text-slate-400 block mb-1">Related Assets</span>
                      <div className="flex flex-wrap gap-1">
                        {selectedCluster.related_assets?.map((a) => (
                          <span key={a} className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                            {a}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <span className="text-slate-400 block mb-1">Related Endpoints</span>
                      <div className="flex flex-wrap gap-1">
                        {selectedCluster.related_endpoints?.map((e) => (
                          <span key={e} className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                            {e}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center text-slate-500">
                  Select a cluster to view priority scoring breakdown
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. ASSET RELATIONSHIP GRAPH (SVG Topology Visualizer) */}
      {activeSubTab === 'graph' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">Asset & Intelligence Relationship Graph</h3>
                <p className="text-xs text-slate-400">
                  Directed topology mapping domains, hosts, IPs, services, technologies, auth boundaries, and finding hypotheses.
                </p>
              </div>

              {/* Node Type Legend */}
              <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-sky-500" /> Target</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-blue-500" /> Domain</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-indigo-500" /> Subdomain</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-purple-500" /> IP</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> HTTP Service</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> Technology</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-pink-500" /> Auth Boundary</span>
                <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-red-500" /> Candidate</span>
              </div>
            </div>

            {/* SVG Visual Graph Stage */}
            <div className="relative h-[480px] w-full rounded-lg border border-slate-800/80 bg-slate-900/40 overflow-hidden flex items-center justify-center">
              {graphData && graphData.nodes.length > 0 ? (
                <svg className="w-full h-full cursor-grab" viewBox="0 0 800 450">
                  <defs>
                    <marker
                      id="arrow"
                      viewBox="0 0 10 10"
                      refX="18"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
                    </marker>
                  </defs>

                  {/* Render Directed Edges */}
                  {graphData.edges.map((edge, i) => {
                    const srcIndex = graphData.nodes.findIndex((n) => n.id === edge.source_node_id);
                    const dstIndex = graphData.nodes.findIndex((n) => n.id === edge.target_node_id);
                    if (srcIndex === -1 || dstIndex === -1) return null;

                    // Calculate circle coordinates
                    const total = graphData.nodes.length;
                    const r = 170;
                    const cx = 400;
                    const cy = 225;

                    const srcAngle = (srcIndex / total) * 2 * Math.PI;
                    const dstAngle = (dstIndex / total) * 2 * Math.PI;

                    const x1 = cx + r * Math.cos(srcAngle);
                    const y1 = cy + r * Math.sin(srcAngle);
                    const x2 = cx + r * Math.cos(dstAngle);
                    const y2 = cy + r * Math.sin(dstAngle);

                    return (
                      <g key={edge.id || i}>
                        <line
                          x1={x1}
                          y1={y1}
                          x2={x2}
                          y2={y2}
                          stroke="#334155"
                          strokeWidth="1.5"
                          markerEnd="url(#arrow)"
                        />
                        <text
                          x={(x1 + x2) / 2}
                          y={(y1 + y2) / 2 - 4}
                          fill="#64748b"
                          fontSize="9"
                          textAnchor="middle"
                          fontFamily="monospace"
                        >
                          {edge.relationship}
                        </text>
                      </g>
                    );
                  })}

                  {/* Render Nodes */}
                  {graphData.nodes.map((node, i) => {
                    const total = graphData.nodes.length;
                    const r = 170;
                    const cx = 400;
                    const cy = 225;
                    const angle = (i / total) * 2 * Math.PI;
                    const x = cx + r * Math.cos(angle);
                    const y = cy + r * Math.sin(angle);

                    const isSelected = selectedNode?.id === node.id;
                    const color = getNodeColor(node.type);

                    return (
                      <g
                        key={node.id}
                        onClick={() => setSelectedNode(node)}
                        className="cursor-pointer transition-transform hover:scale-110"
                      >
                        <circle
                          cx={x}
                          cy={y}
                          r={isSelected ? 16 : 12}
                          fill={color}
                          stroke={isSelected ? '#ffffff' : '#0f172a'}
                          strokeWidth={isSelected ? 3 : 2}
                        />
                        <text
                          x={x}
                          y={y + 24}
                          fill={isSelected ? '#ffffff' : '#94a3b8'}
                          fontSize="10"
                          fontWeight={isSelected ? 'bold' : 'normal'}
                          textAnchor="middle"
                          fontFamily="monospace"
                        >
                          {node.label.length > 20 ? node.label.slice(0, 18) + '…' : node.label}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              ) : (
                <div className="text-center text-slate-500">No graph data generated yet</div>
              )}
            </div>

            {/* Selected Node Details Drawer */}
            {selectedNode && (
              <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
                  <div className="flex items-center gap-2">
                    <span
                      className="h-3 w-3 rounded-full"
                      style={{ backgroundColor: getNodeColor(selectedNode.type) }}
                    />
                    <span className="text-xs font-mono font-bold text-white uppercase">{selectedNode.type}</span>
                    <span className="text-xs font-mono text-slate-400">• {selectedNode.label}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">ID: {selectedNode.id}</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">First Seen:</span>
                    <span className="text-slate-300">{new Date(selectedNode.first_seen).toLocaleDateString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Last Seen:</span>
                    <span className="text-slate-300">{new Date(selectedNode.last_seen).toLocaleTimeString()}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-slate-500 block">Properties:</span>
                    <span className="text-slate-300">{JSON.stringify(selectedNode.properties || {})}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. TEMPORAL INTELLIGENCE ("WHAT CHANGED") */}
      {activeSubTab === 'temporal' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">Temporal Security Intelligence ("What Changed")</h3>
                <p className="text-xs text-slate-400">
                  Chronological difference ledger recording changes across DNS, HTTP behavior, technology stacks, and security headers.
                </p>
              </div>
              <span className="text-xs font-mono text-sky-400">{temporalChanges.length} Events Detected</span>
            </div>

            <div className="space-y-3">
              {temporalChanges.map((change) => (
                <div
                  key={change.id}
                  className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 transition-colors hover:border-slate-700"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-sky-950 px-2 py-0.5 text-sky-400 border border-sky-800 font-semibold">
                        {change.change_type}
                      </span>
                      <span className="text-slate-400">Source: {change.source}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Clock className="h-3 w-3" />
                      <span>{new Date(change.detected_at).toLocaleString()}</span>
                    </div>
                  </div>

                  <p className="mt-2 text-sm font-medium text-white">{change.summary}</p>

                  <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono border-t border-slate-800/60 pt-2">
                    <div className="rounded bg-slate-950 p-2 border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Previous State:</span>
                      <span className="text-rose-400 truncate block">{change.previous_value || 'None'}</span>
                    </div>
                    <div className="rounded bg-slate-950 p-2 border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Current Observed:</span>
                      <span className="text-emerald-400 truncate block">{change.current_value}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 4. STATE INVARIANTS */}
      {activeSubTab === 'invariants' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">State-Machine Invariant Violations</h3>
                <p className="text-xs text-slate-400">
                  Detects unlawful state transitions between unauthenticated and privileged execution boundaries.
                </p>
              </div>
              <span className="text-xs font-mono text-amber-400">{invariants.length} Violations</span>
            </div>

            <div className="space-y-3">
              {invariants.map((inv) => (
                <div key={inv.id} className="rounded-lg border border-amber-900/40 bg-amber-950/10 p-4 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-amber-950 px-2 py-0.5 text-amber-400 border border-amber-800 font-semibold">
                        {inv.endpoint}
                      </span>
                      <span className="text-slate-400">
                        Transition: {inv.state_from} → {inv.state_to}
                      </span>
                    </div>
                    <span className="text-amber-400 font-bold">Confidence: {Math.round(inv.confidence * 100)}%</span>
                  </div>

                  <p className="text-xs text-white font-medium">{inv.invariant_violation}</p>
                  <p className="text-xs text-slate-300 font-sans">{inv.observed_condition}</p>

                  <div className="rounded bg-slate-950 p-2 text-[11px] font-mono text-slate-400 border border-slate-800">
                    Evidence: {inv.evidence}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 5. DIFFERENTIAL PROBING */}
      {activeSubTab === 'behavior' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">Comparative Differential Probing</h3>
                <p className="text-xs text-slate-400">
                  Pairwise comparisons (Origin reflection, User-Agent behavior, parameter pollution, length anomalies).
                </p>
              </div>
              <span className="text-xs font-mono text-sky-400">{behaviorDiffs.length} Comparisons</span>
            </div>

            <div className="space-y-3">
              {behaviorDiffs.map((diff) => (
                <div key={diff.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-200">
                      Meaningful Divergence: {diff.is_meaningful ? 'YES (Significant)' : 'NO (Benign)'}
                    </span>
                    <span className="text-slate-400">Timing Delta: {diff.timing_delta_ms}ms</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="rounded bg-slate-950 p-2 border border-slate-800">
                      <span className="text-sky-400 block text-[10px] uppercase">Probe A: {diff.context_a}</span>
                      <span className="text-slate-300 break-all">{diff.probe_a_url}</span>
                    </div>
                    <div className="rounded bg-slate-950 p-2 border border-slate-800">
                      <span className="text-indigo-400 block text-[10px] uppercase">Probe B: {diff.context_b}</span>
                      <span className="text-slate-300 break-all">{diff.probe_b_url}</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 font-sans">
                    {diff.normalized_details?.finding || 'No substantial behavioral deviation observed between probes.'}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 6. RESEARCH MEMORY */}
      {activeSubTab === 'memory' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-6">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white">Target Research Memory</h3>
              <p className="text-xs text-slate-400">
                Persistent asset intelligence memory across scan sessions to prevent duplicate noise and track evolution.
              </p>
            </div>

            {researchMemory && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-center">
                  <span className="text-2xl font-bold font-mono text-sky-400">{researchMemory.known_assets_count}</span>
                  <span className="block text-xs text-slate-400 mt-1">Known Assets</span>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-center">
                  <span className="text-2xl font-bold font-mono text-emerald-400">{researchMemory.known_endpoints_count}</span>
                  <span className="block text-xs text-slate-400 mt-1">Endpoints Discovered</span>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-center">
                  <span className="text-2xl font-bold font-mono text-indigo-400">{researchMemory.total_historical_changes}</span>
                  <span className="block text-xs text-slate-400 mt-1">Historical Changes</span>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-center">
                  <span className="text-2xl font-bold font-mono text-amber-400">{researchMemory.active_investigations_count}</span>
                  <span className="block text-xs text-slate-400 mt-1">Active Clusters</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
