import React, { useState, useEffect, useCallback } from 'react';
import { Target, ScanJob, SystemEvent, HealthResponse } from './types';
import { api, ApiError } from './lib/api';
import { Sidebar, NavTab } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { LoadingState } from './components/LoadingState';
import { ErrorState } from './components/ErrorState';
import { DashboardView } from './components/views/DashboardView';
import { TargetsView } from './components/views/TargetsView';
import { ScansView } from './components/views/ScansView';
import { ScopeVerifierView } from './components/views/ScopeVerifierView';
import { AssetIntelligenceView } from './components/views/AssetIntelligenceView';
import { FindingCandidatesView } from './components/views/FindingCandidatesView';
import { InvestigationEngineView } from './components/views/InvestigationEngineView';
import { EvidenceIntelligenceView } from './components/views/EvidenceIntelligenceView';
import { SecurityReasoningView } from './components/views/SecurityReasoningView';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  // Core Data States
  const [targets, setTargets] = useState<Target[]>([]);
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [events, setEvents] = useState<SystemEvent[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  // Status flags
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // State for jumping from Targets to Scope Verifier or Intel
  const [selectedTargetForVerify, setSelectedTargetForVerify] = useState<Target | null>(null);
  const [selectedTargetForIntel, setSelectedTargetForIntel] = useState<string>('');

  const fetchData = useCallback(async (isSilent = false) => {
    if (!isSilent) setIsLoading(true);
    else setIsRefreshing(true);
    setError(null);

    try {
      // Check health
      try {
        const h = await api.getHealth();
        setHealth(h);
      } catch {
        setHealth({ status: 'offline', service: 'nexushunter-api' });
      }

      // Fetch targets, jobs, events in parallel
      const [fetchedTargets, fetchedJobs, fetchedEvents] = await Promise.all([
        api.getTargets().catch(() => []),
        api.getJobs().catch(() => []),
        api.getEvents().catch(() => []),
      ]);

      setTargets(fetchedTargets);
      setJobs(fetchedJobs);
      setEvents(fetchedEvents);
    } catch (err: any) {
      setError(err.message || 'Failed to load telemetry and state.');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Target handlers
  const handleCreateTarget = async (payload: {
    name: string;
    root_domain: string;
    allowed_domains: string[];
    allowed_url_patterns: string[];
    excluded_patterns: string[];
  }) => {
    const created = await api.createTarget(payload);
    setTargets((prev) => [created, ...prev]);
    // Refresh events
    api.getEvents().then(setEvents).catch(() => {});
  };

  const handleDeleteTarget = async (id: string) => {
    await api.deleteTarget(id);
    setTargets((prev) => prev.filter((t) => t.id !== id));
  };

  // Job handlers
  const handleCreateJob = async (payload: {
    target_id: string;
    type: string;
    metadata?: any;
  }) => {
    let created: ScanJob;
    if (payload.type === 'HIGH_SPEED_RECON' || payload.type === 'RECON') {
      created = await api.startRecon(payload.target_id, payload.metadata?.options);
    } else {
      created = await api.createJob(payload);
    }
    setJobs((prev) => [created, ...prev]);
    api.getEvents().then(setEvents).catch(() => {});
  };

  const handleStartJob = async (id: string) => {
    setJobs((prev) =>
      prev.map((j) =>
        j.id === id ? { ...j, status: 'RUNNING', started_at: new Date().toISOString() } : j
      )
    );
  };

  const handleCompleteJob = async (id: string) => {
    setJobs((prev) =>
      prev.map((j) =>
        j.id === id ? { ...j, status: 'COMPLETED', completed_at: new Date().toISOString() } : j
      )
    );
  };

  const handleFailJob = async (id: string, failureReason: string) => {
    setJobs((prev) =>
      prev.map((j) =>
        j.id === id
          ? {
              ...j,
              status: 'FAILED',
              completed_at: new Date().toISOString(),
              error: failureReason,
            }
          : j
      )
    );
  };

  const handleCancelJob = async (id: string) => {
    try {
      await api.cancelRecon(id);
    } catch {
      // Fallback if not a recon job
    }
    setJobs((prev) =>
      prev.map((j) =>
        j.id === id ? { ...j, status: 'CANCELLED', completed_at: new Date().toISOString() } : j
      )
    );
    api.getEvents().then(setEvents).catch(() => {});
  };

  const handleSelectTargetForVerify = (target: Target) => {
    setSelectedTargetForVerify(target);
    setActiveTab('scope-verifier');
  };

  const handleSelectTargetForIntel = (target: Target) => {
    setSelectedTargetForIntel(target.id);
    setActiveTab('intel');
  };

  // Title mappings
  const tabTitles: Record<NavTab, { title: string; subtitle: string }> = {
    dashboard: {
      title: 'Security Operations Center',
      subtitle: 'Attributable research overview & scope boundary enforcement',
    },
    targets: {
      title: 'Target Authorization & Scope Rules',
      subtitle: 'Manage explicit program boundaries and exclusion constraints',
    },
    scans: {
      title: 'Active & Scoped Scan Lifecycle',
      subtitle: 'Non-destructive evidence collection state machine',
    },
    intel: {
      title: 'Asset Intelligence & Technology Fingerprints',
      subtitle: 'Declarative signatures, security header posture & change detection',
    },
    candidates: {
      title: 'Hypothesis-to-Finding Pipeline',
      subtitle: 'Multi-stage state machine enforcing evidence-first verification before promotion',
    },
    investigations: {
      title: 'Investigation Engine & Asset Relationship Graph',
      subtitle: 'Topology graph, chronological difference ledger & prioritized attack-surface clusters',
    },
    evidence: {
      title: 'Evidence Intelligence & Comparative Diffs',
      subtitle: 'Cryptographic provenance, 3-level comparative differentials & deterministic contradiction detection',
    },
    reasoning: {
      title: 'Security Reasoning, Hypotheses & Investigation Engine',
      subtitle: 'Competing explanations, falsification conditions, missing evidence requirements & bounded investigations',
    },
    'scope-verifier': {
      title: 'Scope Policy Evaluation Engine',
      subtitle: 'Fail-closed verification against active target boundaries',
    },
  };

  return (
    <div className="flex min-h-screen bg-[#030712] text-slate-100 antialiased font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Sidebar Navigation */}
      <Sidebar
        id="app-sidebar"
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        targetCount={targets.length}
        jobCount={jobs.length}
      />

      {/* Main Content Area */}
      <div className="flex flex-1 flex-col overflow-x-hidden min-w-0">
        <Topbar
          id="app-topbar"
          onToggleSidebar={() => setIsSidebarOpen((v) => !v)}
          title={tabTitles[activeTab].title}
          subtitle={tabTitles[activeTab].subtitle}
          health={health}
          onRefresh={() => fetchData(true)}
          isRefreshing={isRefreshing}
        />

        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8 max-w-7xl w-full mx-auto">
          {isLoading ? (
            <LoadingState id="app-loader" message="Connecting to NexusHunter Core API & Storage..." />
          ) : error ? (
            <div className="space-y-4">
              <ErrorState
                id="app-error-state"
                title="Service Communication Issue"
                message={error}
                onRetry={() => fetchData(false)}
              />
            </div>
          ) : (
            <>
              {activeTab === 'dashboard' && (
                <DashboardView
                  targets={targets}
                  jobs={jobs}
                  events={events}
                  onNavigateToTargets={() => setActiveTab('targets')}
                  onNavigateToScans={() => setActiveTab('scans')}
                  onNavigateToVerifier={() => setActiveTab('scope-verifier')}
                  onNavigateToIntel={() => setActiveTab('intel')}
                  onNavigateToEvidence={() => setActiveTab('evidence')}
                />
              )}

              {activeTab === 'targets' && (
                <TargetsView
                  targets={targets}
                  onCreateTarget={handleCreateTarget}
                  onDeleteTarget={handleDeleteTarget}
                  onSelectTargetForVerify={handleSelectTargetForVerify}
                  onSelectTargetForIntel={handleSelectTargetForIntel}
                />
              )}

              {activeTab === 'scans' && (
                <ScansView
                  jobs={jobs}
                  targets={targets}
                  onCreateJob={handleCreateJob}
                  onStartJob={handleStartJob}
                  onCompleteJob={handleCompleteJob}
                  onFailJob={handleFailJob}
                  onCancelJob={handleCancelJob}
                />
              )}

              {activeTab === 'intel' && (
                <AssetIntelligenceView
                  targets={targets}
                  selectedTargetId={selectedTargetForIntel || (targets[0]?.id ?? '')}
                  onSelectTarget={(id) => setSelectedTargetForIntel(id)}
                />
              )}

              {activeTab === 'candidates' && (
                <FindingCandidatesView
                  targets={targets}
                  selectedTargetId={selectedTargetForIntel || (targets[0]?.id ?? '')}
                  onSelectTarget={(id) => setSelectedTargetForIntel(id)}
                />
              )}

              {activeTab === 'investigations' && (
                <InvestigationEngineView
                  targets={targets}
                  selectedTargetId={selectedTargetForIntel || (targets[0]?.id ?? '')}
                  onSelectTarget={(id) => setSelectedTargetForIntel(id)}
                />
              )}

              {activeTab === 'evidence' && (
                <EvidenceIntelligenceView
                  targets={targets}
                  selectedTargetId={selectedTargetForIntel || (targets[0]?.id ?? '')}
                  onSelectTarget={(id) => setSelectedTargetForIntel(id)}
                />
              )}

              {activeTab === 'reasoning' && (
                <SecurityReasoningView
                  targets={targets}
                  selectedTargetId={selectedTargetForIntel || (targets[0]?.id ?? '')}
                  onSelectTarget={(id) => setSelectedTargetForIntel(id)}
                />
              )}

              {activeTab === 'scope-verifier' && (
                <ScopeVerifierView
                  targets={targets}
                  initialTarget={selectedTargetForVerify}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
