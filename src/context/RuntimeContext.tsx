import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { RuntimeMode, HealthResponse } from '../types';
import { api } from '../lib/api';

interface RuntimeContextType {
  mode: RuntimeMode;
  isLive: boolean;
  isDemo: boolean;
  isOffline: boolean;
  isPartial: boolean;
  isUnknown: boolean;
  health: HealthResponse | null;
  refreshRuntime: () => Promise<void>;
  assertLiveOrThrow: (operationName: string, allowDemo?: boolean) => void;
  allowDemoMutations: boolean;
  setAllowDemoMutations: (allow: boolean) => void;
  runtimeError: string | null;
  showRuntimeError: (err: any) => void;
  clearRuntimeError: () => void;
}

const RuntimeContext = createContext<RuntimeContextType | undefined>(undefined);

export const RuntimeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [mode, setMode] = useState<RuntimeMode>('DEMO');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [allowDemoMutations, setAllowDemoMutations] = useState<boolean>(false);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);

  const refreshRuntime = useCallback(async () => {
    try {
      const h = await api.getHealth();
      setHealth(h);
      if (!h || typeof h !== 'object') {
        setMode('UNKNOWN');
        return;
      }

      // Check authoritative health mode
      if (h.mode === 'LIVE' || api.getLastOrigin() === 'LIVE_BACKEND') {
        setMode('LIVE');
      } else if (h.mode === 'DEMO_FALLBACK' || api.getLastOrigin() === 'DEMO_SYNTHETIC') {
        setMode('DEMO');
      } else if (h.mode === 'PARTIAL') {
        setMode('PARTIAL');
      } else if (h.mode === 'OFFLINE') {
        setMode('OFFLINE');
      } else {
        // Unexpected or malformed mode must be UNKNOWN, NOT DEMO
        setMode('UNKNOWN');
      }
    } catch {
      setMode('OFFLINE');
      setHealth(null);
    }
  }, []);

  useEffect(() => {
    refreshRuntime();
    const interval = setInterval(refreshRuntime, 15000);
    return () => clearInterval(interval);
  }, [refreshRuntime]);

  const showRuntimeError = useCallback((err: any) => {
    const msg = err?.message || (typeof err === 'string' ? err : 'Unknown runtime error occurred.');
    setRuntimeError(msg);
  }, []);

  const clearRuntimeError = useCallback(() => {
    setRuntimeError(null);
  }, []);

  const assertLiveOrThrow = useCallback(
    (operationName: string, allowDemoOverride?: boolean) => {
      // 1. UNKNOWN runtime mode fails closed unconditionally
      if (mode === 'UNKNOWN') {
        const msg = `Action '${operationName}' rejected: Runtime state is UNKNOWN (unexpected or malformed backend health response). All mutations are denied fail-closed to guarantee system truth.`;
        setRuntimeError(msg);
        throw new Error(msg);
      }

      // 2. OFFLINE runtime mode fails closed unconditionally
      if (mode === 'OFFLINE') {
        const msg = `Action '${operationName}' rejected: Backend is currently OFFLINE. Cannot execute mutations without an active connection.`;
        setRuntimeError(msg);
        throw new Error(msg);
      }

      // 3. PARTIAL runtime mode fails closed for mutations
      if (mode === 'PARTIAL') {
        const msg = `Action '${operationName}' rejected: Backend is in degraded PARTIAL mode. Mutations are denied fail-closed.`;
        setRuntimeError(msg);
        throw new Error(msg);
      }

      // 4. DEMO runtime mode requires explicit sandbox writes enabled
      if (mode === 'DEMO') {
        const canExecuteDemo = allowDemoOverride !== undefined ? allowDemoOverride : allowDemoMutations;
        if (!canExecuteDemo) {
          const msg = `Action '${operationName}' rejected: Mutation operations against live environments require an active LIVE backend connection. Currently running in DEMO mode. Enable 'Sandbox Writes' in the top banner to permit synthetic sandbox mutations.`;
          setRuntimeError(msg);
          throw new Error(msg);
        }
      }

      // 5. LIVE mode passes through to real backend operations
    },
    [mode, allowDemoMutations]
  );

  const value: RuntimeContextType = {
    mode,
    isLive: mode === 'LIVE',
    isDemo: mode === 'DEMO',
    isOffline: mode === 'OFFLINE',
    isPartial: mode === 'PARTIAL',
    isUnknown: mode === 'UNKNOWN',
    health,
    refreshRuntime,
    assertLiveOrThrow,
    allowDemoMutations,
    setAllowDemoMutations,
    runtimeError,
    showRuntimeError,
    clearRuntimeError,
  };

  return <RuntimeContext.Provider value={value}>{children}</RuntimeContext.Provider>;
};

export const useRuntime = (): RuntimeContextType => {
  const ctx = useContext(RuntimeContext);
  if (!ctx) {
    throw new Error('useRuntime must be used within a RuntimeProvider');
  }
  return ctx;
};
