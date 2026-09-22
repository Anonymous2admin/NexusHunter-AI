import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { RuntimeMode, HealthResponse } from '../types';
import { api } from '../lib/api';

interface RuntimeContextType {
  mode: RuntimeMode;
  isLive: boolean;
  isDemo: boolean;
  isOffline: boolean;
  isPartial: boolean;
  health: HealthResponse | null;
  refreshRuntime: () => Promise<void>;
  assertLiveOrThrow: (operationName: string) => void;
}

const RuntimeContext = createContext<RuntimeContextType | undefined>(undefined);

export const RuntimeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [mode, setMode] = useState<RuntimeMode>('DEMO');
  const [health, setHealth] = useState<HealthResponse | null>(null);

  const refreshRuntime = useCallback(async () => {
    try {
      const h = await api.getHealth();
      setHealth(h);
      if (h.mode === 'LIVE' || api.getLastOrigin() === 'LIVE_BACKEND') {
        setMode('LIVE');
      } else if (h.mode === 'DEMO_FALLBACK' || api.getLastOrigin() === 'DEMO_SYNTHETIC') {
        setMode('DEMO');
      } else {
        setMode('DEMO');
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

  const assertLiveOrThrow = useCallback(
    (operationName: string) => {
      if (mode !== 'LIVE') {
        throw new Error(
          `Action '${operationName}' rejected: Mutation operations against live environments require an active LIVE backend connection. Currently running in ${mode} mode.`
        );
      }
    },
    [mode]
  );

  const value: RuntimeContextType = {
    mode,
    isLive: mode === 'LIVE',
    isDemo: mode === 'DEMO',
    isOffline: mode === 'OFFLINE',
    isPartial: mode === 'PARTIAL',
    health,
    refreshRuntime,
    assertLiveOrThrow,
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
