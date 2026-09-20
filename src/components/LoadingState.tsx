import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingStateProps {
  id?: string;
  message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  id,
  message = 'Loading telemetry & target data...',
}) => {
  return (
    <div
      id={id}
      className="flex flex-col items-center justify-center rounded-xl border border-slate-800/80 bg-slate-900/30 p-12 text-center"
    >
      <Loader2 className="h-7 w-7 animate-spin text-sky-400" />
      <span className="mt-3 text-sm font-mono text-slate-400">{message}</span>
    </div>
  );
};
