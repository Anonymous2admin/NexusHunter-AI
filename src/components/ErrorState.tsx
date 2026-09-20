import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  id?: string;
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  id,
  title = 'API Communication Failure',
  message,
  onRetry,
}) => {
  return (
    <div
      id={id}
      className="rounded-xl border border-rose-900/60 bg-rose-950/20 p-6 text-left"
    >
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg bg-rose-900/40 text-rose-400 mt-0.5">
          <AlertTriangle className="h-5 w-5" />
        </div>
        <div className="flex-1">
          <h4 className="text-sm font-semibold text-rose-300">{title}</h4>
          <p className="mt-1 text-xs text-rose-400/90 font-mono break-all">{message}</p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-1.5 rounded-md bg-rose-900/50 px-3 py-1.5 text-xs font-medium text-rose-200 hover:bg-rose-900/80 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Retry Request
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
