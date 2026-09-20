import React from 'react';
import { TargetStatus, JobStatus } from '../types';

interface StatusBadgeProps {
  id?: string;
  status: TargetStatus | JobStatus | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ id, status, size = 'sm' }) => {
  const normalized = status.toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  if (normalized === 'ACTIVE' || normalized === 'COMPLETED') {
    colorClasses = 'bg-emerald-950/60 text-emerald-400 border-emerald-800/80';
    dotColor = 'bg-emerald-400';
  } else if (normalized === 'RUNNING') {
    colorClasses = 'bg-sky-950/60 text-sky-400 border-sky-800/80 animate-pulse';
    dotColor = 'bg-sky-400';
  } else if (normalized === 'QUEUED') {
    colorClasses = 'bg-amber-950/60 text-amber-400 border-amber-800/80';
    dotColor = 'bg-amber-400';
  } else if (normalized === 'FAILED') {
    colorClasses = 'bg-rose-950/60 text-rose-400 border-rose-800/80';
    dotColor = 'bg-rose-400';
  } else if (normalized === 'CANCELLED' || normalized === 'ARCHIVED' || normalized === 'INACTIVE') {
    colorClasses = 'bg-slate-900 text-slate-400 border-slate-800';
    dotColor = 'bg-slate-500';
  }

  const padding = size === 'sm' ? 'px-2.5 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span
      id={id}
      className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-full border ${padding} ${colorClasses} whitespace-nowrap`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      {normalized}
    </span>
  );
};
