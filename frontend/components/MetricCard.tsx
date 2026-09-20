import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  id?: string;
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: string;
  accent?: 'sky' | 'emerald' | 'amber' | 'rose' | 'slate';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  id,
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  accent = 'sky',
}) => {
  const accentStyles = {
    sky: 'border-sky-900/40 hover:border-sky-700/60 text-sky-400 bg-sky-950/20',
    emerald: 'border-emerald-900/40 hover:border-emerald-700/60 text-emerald-400 bg-emerald-950/20',
    amber: 'border-amber-900/40 hover:border-amber-700/60 text-amber-400 bg-amber-950/20',
    rose: 'border-rose-900/40 hover:border-rose-700/60 text-rose-400 bg-rose-950/20',
    slate: 'border-slate-800 hover:border-slate-700 text-slate-400 bg-slate-900/40',
  };

  return (
    <div
      id={id}
      className={`rounded-xl border bg-slate-900/70 p-5 transition-colors ${accentStyles[accent]}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400 tracking-wider uppercase">{title}</span>
        <div className="p-2 rounded-lg bg-slate-800/80">
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-white">{value}</span>
        {trend && <span className="text-xs font-mono text-emerald-400">{trend}</span>}
      </div>
      {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
};
