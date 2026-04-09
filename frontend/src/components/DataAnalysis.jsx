import React, { useMemo } from 'react';
import { BarChart3, PieChart, Activity, HardDrive, Cpu } from 'lucide-react';

export default function DataAnalysis({ stats }) {
  
  const topMemory = useMemo(() => {
    return [...stats.processes].sort((a, b) => b.memory_mb - a.memory_mb).slice(0, 10);
  }, [stats.processes]);

  const topThreads = useMemo(() => {
    return [...stats.processes].sort((a, b) => b.threads - a.threads).slice(0, 10);
  }, [stats.processes]);

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="glass-panel p-6 border border-slate-800">
        <h2 className="text-xl font-bold flex items-center gap-2 mb-2">
          <BarChart3 className="text-purple-500" />
          Statistical Analysis
        </h2>
        <p className="text-sm text-slate-400">
          Aggregated behavior and resource utilization heuristics.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Top Memory Consumers */}
        <div className="glass-panel p-5 flex flex-col h-[400px]">
          <h3 className="font-semibold flex items-center gap-2 mb-4 text-slate-300 border-b border-slate-800 pb-2">
            <HardDrive className="text-purple-400" size={18} />
            Top 10 Memory Consumers
          </h3>
          <div className="flex-1 overflow-auto pr-2">
            {topMemory.length === 0 ? (
               <div className="h-full flex items-center justify-center text-slate-500">Awaiting data...</div>
            ) : (
               <div className="space-y-4">
                 {topMemory.map((proc, index) => {
                   const maxMem = topMemory[0].memory_mb || 1;
                   const pct = (proc.memory_mb / maxMem) * 100;
                   return (
                     <div key={`mem-${proc.pid}-${index}`}>
                       <div className="flex justify-between text-xs mb-1">
                         <span className="font-medium text-slate-300 truncate w-48">{proc.name} <span className="text-slate-500 font-mono">({proc.pid})</span></span>
                         <span className="text-purple-400 font-mono">{proc.memory_mb.toFixed(1)} MB</span>
                       </div>
                       <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                         <div className="h-full bg-purple-500" style={{ width: `${pct}%` }}></div>
                       </div>
                     </div>
                   );
                 })}
               </div>
            )}
          </div>
        </div>

        {/* Top Threads Consumers */}
        <div className="glass-panel p-5 flex flex-col h-[400px]">
          <h3 className="font-semibold flex items-center gap-2 mb-4 text-slate-300 border-b border-slate-800 pb-2">
            <Activity className="text-indigo-400" size={18} />
            Top 10 Thread Spawners
          </h3>
          <div className="flex-1 overflow-auto pr-2">
            {topThreads.length === 0 ? (
               <div className="h-full flex items-center justify-center text-slate-500">Awaiting data...</div>
            ) : (
               <div className="space-y-4">
                 {topThreads.map((proc, index) => {
                   const maxTh = topThreads[0].threads || 1;
                   const pct = (proc.threads / maxTh) * 100;
                   return (
                     <div key={`th-${proc.pid}-${index}`}>
                       <div className="flex justify-between text-xs mb-1">
                         <span className="font-medium text-slate-300 truncate w-48">{proc.name} <span className="text-slate-500 font-mono">({proc.pid})</span></span>
                         <span className="text-indigo-400 font-mono">{proc.threads}</span>
                       </div>
                       <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                         <div className="h-full bg-indigo-500" style={{ width: `${pct}%` }}></div>
                       </div>
                     </div>
                   );
                 })}
               </div>
            )}
          </div>
        </div>
        
      </div>
    </div>
  );
}
