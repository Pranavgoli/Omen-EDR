import React, { useMemo } from 'react';
import { Eye, Map, Network, Folder, Globe } from 'lucide-react';

export default function Visibility({ stats }) {

  // Group processes by network activity
  const networkProcs = useMemo(() => {
    return stats.processes.filter(p => p.connections_count && p.connections_count > 0).sort((a,b) => b.connections_count - a.connections_count);
  }, [stats.processes]);

  // Group processes by path context (simplified: Windows System vs User vs Other)
  const pathContexts = useMemo(() => {
    const contexts = {
      system: [],
      user: [],
      other: []
    };
    
    stats.processes.forEach(p => {
      const path = (p.path || '').toLowerCase();
      if (!path) {
        contexts.other.push(p);
      } else if (path.includes('c:\\windows') || path.includes('system32')) {
        contexts.system.push(p);
      } else if (path.includes('users\\') || path.includes('appdata')) {
        contexts.user.push(p);
      } else {
        contexts.other.push(p);
      }
    });
    
    return contexts;
  }, [stats.processes]);

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="glass-panel p-6 border border-slate-800">
        <h2 className="text-xl font-bold flex items-center gap-2 mb-2">
          <Eye className="text-teal-500" />
          Visibility & Context
        </h2>
        <p className="text-sm text-slate-400">
          Mapping process execution origins and external network boundaries.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Network Connections */}
        <div className="glass-panel p-5 flex flex-col h-[500px]">
          <h3 className="font-semibold flex items-center justify-between text-slate-300 border-b border-slate-800 pb-3 mb-4">
            <span className="flex items-center gap-2"><Network className="text-teal-400" size={18} /> Network Communications</span>
            <span className="text-xs bg-slate-800 px-2 py-1 rounded text-slate-400">{networkProcs.length} Active</span>
          </h3>
          <div className="flex-1 overflow-auto pr-2">
             {networkProcs.length === 0 ? (
               <div className="h-full flex items-center justify-center text-slate-500">No active process connections detected.</div>
             ) : (
               <div className="space-y-3">
                 {networkProcs.map(proc => (
                   <div key={`net-${proc.pid}`} className="bg-slate-900/50 p-3 rounded-lg border border-slate-700 hover:border-slate-500 transition-colors">
                     <div className="flex justify-between items-center mb-2">
                       <span className="font-bold text-slate-200">{proc.name}</span>
                       <span className="text-xs bg-teal-500/10 text-teal-400 px-2 py-0.5 rounded-full border border-teal-500/20 flex gap-1 items-center">
                         <Globe size={12} />
                         {proc.connections_count} Cons
                       </span>
                     </div>
                     <div className="text-xs text-slate-500 font-mono truncate">{proc.path || 'Unknown Path'}</div>
                   </div>
                 ))}
               </div>
             )}
          </div>
        </div>

        {/* Execution Path Context */}
        <div className="glass-panel p-5 flex flex-col h-[500px]">
          <h3 className="font-semibold flex items-center gap-2 mb-4 text-slate-300 border-b border-slate-800 pb-3">
            <Map className="text-emerald-400" size={18} /> Execution Path Context
          </h3>
          <div className="flex-1 overflow-auto pr-2 space-y-4">
             
             {/* System Level */}
             <div className="bg-slate-900/80 rounded-lg p-4 border border-slate-800">
                <div className="flex items-center justify-between mb-3 text-slate-300">
                  <h4 className="font-medium flex items-center gap-2"><Folder size={16} className="text-slate-500" /> Windows / System32</h4>
                  <span className="text-xs bg-slate-800 px-2 py-0.5 rounded">{pathContexts.system.length}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {pathContexts.system.slice(0, 15).map(p => (
                    <span key={`sys-${p.pid}`} className="text-[10px] bg-slate-950 px-2 py-1 rounded border border-slate-800 text-slate-400 truncate max-w-[120px] hover:text-slate-200 cursor-help" title={p.path}>
                      {p.name}
                    </span>
                  ))}
                  {pathContexts.system.length > 15 && <span className="text-[10px] text-slate-500 px-2 py-1">+{pathContexts.system.length - 15} more</span>}
                </div>
             </div>

             {/* User Level */}
             <div className="bg-slate-900/80 rounded-lg p-4 border border-slate-800">
                <div className="flex items-center justify-between mb-3 text-slate-300">
                  <h4 className="font-medium flex items-center gap-2"><Folder size={16} className="text-blue-400" /> User Space / AppData</h4>
                  <span className="text-xs bg-slate-800 px-2 py-0.5 rounded">{pathContexts.user.length}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {pathContexts.user.slice(0, 15).map(p => (
                    <span key={`usr-${p.pid}`} className="text-[10px] bg-blue-900/20 px-2 py-1 rounded border border-blue-900/50 text-blue-300 truncate max-w-[120px] hover:text-blue-100 cursor-help" title={p.path}>
                      {p.name}
                    </span>
                  ))}
                  {pathContexts.user.length > 15 && <span className="text-[10px] text-slate-500 px-2 py-1">+{pathContexts.user.length - 15} more</span>}
                </div>
             </div>

             {/* Other */}
             <div className="bg-slate-900/80 rounded-lg p-4 border border-slate-800">
                <div className="flex items-center justify-between mb-3 text-slate-300">
                  <h4 className="font-medium flex items-center gap-2"><Folder size={16} className="text-rose-400" /> Other / Unknown</h4>
                  <span className="text-xs bg-slate-800 px-2 py-0.5 rounded">{pathContexts.other.length}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {pathContexts.other.slice(0, 15).map(p => (
                    <span key={`oth-${p.pid}`} className="text-[10px] bg-rose-900/20 px-2 py-1 rounded border border-rose-900/50 text-rose-300 truncate max-w-[120px] hover:text-rose-100 cursor-help" title={p.path}>
                      {p.name}
                    </span>
                  ))}
                  {pathContexts.other.length > 15 && <span className="text-[10px] text-slate-500 px-2 py-1">+{pathContexts.other.length - 15} more</span>}
                </div>
             </div>

          </div>
        </div>
        
      </div>
    </div>
  );
}
