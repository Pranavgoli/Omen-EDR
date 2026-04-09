import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

export default function ThreatDetection({ stats, setSelectedProcess }) {
  const threats = stats.processes
    .filter(p => p.threat_score > 0)
    .sort((a, b) => b.threat_score - a.threat_score);

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="glass-panel p-6 border border-slate-800">
        <h2 className="text-xl font-bold flex items-center gap-2 mb-2">
          <ShieldAlert className="text-red-500" />
          Active Threats
        </h2>
        <p className="text-sm text-slate-400">
          Processes identified with suspicious heuristics or high threat scores.
        </p>
      </div>

      {threats.length === 0 ? (
        <div className="flex-1 glass-panel flex flex-col items-center justify-center p-12 text-slate-500">
          <ShieldCheck size={64} className="text-green-500/30 mb-4" />
          <h3 className="text-lg font-medium text-slate-300">No Active Threats Detected</h3>
          <p className="text-sm mt-2">The system heuristic scanner indicates normal operation.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {threats.map((proc) => (
            <div key={proc.pid} className={`p-5 rounded-xl border flex flex-col gap-4 shadow-lg
              ${proc.threat_score >= 50 ? 'bg-red-950/20 border-red-900/50' : 
                proc.threat_score >= 20 ? 'bg-amber-950/20 border-amber-900/50' : 
                'bg-slate-900 border-slate-700'}`}>
              
               <div className="flex justify-between items-start">
                 <div>
                   <h3 className="text-lg font-bold text-slate-200">{proc.name}</h3>
                   <p className="text-xs text-slate-500 font-mono mt-1 blur-sm hover:blur-none transition-all">{proc.path}</p>
                 </div>
                 <div className="text-right">
                   <div className="text-xs uppercase font-semibold text-slate-500">Score</div>
                   <div className={`text-2xl font-black 
                     ${proc.threat_score >= 50 ? 'text-red-500' : 
                     proc.threat_score >= 20 ? 'text-amber-500' : 'text-yellow-500'}`}>
                     {proc.threat_score}
                   </div>
                 </div>
               </div>

               <div className="bg-slate-950/50 rounded p-3 text-sm text-slate-300 border border-slate-800 flex-1">
                 <div className="font-semibold text-slate-400 mb-2 text-xs uppercase">Heuristic Evidence</div>
                 {proc.evidence && proc.evidence.length > 0 ? (
                   <ul className="list-disc pl-5 space-y-1">
                     {proc.evidence.map((ev, i) => (
                       <li key={i}>{ev}</li>
                     ))}
                   </ul>
                 ) : (
                   <span className="italic text-slate-500">Analysis pending or unclear heuristics.</span>
                 )}
               </div>

               <div className="mt-auto grid grid-cols-3 gap-2 text-xs">
                 <div className="bg-slate-900 px-2 py-1.5 rounded border border-slate-800 text-center">
                   <span className="block text-slate-500">PID</span>
                   <span className="font-mono text-slate-300">{proc.pid}</span>
                 </div>
                 <div className="bg-slate-900 px-2 py-1.5 rounded border border-slate-800 text-center">
                   <span className="block text-slate-500">Net Cons</span>
                   <span className="font-mono text-slate-300">{proc.connections_count}</span>
                 </div>
                 <button 
                    onClick={() => setSelectedProcess(proc)}
                    className="bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition-colors border-none"
                 >
                   Inspect
                 </button>
               </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
