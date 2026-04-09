import React from 'react';
import { Target, AlertOctagon, CheckCircle, Clock } from 'lucide-react';

export default function IncidentResponse({ stats, handleQuarantine, incidentLog, quarantining }) {
  const criticalThreats = stats.processes
    .filter(p => p.threat_score >= 20)
    .sort((a, b) => b.threat_score - a.threat_score);

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Action Center */}
        <div className="glass-panel p-6 flex flex-col gap-4">
          <h2 className="text-xl font-bold flex items-center gap-2 border-b border-slate-800 pb-3">
            <Target className="text-red-500" />
            Active Response Center
          </h2>
          
          <div className="flex-1 overflow-auto max-h-[400px]">
            {criticalThreats.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 py-8">
                <CheckCircle size={48} className="text-green-500/30 mb-2" />
                <p>No critical threats require immediate response.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {criticalThreats.map(proc => (
                  <div key={proc.pid} className="bg-slate-900 border border-slate-700 rounded-lg p-4 flex items-center justify-between">
                    <div>
                      <div className="font-bold text-slate-200">{proc.name} <span className="text-slate-500 font-mono text-xs ml-2">PID: {proc.pid}</span></div>
                      <div className="text-xs text-red-400 mt-1">Score: {proc.threat_score} | {proc.analysis || 'High Risk'}</div>
                    </div>
                    <button 
                      onClick={() => handleQuarantine(proc.pid, proc.name)}
                      disabled={quarantining || proc.is_protected}
                      className={`px-4 py-2 text-sm font-semibold text-white rounded-lg shadow-lg transition-all 
                        ${(quarantining || proc.is_protected) 
                           ? 'bg-slate-700 text-slate-500 cursor-not-allowed' 
                           : 'bg-red-600 hover:bg-red-500 shadow-red-500/20 active:scale-95'}`}
                    >
                      {quarantining ? 'Terminating...' : proc.is_protected ? 'Protected' : 'Quarantine'}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Action Log */}
        <div className="glass-panel p-6 flex flex-col gap-4">
          <h2 className="text-xl font-bold flex items-center gap-2 border-b border-slate-800 pb-3">
            <AlertOctagon className="text-blue-500" />
            Response Audit Log
          </h2>
          
          <div className="flex-1 overflow-auto max-h-[400px]">
            {incidentLog.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 py-8">
                <Clock size={48} className="text-slate-700 mb-2" />
                <p>No incidents responded to yet.</p>
              </div>
            ) : (
              <div className="space-y-3 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-700 before:to-transparent">
                 {incidentLog.map((log, i) => (
                   <div key={i} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                     <div className="flex items-center justify-center w-10 h-10 rounded-full border border-slate-700 bg-slate-900 text-slate-500 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow">
                        <CheckCircle size={16} className={log.success ? "text-green-500" : "text-red-500"} />
                     </div>
                     <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-lg bg-slate-900/80 border border-slate-800">
                        <div className="flex items-center justify-between mb-1">
                          <div className="text-xs text-slate-400 font-medium">{log.timestamp}</div>
                        </div>
                        <div className="text-sm font-semibold text-slate-200">{log.action}: {log.target}</div>
                        <div className="text-xs text-slate-500 mt-1">{log.message}</div>
                     </div>
                   </div>
                 ))}
              </div>
            )}
          </div>
        </div>
        
      </div>
    </div>
  );
}
