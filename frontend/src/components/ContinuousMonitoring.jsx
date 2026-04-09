import React from 'react';
import { Activity, Cpu, HardDrive, ShieldAlert, Database, Layers, Search, ShieldCheck } from 'lucide-react';

export default function ContinuousMonitoring({ stats, searchQuery, setSearchQuery, setSelectedProcess }) {
  const filteredProcesses = stats.processes.filter(proc => {
    if (!searchQuery) return true;
    const lowerQuery = searchQuery.toLowerCase();
    return (
      proc.name.toLowerCase().includes(lowerQuery) ||
      proc.pid.toString().includes(lowerQuery) ||
      proc.threat_score.toString().includes(lowerQuery) ||
      (proc.path && proc.path.toLowerCase().includes(lowerQuery))
    );
  });

  return (
    <>
      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="glass-panel p-5 flex flex-col relative overflow-hidden group">
          <div className="flex items-center justify-between mb-4">
            <span className="text-slate-400 font-medium">CPU Usage</span>
            <Cpu className="text-blue-400" size={20} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-4xl font-bold">{stats.cpu_usage.toFixed(1)}</span>
            <span className="text-slate-500 font-medium mb-1">%</span>
          </div>
          <div className="absolute bottom-0 left-0 h-1 bg-blue-500/20 w-full">
            <div className="h-full bg-blue-500 transition-all duration-500 ease-out" style={{ width: `${stats.cpu_usage}%`}}></div>
          </div>
        </div>

        <div className="glass-panel p-5 flex flex-col relative overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <span className="text-slate-400 font-medium">Memory Usage</span>
            <HardDrive className="text-purple-400" size={20} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-4xl font-bold">{stats.ram_usage.toFixed(1)}</span>
            <span className="text-slate-500 font-medium mb-1">%</span>
          </div>
          <div className="absolute bottom-0 left-0 h-1 bg-purple-500/20 w-full">
            <div className="h-full bg-purple-500 transition-all duration-500 ease-out" style={{ width: `${stats.ram_usage}%`}}></div>
          </div>
        </div>

        <div className="glass-panel p-5 flex flex-col relative overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <span className="text-slate-400 font-medium">Disk Space</span>
            <Database className="text-rose-400" size={20} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-4xl font-bold">{stats.disk_usage.toFixed(1)}</span>
            <span className="text-slate-500 font-medium mb-1">%</span>
          </div>
          <div className="absolute bottom-0 left-0 h-1 bg-rose-500/20 w-full">
            <div className="h-full bg-rose-500 transition-all duration-500 ease-out" style={{ width: `${stats.disk_usage}%`}}></div>
          </div>
        </div>

        <div className="glass-panel p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <span className="text-slate-400 font-medium">Process Count</span>
            <Activity className="text-emerald-400" size={20} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-4xl font-bold">{stats.total_processes}</span>
            <span className="text-slate-500 font-medium mb-1">active</span>
          </div>
        </div>

        <div className="glass-panel p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <span className="text-slate-400 font-medium">Thread Count</span>
            <Layers className="text-indigo-400" size={20} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-4xl font-bold">{stats.total_threads}</span>
            <span className="text-slate-500 font-medium mb-1">active</span>
          </div>
        </div>

        <div className="glass-panel p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <span className="text-slate-400 font-medium">Threats Detected</span>
            <ShieldAlert className={stats.threats_found > 0 ? "text-red-400" : "text-slate-600"} size={20} />
          </div>
          <div className="flex items-end gap-2">
            <span className={`text-4xl font-bold ${stats.threats_found > 0 ? 'text-red-400 animate-pulse' : 'text-slate-400'}`}>
              {stats.threats_found}
            </span>
            <span className="text-slate-500 font-medium mb-1">flagged</span>
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="glass-panel flex-1 flex flex-col overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
          <h2 className="font-semibold text-lg flex items-center gap-2">
            Process Forensics
            {stats.scan_status === 'scanning' && <span className="flex h-2 w-2 relative"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span></span>}
          </h2>

          <div className="flex items-center gap-2 bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 focus-within:ring-1 focus-within:ring-blue-500 transition-shadow">
            <Search className="text-slate-500" size={16} />
            <input 
              type="text"
              placeholder="Search Name, PID, Score..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent text-sm text-slate-300 outline-none w-48 placeholder-slate-600 focus:outline-none"
            />
          </div>
        </div>
        
        <div className="overflow-auto max-h-[600px]">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 bg-slate-900 bg-opacity-90 backdrop-blur-md z-10 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-4 px-6 font-medium">PID</th>
                <th className="py-4 px-6 font-medium">Name</th>
                <th className="py-4 px-6 font-medium text-center">Threads</th>
                <th className="py-4 px-6 font-medium text-right">Memory (MB)</th>
                <th className="py-4 px-6 font-medium text-center">Net Cons</th>
                <th className="py-4 px-6 font-medium text-right">Threat Score</th>
                <th className="py-4 px-6 font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filteredProcesses.map(proc => (
                <tr key={proc.pid} className="hover:bg-slate-800/30 transition-colors group">
                  <td className="py-3 px-6 text-slate-400 font-mono text-sm">{proc.pid}</td>
                  <td className="py-3 px-6">
                    <div className="font-medium text-slate-200">{proc.name}</div>
                    <div className="text-xs text-slate-500 truncate max-w-[300px]" title={proc.path}>{proc.path}</div>
                  </td>
                  <td className="py-3 px-6 text-center font-mono text-sm text-indigo-300">{proc.threads}</td>
                  <td className="py-3 px-6 text-right font-mono text-sm">{proc.memory_mb}</td>
                  <td className="py-3 px-6 text-center">
                    {proc.connections_count > 0 ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {proc.connections_count}
                      </span>
                    ) : (
                      <span className="text-slate-600">-</span>
                    )}
                  </td>
                  <td className="py-3 px-6 text-right">
                    {proc.threat_score > 0 ? (
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold border 
                        ${proc.threat_score >= 50 ? 'bg-red-500/10 text-red-400 border-red-500/30' : 
                          proc.threat_score >= 20 ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 
                          'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'}`}>
                        {proc.threat_score}
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/10">
                        Safe
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-6">
                    <button 
                      onClick={() => setSelectedProcess(proc)}
                      className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-lg border border-slate-700 transition-colors focus:ring-2 focus:ring-blue-500 outline-none"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
              {filteredProcesses.length === 0 && (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-500">
                    {stats.processes.length === 0 ? "Awaiting scan data..." : "No processes match your search."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
