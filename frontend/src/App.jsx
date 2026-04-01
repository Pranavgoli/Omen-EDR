import React, { useState, useEffect } from 'react';
import { Activity, Cpu, HardDrive, ShieldAlert, ShieldCheck, Database, Layers, Search } from 'lucide-react';
import { Dialog } from '@headlessui/react';

function App() {
  const [stats, setStats] = useState({
    cpu_usage: 0,
    ram_usage: 0,
    disk_usage: 0,
    total_threads: 0,
    total_processes: 0,
    threats_found: 0,
    scan_status: 'idle',
    processes: []
  });
  
  const [wsConnected, setWsConnected] = useState(false);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [quarantining, setQuarantining] = useState(false);
  const [sessionToken, setSessionToken] = useState(null);

  const handleQuarantine = async (pid) => {
    if (!sessionToken) {
      alert("Security Error: No active session token. Please refresh.");
      return;
    }

    if (!window.confirm(`Are you sure you want to terminate process ${pid}?`)) return;
    
    setQuarantining(true);
    try {
      const resp = await fetch(`http://127.0.0.1:8192/api/quarantine/${pid}`, {
        method: 'POST',
        headers: {
          'X-Omen-Token': sessionToken
        }
      });
      const data = await resp.json();
      if (data.status === 'success') {
        alert(data.message);
        setSelectedProcess(null); // Close modal
      } else {
        alert(`Error: ${data.message}`);
      }
    } catch (err) {
      alert(`Network error: ${err.message}`);
    } finally {
      setQuarantining(false);
    }
  };

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

  useEffect(() => {
    // Connect to WebSocket Server with Security Token (OWASP A01:2025)
    const token = import.meta.env.VITE_SESSION_TOKEN;
    const ws = new WebSocket(`ws://127.0.0.1:8192/ws/stats?token=${token}`);

    ws.onopen = () => {
      console.log('Connected to Backend');
      setWsConnected(true);
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      // Stats Update

      setStats({
        ...data,
        // if backend doesn't send processes sometimes, fallback
        processes: data.processes || []
      });
    };

    ws.onclose = () => {
      console.log('Disconnected');
      setWsConnected(false);
      // Optional: Add auto-reconnect fallback
    };

    return () => ws.close();
  }, []);

  return (
    <div className="min-h-screen p-6 max-w-7xl mx-auto flex flex-col gap-6">
      
      {/* Header */}
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-xl border ${stats.threats_found > 0 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-green-500/10 border-green-500/30 text-green-400'}`}>
            {stats.threats_found > 0 ? <ShieldAlert size={28} /> : <ShieldCheck size={28} />}
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white leading-tight">
              Omen EDR
            </h1>
            <p className="text-sm text-slate-400">Threat Telemetry & Process Monitor</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-sm font-medium">
          <span className="relative flex h-3 w-3">
            {wsConnected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
            <span className={`relative inline-flex rounded-full h-3 w-3 ${wsConnected ? 'bg-emerald-500' : 'bg-slate-600'}`}></span>
          </span>
          <span className={wsConnected ? 'text-emerald-400' : 'text-slate-500'}>
            {wsConnected ? 'Live Connection Active' : 'Disconnected'}
          </span>
        </div>
      </header>

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

      {/* Deep Dive Modal */}
      <Dialog 
        open={!!selectedProcess} 
        onClose={() => setSelectedProcess(null)}
        className="relative z-50"
      >
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm" aria-hidden="true" />
        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Dialog.Panel className="mx-auto max-w-xl w-full glass-panel flex flex-col shadow-2xl overflow-hidden ring-1 ring-white/10">
            {selectedProcess && (
              <>
                <div className={`p-5 border-b flex justify-between items-start
                  ${selectedProcess.threat_score >= 50 ? 'bg-red-950/30 border-red-900/50' : 
                    selectedProcess.threat_score >= 20 ? 'bg-amber-950/30 border-amber-900/50' : 
                    'bg-slate-900 border-slate-800'}`}>
                  
                  <div>
                    <Dialog.Title className="text-xl font-bold flex items-center gap-2">
                       {selectedProcess.name}
                       {selectedProcess.threat_score >= 50 && <ShieldAlert className="text-red-500" size={20}/>}
                    </Dialog.Title>
                    <p className="text-sm text-slate-400 mt-1 font-mono">{selectedProcess.path}</p>
                  </div>
                  
                  <div className="text-right">
                    <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-1">Threat Score</div>
                    <div className={`text-3xl font-black 
                      ${selectedProcess.threat_score >= 50 ? 'text-red-400' : 
                        selectedProcess.threat_score >= 20 ? 'text-amber-400' : 
                        selectedProcess.threat_score > 0 ? 'text-yellow-500' : 'text-green-500'}`}>
                      {selectedProcess.threat_score}
                    </div>
                  </div>
                </div>

                {selectedProcess.analysis && (
                  <div className={`px-5 py-2 text-sm font-semibold border-b ${
                    selectedProcess.analysis.includes('False Positive') ? 'bg-blue-900/30 text-blue-400 border-blue-900/50' :
                    selectedProcess.analysis.includes('Critical') ? 'bg-red-900/30 text-red-500 border-red-900/50' :
                    selectedProcess.analysis.includes('Benign') ? 'bg-green-900/30 text-green-500 border-green-900/50' :
                    'bg-amber-900/30 text-amber-500 border-amber-900/50'
                  }`}>
                    Analysis: {selectedProcess.analysis}
                  </div>
                )}

                <div className="p-5 flex-1 bg-slate-900/80">
                  <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">Forensic Evidence</h4>
                  
                  {selectedProcess.evidence && selectedProcess.evidence.length > 0 ? (
                    <ul className="space-y-3">
                      {selectedProcess.evidence.map((ev, i) => (
                        <li key={i} className="flex gap-3 bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                          <div className="mt-0.5 text-amber-500 border border-amber-500/20 bg-amber-500/10 h-5 w-5 rounded flex items-center justify-center font-bold text-xs shrink-0">!</div>
                          <span className="text-sm text-slate-300">{ev}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="text-slate-500 text-sm italic py-4 flex flex-col items-center justify-center border border-dashed border-slate-700 rounded-lg bg-slate-800/20">
                      <ShieldCheck className="text-green-500/50 mb-2" size={32} />
                      No suspicious heuristic traits found. Process appears benign.
                    </div>
                  )}

                  <div className="mt-6 grid grid-cols-3 gap-4">
                    <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800">
                      <div className="text-xs text-slate-500 font-medium">Process ID</div>
                      <div className="font-mono mt-1 text-slate-300">{selectedProcess.pid}</div>
                    </div>
                    <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800">
                      <div className="text-xs text-slate-500 font-medium">Memory Footprint</div>
                      <div className="font-mono mt-1 text-slate-300">{selectedProcess.memory_mb} MB</div>
                    </div>
                    <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800">
                      <div className="text-xs text-slate-500 font-medium">Threads</div>
                      <div className="font-mono mt-1 text-slate-300">{selectedProcess.threads}</div>
                    </div>
                  </div>
                </div>

                <div className="p-4 bg-slate-950 border-t border-slate-800 flex justify-end gap-3">
                  <button 
                    onClick={() => setSelectedProcess(null)}
                    className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    Close Log
                  </button>
                  <button 
                    onClick={() => handleQuarantine(selectedProcess.pid)}
                    disabled={quarantining || selectedProcess.is_protected}
                    className={`px-4 py-2 text-sm font-semibold text-white rounded-lg shadow-lg transition-all active:scale-95 
                      ${(quarantining || selectedProcess.is_protected) 
                         ? 'bg-slate-700 text-slate-500 cursor-not-allowed border border-slate-600' 
                         : 'bg-red-600 hover:bg-red-500 shadow-red-500/20'}`}
                  >
                    {quarantining ? 'Terminating...' : selectedProcess.is_protected ? 'System Protected' : 'Quarantine Process'}
                  </button>
                </div>
              </>
            )}
          </Dialog.Panel>
        </div>
      </Dialog>
    </div>
  );
}

export default App;
