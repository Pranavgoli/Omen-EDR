import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, LayoutDashboard, Target, BarChart3, Eye, AlertTriangle, FileText } from 'lucide-react';
import { Dialog } from '@headlessui/react';
import ContinuousMonitoring from './components/ContinuousMonitoring';
import ThreatDetection from './components/ThreatDetection';
import IncidentResponse from './components/IncidentResponse';
import DataAnalysis from './components/DataAnalysis';
import Visibility from './components/Visibility';
import LogForensics from './components/LogForensics';

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
  const [activeTab, setActiveTab] = useState('monitoring');
  const [incidentLog, setIncidentLog] = useState([]);

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
        setIncidentLog(prev => [{
          timestamp: new Date().toLocaleTimeString(),
          action: 'Quarantine',
          target: `${pid}`,
          message: data.message,
          success: true
        }, ...prev]);
        setSelectedProcess(null); // Close modal
      } else {
        alert(`Error: ${data.message}`);
        setIncidentLog(prev => [{
          timestamp: new Date().toLocaleTimeString(),
          action: 'Quarantine Failed',
          target: `${pid}`,
          message: data.message,
          success: false
        }, ...prev]);
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
    setSessionToken(token);
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
        <div className="flex items-center gap-2 text-sm font-medium border-l border-slate-700 pl-4">
          <span className="relative flex h-3 w-3">
            {wsConnected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
            <span className={`relative inline-flex rounded-full h-3 w-3 ${wsConnected ? 'bg-emerald-500' : 'bg-slate-600'}`}></span>
          </span>
          <span className={wsConnected ? 'text-emerald-400' : 'text-slate-500'}>
            {wsConnected ? 'Live Connection Active' : 'Disconnected'}
          </span>
        </div>
      </header>

      {/* Primary Navigation Tabs */}
      <nav className="flex p-1 bg-slate-900/80 rounded-xl border border-slate-800 shrink-0 overflow-x-auto text-center w-full">
        <button onClick={() => setActiveTab('monitoring')} className={`flex-1 flex justify-center items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${activeTab === 'monitoring' ? 'bg-slate-800 text-white shadow-md border border-slate-700' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
          <LayoutDashboard size={18} /> Continuous Monitoring
        </button>
        <button onClick={() => setActiveTab('threats')} className={`flex-1 flex justify-center items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${activeTab === 'threats' ? 'bg-slate-800 text-white shadow-md border border-slate-700' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
          <AlertTriangle size={18} /> Threat Detection <span className="ml-1 bg-slate-950 text-xs px-1.5 rounded text-amber-500 border border-slate-800">{stats.threats_found}</span>
        </button>
        <button onClick={() => setActiveTab('response')} className={`flex-1 flex justify-center items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${activeTab === 'response' ? 'bg-slate-800 text-white shadow-md border border-slate-700' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
          <Target size={18} /> Incident Response
        </button>
        <button onClick={() => setActiveTab('analysis')} className={`flex-1 flex justify-center items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${activeTab === 'analysis' ? 'bg-slate-800 text-white shadow-md border border-slate-700' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
          <BarChart3 size={18} /> Data Analysis
        </button>
        <button onClick={() => setActiveTab('visibility')} className={`flex-1 flex justify-center items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${activeTab === 'visibility' ? 'bg-slate-800 text-white shadow-md border border-slate-700' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
          <Eye size={18} /> Visibility & Context
        </button>
        <button onClick={() => setActiveTab('logs')} className={`flex-1 flex justify-center items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${activeTab === 'logs' ? 'bg-slate-800 text-white shadow-md border border-slate-700' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}>
          <FileText size={18} /> Log Forensics
        </button>
      </nav>

      {/* Dynamic View Generation */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'monitoring' && <ContinuousMonitoring stats={stats} searchQuery={searchQuery} setSearchQuery={setSearchQuery} setSelectedProcess={setSelectedProcess} />}
        {activeTab === 'threats' && <ThreatDetection stats={stats} setSelectedProcess={setSelectedProcess} />}
        {activeTab === 'response' && <IncidentResponse stats={stats} handleQuarantine={handleQuarantine} incidentLog={incidentLog} quarantining={quarantining} />}
        {activeTab === 'analysis' && <DataAnalysis stats={stats} />}
        {activeTab === 'visibility' && <Visibility stats={stats} />}
        {activeTab === 'logs' && <LogForensics token={sessionToken} />}
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
