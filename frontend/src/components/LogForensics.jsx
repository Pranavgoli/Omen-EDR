import React, { useState, useRef } from 'react';
import { FileText, UploadCloud, AlertTriangle, Hash, Network, Download, Shield, Database, Archive, Globe, Clock, Info, ShieldAlert } from 'lucide-react';

export default function LogForensics({ token }) {
  const [file, setFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [expandedEvent, setExpandedEvent] = useState(null);
  const fileInputRef = useRef(null);

  const supportedExtensions = ".evtx, .evt, .etl, .log, .txt, .bak, .config, .json, .xml, .csv, .gr, .tar.gz, .gz, .out, .pcap, .pcapng";

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    if (!token) {
      alert("Session token is missing.");
      return;
    }

    setAnalyzing(true);
    setResults(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const resp = await fetch('http://127.0.0.1:8192/api/analyze-logs', {
        method: 'POST',
        headers: {
          'X-Omen-Token': token
        },
        body: formData
      });

      const data = await resp.json();
      if (data.status === 'success') {
        setResults(data);
      } else {
        alert(`Forensic analysis failed: ${data.message || "Unknown error"}. Make sure the backend was restarted after updates.`);
      }
    } catch (err) {
      alert("Network or server error during upload: " + err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const downloadText = () => {
    if (!results || !results.decoded_text) return;
    const blob = new Blob([results.decoded_text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `decoded_${file.name}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getLevelColor = (level) => {
    switch (level) {
      case 'Critical': return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      case 'High': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'Medium': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      default: return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
    }
  };

  return (
    <div className="flex flex-col gap-6 h-full min-h-0">
      <div className="glass-panel p-6 border border-slate-800 flex flex-col md:flex-row justify-between items-center gap-4 shrink-0 transition-all hover:bg-slate-900/50">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2 mb-1">
            <ShieldAlert className="text-emerald-500" />
            Universal Log Forensics
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl">
            Drop raw telemetry or Windows binary logs to generate an automated **Forensic Event Timeline**. 
            Cross-OS heuristics enabled.
          </p>
        </div>
        
        <div className="flex items-center gap-3 shrink-0">
          <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
          <button 
            onClick={() => fileInputRef.current.click()}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded-lg border border-slate-700 transition-colors text-xs font-semibold"
          >
            {file ? file.name : "Select Log File..."}
          </button>
          
          <button 
            onClick={handleUpload}
            disabled={!file || analyzing}
            className={`flex items-center gap-2 px-6 py-2 rounded-lg text-xs font-bold shadow-lg transition-all ${(!file || analyzing) ? 'bg-slate-700 text-slate-500 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-500/20 active:scale-95'}`}
          >
            <UploadCloud size={16} />
            {analyzing ? "Synthesizing Timeline..." : "Run Analysis"}
          </button>
        </div>
      </div>

      {analyzing ? (
        <div className="flex-1 glass-panel flex flex-col items-center justify-center p-12 text-slate-400 min-h-[400px]">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/5 mb-6 ring-1 ring-emerald-500/20">
             <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500"></div>
          </div>
          <h3 className="text-lg font-bold text-slate-200 mb-2">Generating Forensic Timeline</h3>
          <p className="text-sm text-center max-w-xs text-slate-500">Extracting timestamps, matching heuristic levels, and determining recommended actions...</p>
        </div>
      ) : results ? (
        <div className="flex flex-col gap-6 flex-1 min-h-0">
          
          {/* Action Row */}
          <div className="flex flex-col md:flex-row justify-between items-center bg-slate-900 border border-slate-800 p-4 rounded-xl gap-4 shrink-0">
             <div className="flex flex-wrap gap-6">
                <div className="flex items-center gap-3">
                   <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <Clock size={16} />
                   </div>
                   <div className="flex flex-col">
                      <span className="text-[10px] uppercase font-black text-slate-500 leading-none mb-1">Total Events</span>
                      <span className="text-sm font-bold text-slate-200 leading-none">{(results.events || []).length}</span>
                   </div>
                </div>
                <div className="flex items-center gap-3">
                   <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      <Archive size={16} />
                   </div>
                   <div className="flex flex-col">
                      <span className="text-[10px] uppercase font-black text-slate-500 leading-none mb-1">Source Type</span>
                      <span className="text-sm font-bold text-slate-200 leading-none">{results.log_type || "Unknown"}</span>
                   </div>
                </div>
             </div>
             
             <button 
                onClick={downloadText}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-5 py-2 rounded-lg text-xs font-bold shadow-lg shadow-blue-500/20 transition-all border-none active:scale-95"
             >
                <Download size={14} />
                Export Analyzed Set (.txt)
             </button>
          </div>

          <div className="grid grid-cols-1 gap-6 flex-1 min-h-0">
             {/* Event Timeline Table */}
             <div className="glass-panel overflow-hidden border-slate-800 flex flex-col h-full bg-slate-950/30">
                <div className="bg-slate-900/50 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                   <h3 className="text-sm font-black uppercase text-slate-400 tracking-widest flex items-center gap-2">
                      <Clock size={16} className="text-emerald-500" /> Forensic Event Timeline
                   </h3>
                </div>
                <div className="flex-1 overflow-auto">
                   <table className="w-full text-left border-collapse min-w-[1000px]">
                      <thead>
                         <tr className="bg-slate-900 text-slate-500 sticky top-0 z-10">
                            <th className="px-6 py-3 text-[10px] font-black uppercase tracking-wider border-b border-slate-800">Timestamp</th>
                            <th className="px-6 py-3 text-[10px] font-black uppercase tracking-wider border-b border-slate-800">Event Description</th>
                            <th className="px-6 py-3 text-[10px] font-black uppercase tracking-wider border-b border-slate-800">Details</th>
                            <th className="px-6 py-3 text-[10px] font-black uppercase tracking-wider border-b border-slate-800">Security Level</th>
                            <th className="px-6 py-3 text-[10px] font-black uppercase tracking-wider border-b border-slate-800">Action Taken</th>
                         </tr>
                      </thead>
                      <tbody>
                         {(!results.events || results.events.length === 0) ? (
                           <tr>
                              <td colSpan="5" className="px-6 py-12 text-center text-slate-500 italic">No discrete events identified in this payload. Try a common log format.</td>
                           </tr>
                         ) : (
                           (results.events || []).map((evt, idx) => (
                             <tr key={idx} className="border-b border-slate-800/50 hover:bg-emerald-500/5 transition-colors group">
                                <td className="px-6 py-4 text-xs font-mono text-emerald-300/80 align-top">
                                   {evt.timestamp}
                                </td>
                                <td className="px-6 py-4 text-xs font-bold text-slate-200 align-top">
                                   {evt.description}
                                </td>
                                <td className="px-6 py-4 text-[11px] text-slate-400 max-w-md align-top">
                                   <div className="line-clamp-2 group-hover:line-clamp-none transition-all">
                                      {evt.details}
                                   </div>
                                </td>
                                <td className="px-6 py-4 align-top">
                                   <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase border ${getLevelColor(evt.level)}`}>
                                      {evt.level}
                                   </span>
                                </td>
                                <td className="px-6 py-4 text-xs font-semibold text-slate-300 align-top italic">
                                   {evt.action}
                                </td>
                             </tr>
                           ))
                         )}
                      </tbody>
                   </table>
                </div>
             </div>

             {/* Secondary Heuristics Row */}
             <div className="grid grid-cols-1 md:grid-cols-3 gap-6 shrink-0">
                <div className="glass-panel p-4 flex flex-col gap-2 bg-slate-900/40">
                   <h4 className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2">
                      <Globe size={12} className="text-teal-400" /> Network Hits
                   </h4>
                   <div className="flex flex-wrap gap-2">
                      {(results?.heuristics?.ips || []).slice(0, 10).map(ip => (
                        <span key={ip} className="text-[10px] font-mono bg-slate-800 px-2 py-0.5 rounded text-teal-300 border border-teal-900/30">{ip}</span>
                      ))}
                      {(results?.heuristics?.ips || []).length === 0 && <span className="text-[10px] italic text-slate-700">None</span>}
                   </div>
                </div>
                <div className="glass-panel p-4 flex flex-col gap-2 bg-slate-900/40">
                   <h4 className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2">
                      <Database size={12} className="text-purple-400" /> Registry
                   </h4>
                   <div className="flex flex-wrap gap-2 truncate">
                      {(results?.heuristics?.registry || []).slice(0, 5).map(reg => (
                        <span key={reg} className="text-[10px] font-mono bg-slate-800 px-2 py-0.5 rounded text-purple-400 border border-purple-900/30 truncate max-w-[150px]">{reg}</span>
                      ))}
                      {(results?.heuristics?.registry || []).length === 0 && <span className="text-[10px] italic text-slate-700">None</span>}
                   </div>
                </div>
                <div className="glass-panel p-4 flex flex-col gap-2 bg-slate-900/40">
                   <h4 className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2">
                      <AlertTriangle size={12} className="text-rose-500" /> Risk Keywords
                   </h4>
                   <div className="flex flex-wrap gap-2">
                      {Object.keys(results?.heuristics?.critical_keywords || {}).slice(0, 5).map(kw => (
                        <span key={kw} className="text-[10px] font-mono bg-rose-500/10 px-2 py-0.5 rounded text-rose-400 border border-rose-500/20">{kw}</span>
                      ))}
                      {Object.keys(results?.heuristics?.critical_keywords || {}).length === 0 && <span className="text-[10px] italic text-slate-700">None</span>}
                   </div>
                </div>
             </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 glass-panel flex flex-col items-center justify-center p-12 text-slate-500 border-dashed border-2 border-slate-800 bg-slate-900/20 min-h-[400px]">
          <div className="p-8 rounded-full bg-slate-800/30 border border-slate-700/50 mb-8 relative">
             <div className="absolute inset-0 bg-emerald-500/5 blur-2xl animate-pulse rounded-full"></div>
             <UploadCloud size={64} className="text-slate-600 relative z-10" />
          </div>
          <h3 className="text-2xl font-black text-slate-200 mb-3 tracking-tight">Timeline Synthesizer</h3>
          <p className="text-xs uppercase tracking-widest text-slate-500 font-bold max-w-md text-center">
             Drop raw log telemetry to build a structured audit trail
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-2 max-w-sm opacity-50">
             {supportedExtensions.split(', ').slice(0, 8).map(ext => (
               <span key={ext} className="text-[9px] font-mono bg-slate-900 border border-slate-800 px-2 py-1 rounded text-slate-500">
                 {ext}
               </span>
             ))}
             <span className="text-[9px] font-mono bg-slate-900 px-2 py-1 rounded text-slate-500">...and more</span>
          </div>
        </div>
      )}
    </div>
  );
}
