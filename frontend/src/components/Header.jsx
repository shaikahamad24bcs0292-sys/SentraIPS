import React from 'react';
import { Shield, Radio, Box, Eye, FileText, Download, CheckCircle, RefreshCw } from 'lucide-react';

export default function Header({ 
  backendOnline, 
  is3DEnabled, 
  onToggle3D, 
  onSelectPreset, 
  onOpenReport,
  activeCaptureId
}) {
  return (
    <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-50 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 flex-wrap">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-sky-600/30 border border-cyan-500/40 shadow-lg shadow-cyan-500/10">
            <Shield className="w-5 h-5 text-cyan-400" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-100 flex items-center gap-1.5">
                Sentra<span className="text-cyan-400">IPS</span>
              </h1>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-950 text-cyan-300 border border-sky-800">
                3D SOC v0.5.0
              </span>
            </div>
            <p className="text-xs text-slate-400">
              AI-Driven IPsec VPN Cryptographic Assessment & 3D Network Telemetry
            </p>
          </div>
        </div>

        {/* Center / Right Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Backend Health Pill */}
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono">
            <div className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            <span className="text-slate-300">
              API: <strong>{backendOnline ? 'Online (8000)' : 'Offline / Standalone'}</strong>
            </span>
          </div>

          {/* Quick Demo Switcher */}
          <div className="flex items-center gap-1.5 bg-slate-900/90 border border-slate-800 p-1 rounded-lg text-xs font-mono">
            <span className="text-slate-400 pl-2 pr-1 text-[11px]">Demo:</span>
            <button
              type="button"
              onClick={() => onSelectPreset('compliant')}
              className={`px-2.5 py-1 rounded transition-colors ${
                activeCaptureId === 'demo_capture' 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Compliant (GCM/19)
            </button>
            <button
              type="button"
              onClick={() => onSelectPreset('weak')}
              className={`px-2.5 py-1 rounded transition-colors ${
                activeCaptureId === 'weak_capture' 
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Vulnerable (CBC/5)
            </button>
          </div>

          {/* 3D / 2D Toggle Switch */}
          <button
            type="button"
            onClick={onToggle3D}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium border transition-all ${
              is3DEnabled 
                ? 'bg-sky-500/15 text-cyan-300 border-cyan-500/40 shadow-sm shadow-cyan-500/20' 
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            <Box className={`w-3.5 h-3.5 ${is3DEnabled ? 'text-cyan-400 animate-spin' : ''}`} style={{ animationDuration: '10s' }} />
            <span>3D Visualizer: <strong>{is3DEnabled ? 'ENABLED' : '2D FALLBACK'}</strong></span>
          </button>

          {/* Export Report Trigger */}
          <button
            type="button"
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-gradient-to-r from-sky-600 to-cyan-600 hover:from-sky-500 hover:to-cyan-500 text-white shadow-md shadow-sky-950 transition-all active:scale-95"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>View Full Audit Report</span>
          </button>
        </div>
      </div>
    </header>
  );
}
