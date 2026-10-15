import React from 'react';
import { Server, Lock, Activity, ArrowRight, Shield } from 'lucide-react';

export default function Fallback2D({ sessionData }) {
  const encryption = sessionData?.encryption || 'AES-256-GCM';
  const ikeVer = sessionData?.ike_version || 'IKEv2';
  const dhGroup = sessionData?.dh_group_name || 'ecp256';
  const pfs = sessionData?.pfs ?? 'Unknown';
  const espPackets = sessionData?.esp_packets || 0;
  const severity = sessionData?.security_assessment?.severity || 'LOW';

  const isWeak = severity === 'HIGH' || severity === 'CRITICAL';
  const isWarn = severity === 'MEDIUM' || severity === 'LOW-MEDIUM';
  const colorClass = isWeak ? 'text-rose-400' : isWarn ? 'text-amber-400' : 'text-cyan-400';
  const borderClass = isWeak ? 'border-rose-500/40' : isWarn ? 'border-amber-500/40' : 'border-cyan-500/40';

  return (
    <div className="glass-panel p-6 flex flex-col justify-between" style={{ minHeight: '360px' }}>
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Server className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100 uppercase tracking-wide">
            2D High-Performance Topology View (Fallback Mode)
          </h3>
        </div>
        <span className="text-xs px-2.5 py-1 rounded bg-slate-900 border border-slate-800 font-mono text-slate-300">
          Hardware Accelerated 2D
        </span>
      </div>

      {/* SVG Interactive Topology */}
      <div className="my-6 flex items-center justify-between px-8 gap-4 flex-wrap md:flex-nowrap">
        {/* Gateway A Node */}
        <div className="flex-1 bg-slate-900/90 p-4 rounded-xl border border-slate-800 text-center max-w-[220px] shadow-lg">
          <div className="w-12 h-12 mx-auto mb-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Server className="w-6 h-6 text-cyan-400" />
          </div>
          <h4 className="text-xs font-bold text-slate-100 font-mono">Gateway A (Initiator)</h4>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">192.168.1.1</p>
          <div className="text-[10px] text-cyan-400 font-mono mt-2 bg-slate-950 p-1 rounded">
            SPI: {sessionData?.initiator_spi?.slice(0, 10) || '0x8f2d4e1a'}...
          </div>
        </div>

        {/* Center Tunnel Conduit */}
        <div className="flex-1 text-center px-4">
          <div className="flex items-center justify-center gap-2 text-xs font-mono font-bold mb-2">
            <Lock className={`w-4 h-4 ${colorClass}`} />
            <span className={colorClass}>IPsec ESP Encrypted Conduit</span>
          </div>

          {/* Conduit Graphic */}
          <div className="relative h-3 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700">
            <div 
              className={`h-full rounded-full transition-all duration-500 ${isWeak ? 'bg-rose-500' : isWarn ? 'bg-amber-500' : 'bg-cyan-400'}`}
              style={{ width: '100%' }}
            />
          </div>

          <div className="mt-2 text-xs font-mono text-slate-300">
            <strong>{espPackets.toLocaleString()}</strong> ESP Packets &bull; {ikeVer}
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-0.5">
            {encryption} &bull; DH {dhGroup} &bull; PFS: {String(pfs)}
          </div>
        </div>

        {/* Gateway B Node */}
        <div className="flex-1 bg-slate-900/90 p-4 rounded-xl border border-slate-800 text-center max-w-[220px] shadow-lg">
          <div className="w-12 h-12 mx-auto mb-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Server className="w-6 h-6 text-cyan-400" />
          </div>
          <h4 className="text-xs font-bold text-slate-100 font-mono">Gateway B (Responder)</h4>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">192.168.2.1</p>
          <div className="text-[10px] text-cyan-400 font-mono mt-2 bg-slate-950 p-1 rounded">
            SPI: {sessionData?.responder_spi?.slice(0, 10) || '0x1c9a4b8e'}...
          </div>
        </div>
      </div>

      <div className="text-xs font-mono text-slate-400 text-center pt-3 border-t border-slate-800">
        Status Profile: <strong className={colorClass}>{severity}</strong> &bull; Zero payload decryption architecture
      </div>
    </div>
  );
}
