import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, HelpCircle, Shield } from 'lucide-react';

export default function ComplianceMatrix({ compliance = [] }) {
  if (!compliance || compliance.length === 0) return null;

  const getStatusBadge = (status) => {
    const s = String(status).toUpperCase();
    if (s === 'PASS') {
      return (
        <span className="badge-pass inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full font-mono">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" /> PASS
        </span>
      );
    }
    if (s === 'WARNING') {
      return (
        <span className="badge-warn inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full font-mono">
          <AlertTriangle className="w-3 h-3 text-amber-400" /> WARNING
        </span>
      );
    }
    if (s === 'FAIL') {
      return (
        <span className="badge-crit inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full font-mono">
          <XCircle className="w-3 h-3 text-rose-400" /> FAIL
        </span>
      );
    }
    return (
      <span className="badge-info inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full font-mono">
        <HelpCircle className="w-3 h-3 text-sky-400" /> UNKNOWN
      </span>
    );
  };

  return (
    <div className="glass-panel p-5 relative overflow-hidden">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100 uppercase tracking-wide">
            Standards Compliance & Best Practice Matrix (NIST & RFC Baseline)
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          NIST SP 800-77 Rev. 1 &bull; RFC 8221 &bull; RFC 8247
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
              <th className="pb-2 font-semibold">Control ID</th>
              <th className="pb-2 font-semibold">Control Title</th>
              <th className="pb-2 font-semibold">Status</th>
              <th className="pb-2 font-semibold">Observed Configuration</th>
              <th className="pb-2 font-semibold">Standard Baseline</th>
              <th className="pb-2 font-semibold">Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {compliance.map((c, idx) => (
              <tr key={c.control_id || idx} className="hover:bg-slate-900/40 transition-colors">
                <td className="py-2.5 text-slate-300 font-bold">{c.control_id || c.id || `COMP-${idx + 1}`}</td>
                <td className="py-2.5 text-slate-200">{c.title || c.category}</td>
                <td className="py-2.5">{getStatusBadge(c.status)}</td>
                <td className="py-2.5">
                  <code className="text-cyan-300 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                    {String(c.observed_value)}
                  </code>
                </td>
                <td className="py-2.5 text-slate-300">{c.expected_standard || c.standard || 'Recommended baseline'}</td>
                <td className="py-2.5 text-slate-400 text-[11px] max-w-xs">{c.rationale || c.details || 'Baseline control.'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
