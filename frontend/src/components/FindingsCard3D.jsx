import React, { useState } from 'react';
import { AlertCircle, AlertTriangle, ShieldCheck, Info, ChevronDown, ChevronUp, BookOpen } from 'lucide-react';

export default function FindingsCard3D({ findings = [] }) {
  const [expandedId, setExpandedId] = useState(null);

  if (!findings || findings.length === 0) {
    return (
      <div className="glass-panel p-6 text-center">
        <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
        <h3 className="text-sm font-semibold text-emerald-300">No Security Findings Detected</h3>
        <p className="text-xs text-slate-400 mt-1">
          Observed cryptographic configuration complies with modern IPsec security baselines (NIST SP 800-77 & RFC 8221).
        </p>
      </div>
    );
  }

  const getSeverityStyle = (sev) => {
    const s = String(sev).toUpperCase();
    if (s === 'CRITICAL') return { badge: 'badge-crit', border: 'border-rose-500/40', text: 'text-rose-400', icon: AlertCircle };
    if (s === 'HIGH') return { badge: 'badge-crit', border: 'border-orange-500/40', text: 'text-orange-400', icon: AlertCircle };
    if (s === 'MEDIUM') return { badge: 'badge-warn', border: 'border-amber-500/40', text: 'text-amber-400', icon: AlertTriangle };
    return { badge: 'badge-info', border: 'border-sky-500/40', text: 'text-sky-400', icon: Info };
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-slate-100 uppercase tracking-wide">
          Security Findings & Deterministic Threat Matrix ({findings.length})
        </h3>
        <span className="text-xs text-slate-400 font-mono">
          Interactive Depth Cards
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {findings.map((f, idx) => {
          const style = getSeverityStyle(f.severity);
          const Icon = style.icon;
          const isExpanded = expandedId === (f.id || idx);

          return (
            <div
              key={f.id || idx}
              className={`glass-panel p-4 cursor-pointer transition-all duration-300 transform hover:-translate-y-1 hover:shadow-xl ${style.border}`}
              style={{
                perspective: '1000px',
                transformStyle: 'preserve-3d',
              }}
              onClick={() => setExpandedId(isExpanded ? null : (f.id || idx))}
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 shrink-0 ${style.text}`} />
                  <span className="text-xs font-mono font-bold text-slate-300 bg-slate-900/90 px-1.5 py-0.5 rounded border border-slate-800">
                    {f.id || `VPN-${idx + 1}`}
                  </span>
                  <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full font-mono uppercase ${style.badge}`}>
                    {f.severity}
                  </span>
                </div>
                <div className="text-slate-400 text-xs">
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
              </div>

              {/* Title & Category */}
              <h4 className="text-sm font-semibold text-slate-100 mb-1 leading-snug">
                {f.title}
              </h4>
              <div className="text-[11px] font-mono text-cyan-400/80 mb-2">
                Category: {f.category} &bull; Confidence: {((f.confidence || 1.0) * 100).toFixed(0)}%
              </div>

              {/* Description */}
              <p className="text-xs text-slate-300 leading-relaxed mb-3">
                {f.description}
              </p>

              {/* Expanded Evidence & Remediation */}
              {isExpanded && (
                <div className="space-y-2 pt-3 border-t border-slate-800/80 text-xs font-mono animate-fadeIn">
                  {/* Evidence */}
                  <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-400 font-bold block mb-1">Observed Evidence:</span>
                    <pre className="text-[11px] text-cyan-300 whitespace-pre-wrap break-all font-mono">
                      {typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : String(f.evidence)}
                    </pre>
                  </div>

                  {/* Impact */}
                  {f.impact && (
                    <div className="text-rose-300/90">
                      <strong className="text-rose-400">Threat & Impact:</strong> {f.impact}
                    </div>
                  )}

                  {/* Recommendation */}
                  {f.recommendation && (
                    <div className="text-emerald-300/90 bg-emerald-950/20 p-2 rounded border border-emerald-900/40">
                      <strong className="text-emerald-400">Remedial Action:</strong> {f.recommendation}
                    </div>
                  )}

                  {/* Standards References */}
                  {f.references && f.references.length > 0 && (
                    <div className="text-[11px] text-slate-400 pt-1 flex items-center gap-1.5 flex-wrap">
                      <BookOpen className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span>Standards:</span>
                      {f.references.map((r, rIdx) => (
                        <span key={rIdx} className="bg-slate-900 px-1.5 py-0.5 rounded text-slate-300 border border-slate-800">
                          {typeof r === 'object' ? `${r.source} ${r.section || ''}` : String(r)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
