import React, { useState } from 'react';
import { X, FileText, Download, ExternalLink, Code2, ShieldAlert } from 'lucide-react';

export default function ReportViewerModal({ isOpen, onClose, sessionData }) {
  const [activeTab, setActiveTab] = useState('html'); // 'html' or 'json'

  if (!isOpen || !sessionData) return null;

  const captureId = sessionData.capture_id || 'demo_capture';
  const riskScore = sessionData.security_assessment?.risk_score ?? 15;
  const severity = sessionData.security_assessment?.severity || 'LOW';
  const findings = sessionData.security_assessment?.findings || [];
  const compliance = sessionData.compliance || [];

  const jsonString = JSON.stringify(sessionData, null, 2);

  const downloadJson = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentraips_audit_${captureId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const openHtmlReport = () => {
    // If backend reports endpoint is active
    window.open(`http://127.0.0.1:8000/reports/${captureId}/html`, '_blank');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <div className="glass-panel w-full max-w-5xl h-[85vh] flex flex-col overflow-hidden border border-cyan-500/30 shadow-2xl">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-base font-bold text-slate-100">
                Security & Compliance Audit Report — {captureId}
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Risk Score: {riskScore}/100 ({severity}) &bull; NIST SP 800-77 Rev. 1 Baseline
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Tab Buttons */}
            <div className="flex bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveTab('html')}
                className={`px-3 py-1 rounded transition-colors ${
                  activeTab === 'html' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Executive Audit View
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('json')}
                className={`px-3 py-1 rounded transition-colors ${
                  activeTab === 'json' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Raw JSON Schema
              </button>
            </div>

            <button
              type="button"
              onClick={downloadJson}
              className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors"
              title="Download JSON Report"
            >
              <Download className="w-4 h-4" />
            </button>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-rose-400 border border-slate-700 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'html' ? (
            <div className="space-y-6 text-slate-200 text-xs">
              {/* Executive Summary Card */}
              <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 flex justify-between items-center">
                <div>
                  <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-widest font-bold">Executive Overview</span>
                  <div className="text-xl font-extrabold text-slate-100 mt-1">
                    Risk Score: <span className={riskScore <= 24 ? 'text-emerald-400' : 'text-amber-400'}>{riskScore}/100</span> ({severity})
                  </div>
                  <div className="text-slate-400 mt-1">
                    Evaluated against NIST SP 800-77 Rev. 1 & RFC 8221/8247 baseline.
                  </div>
                </div>

                <button
                  type="button"
                  onClick={openHtmlReport}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-mono text-xs transition-colors"
                >
                  <ExternalLink className="w-4 h-4" />
                  <span>Open Standalone HTML Report</span>
                </button>
              </div>

              {/* Detected Cryptographic Parameters */}
              <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono mb-3">
                  Cryptographic Suite & Network Baseline
                </h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
                  <div>
                    <span className="text-slate-400 block">Symmetric Cipher:</span>
                    <strong className="text-cyan-300">{sessionData.encryption || 'AES-256-GCM'}</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Key Exchange:</span>
                    <strong className="text-cyan-300">{sessionData.dh_group_name || 'ecp256'} (Group {sessionData.dh_group || 19})</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Forward Secrecy:</span>
                    <strong className="text-cyan-300">PFS: {String(sessionData.pfs)}</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block">IKE Protocol:</span>
                    <strong className="text-cyan-300">{sessionData.ike_version || 'IKEv2'}</strong>
                  </div>
                </div>
              </div>

              {/* Security Findings Summary */}
              <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono mb-3">
                  Identified Security Findings ({findings.length})
                </h4>
                {findings.length === 0 ? (
                  <div className="text-emerald-400 font-mono">No vulnerabilities detected. All parameters comply with RFC 8221/8247 recommendations.</div>
                ) : (
                  <div className="space-y-3">
                    {findings.map((f, i) => (
                      <div key={i} className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <span className="text-cyan-400 font-mono font-bold">{f.id}</span>
                          <span className="text-slate-200 font-semibold">{f.title}</span>
                          <span className="badge-crit text-[10px] px-2 py-0.2 rounded font-mono uppercase">{f.severity}</span>
                        </div>
                        <p className="text-slate-400">{f.description}</p>
                        {f.recommendation && (
                          <div className="text-emerald-400 text-[11px] font-mono mt-1">
                            Action: {f.recommendation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 h-full overflow-auto">
              <pre className="text-xs font-mono text-cyan-300">
                {jsonString}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
