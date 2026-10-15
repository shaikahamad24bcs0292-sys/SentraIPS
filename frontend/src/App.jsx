import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import Topology3D from './components/Topology3D';
import Fallback2D from './components/Fallback2D';
import SecurityScore3D from './components/SecurityScore3D';
import PcapAnalyzer3D from './components/PcapAnalyzer3D';
import TrafficVis3D from './components/TrafficVis3D';
import FindingsCard3D from './components/FindingsCard3D';
import ComplianceMatrix from './components/ComplianceMatrix';
import ReportViewerModal from './components/ReportViewerModal';
import { checkHealth, generateReport, analyzePcap, DEMO_PRESETS } from './services/api';
import { AlertTriangle, X, ShieldAlert, Cpu, Terminal, ArrowUpRight } from 'lucide-react';

function normalizeData(data) {
  if (!data) return DEMO_PRESETS.compliant;
  
  // Phase 5 SecurityAssessmentReportUnified structure
  if (data.summary && data.vpn_configuration) {
    return {
      capture_id: data.report_id || data.summary.analysis_id || 'capture',
      filename: data.summary.analysis_id || 'capture.pcap',
      ipsec_detected: data.summary.ipsec_detected ?? true,
      ike_detected: true,
      esp_detected: data.vpn_configuration.esp_detected ?? (data.vpn_configuration.esp_packets > 0),
      ike_version: data.vpn_configuration.ike_version || data.summary.ike_version || 'IKEv2',
      encryption: data.vpn_configuration.encryption || data.summary.encryption || 'AES-256-GCM',
      encryption_key_length: data.vpn_configuration.encryption_key_length,
      authentication: data.vpn_configuration.authentication || 'SHA-256',
      dh_group: data.vpn_configuration.dh_group,
      dh_group_name: data.vpn_configuration.dh_group_name || data.summary.dh_group || 'ecp256',
      pfs: data.vpn_configuration.pfs ?? data.summary.pfs ?? 'Unknown',
      initiator_spi: data.vpn_configuration.initiator_spi || '0x8f2d4e1a0b3c5e7f',
      responder_spi: data.vpn_configuration.responder_spi || '0x1c9a4b8e2f6d0e3a',
      total_packets: data.vpn_configuration.total_packets || 0,
      ike_packets: data.vpn_configuration.ike_packets || 0,
      esp_packets: data.vpn_configuration.esp_packets || 0,
      security_assessment: {
        risk_score: data.summary.overall_risk_score ?? 0,
        severity: data.summary.severity || 'LOW',
        findings: data.findings || [],
        recommendations: data.recommendations || [],
        sub_scores: data.security_assessment?.sub_scores || {
          crypto_risk: 0,
          key_exchange_risk: 0,
          configuration_risk: 0,
          metadata_exposure_risk: 0,
        },
        observed_configuration: data.vpn_configuration,
      },
      traffic_analysis: data.traffic_analysis || {
        traffic_type: data.summary.traffic_classification || 'Unknown',
        confidence: data.summary.traffic_confidence || 0.0,
      },
      compliance: data.compliance || [],
      raw: data,
    };
  }

  // Phase 4 PCAPAnalysisResponse structure
  return {
    ...data,
    compliance: data.compliance || data.security_assessment?.compliance || [],
  };
}

export default function App() {
  const [sessionData, setSessionData] = useState(DEMO_PRESETS.compliant);
  const [is3DEnabled, setIs3DEnabled] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [activePreset, setActivePreset] = useState('demo_capture');

  // Verify backend health on mount
  useEffect(() => {
    let mounted = true;
    const verifyHealth = async () => {
      const res = await checkHealth();
      if (mounted) {
        setBackendOnline(res.online);
      }
    };
    verifyHealth();

    const interval = setInterval(verifyHealth, 10000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  // Handle Preset Switching
  const handleSelectPreset = (presetKey) => {
    const preset = DEMO_PRESETS[presetKey];
    if (preset) {
      setSessionData(preset);
      setActivePreset(preset.capture_id);
      setErrorMessage(null);
    }
  };

  // Handle Real File Upload and Analysis
  const handleAnalyzeFile = async (file) => {
    setIsAnalyzing(true);
    setErrorMessage(null);

    try {
      // First attempt Phase 5 full report generation endpoint
      let result;
      try {
        result = await generateReport(file);
      } catch (genErr) {
        // Fallback to standard /analyze-pcap endpoint
        console.warn('generateReport failed, attempting /analyze-pcap:', genErr);
        result = await analyzePcap(file);
      }

      const normalized = normalizeData(result);
      setSessionData(normalized);
      setActivePreset(normalized.capture_id || file.name);
    } catch (err) {
      console.error('File analysis error:', err);
      setErrorMessage(
        backendOnline
          ? `Analysis failed: ${err.message}. Please verify the PCAP contains valid IPsec/IKE/ESP frames.`
          : 'Backend API is currently offline. Please launch FastAPI on port 8000 to process custom PCAP uploads.'
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const findings = sessionData?.security_assessment?.findings || sessionData?.findings || [];
  const compliance = sessionData?.compliance || [];
  const trafficAnalysis = sessionData?.traffic_analysis;
  const espPackets = sessionData?.esp_packets ?? sessionData?.vpn_configuration?.esp_packets ?? 0;

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Top SOC Navigation Bar */}
      <Header
        backendOnline={backendOnline}
        is3DEnabled={is3DEnabled}
        onToggle3D={() => setIs3DEnabled((prev) => !prev)}
        onSelectPreset={handleSelectPreset}
        onOpenReport={() => setReportModalOpen(true)}
        activeCaptureId={activePreset}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Error / Offline Alert Banner */}
        {errorMessage && (
          <div className="flex items-center justify-between p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 shadow-lg">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <p className="text-xs sm:text-sm font-medium">{errorMessage}</p>
            </div>
            <button
              type="button"
              onClick={() => setErrorMessage(null)}
              className="p-1 rounded-lg hover:bg-rose-900/50 text-rose-400"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* TOP ROW: 3D Network Topology (or 2D Fallback) + 3D Security Score Hologram */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
          <div className="lg:col-span-2">
            {is3DEnabled ? (
              <Topology3D sessionData={sessionData} is3DEnabled={is3DEnabled} />
            ) : (
              <Fallback2D sessionData={sessionData} />
            )}
          </div>
          <div className="lg:col-span-1">
            <SecurityScore3D
              assessment={sessionData?.security_assessment}
              is3DEnabled={is3DEnabled}
            />
          </div>
        </div>

        {/* MIDDLE ROW: 3D Floating PCAP Analyzer Dropzone + 3D ESP Traffic Flow Spectrum */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
          <PcapAnalyzer3D
            onAnalyzeFile={handleAnalyzeFile}
            onSelectPreset={handleSelectPreset}
            isAnalyzing={isAnalyzing}
            is3DEnabled={is3DEnabled}
          />
          <TrafficVis3D
            trafficAnalysis={trafficAnalysis}
            espPackets={espPackets}
            is3DEnabled={is3DEnabled}
          />
        </div>

        {/* BOTTOM ROW: Deterministic Security Findings + Standards Compliance Matrix */}
        <div className="space-y-6">
          <FindingsCard3D findings={findings} />
          <ComplianceMatrix compliance={compliance} />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-4 px-6 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
          <span>SentraIPS Enterprise SOC &bull; Smart India Hackathon Prototype</span>
          <span className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-cyan-400" />
            RFC 4301 / RFC 7296 / NIST SP 800-77 Rev. 1 Compliant Engine
          </span>
        </div>
      </footer>

      {/* Full Audit Report Modal */}
      <ReportViewerModal
        isOpen={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        sessionData={sessionData}
      />
    </div>
  );
}
