/**
 * SentraIPS API Client Service
 * Connects directly to FastAPI backend (port 8000) or Vite reverse proxy.
 */

const API_BASE = '';

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { online: false, error: res.statusText };
    const data = await res.json();
    return { online: true, data };
  } catch (err) {
    return { online: false, error: err.message };
  }
}

export async function analyzePcap(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/analyze-pcap`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'PCAP analysis failed');
  }

  return await res.json();
}

export async function generateReport(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/reports/generate`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Report generation failed');
  }

  return await res.json();
}

export async function getReports() {
  try {
    const res = await fetch(`${API_BASE}/reports`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.reports || [];
  } catch (e) {
    console.warn('Failed to fetch reports list:', e);
    return [];
  }
}

export async function getReportJson(reportId) {
  const res = await fetch(`${API_BASE}/reports/${reportId}`);
  if (!res.ok) throw new Error('Report not found');
  return await res.json();
}

export async function getCaptures() {
  try {
    const res = await fetch(`${API_BASE}/captures`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.captures || [];
  } catch (e) {
    return [];
  }
}

export async function getCaptureDetails(captureId) {
  const res = await fetch(`${API_BASE}/captures/${captureId}`);
  if (!res.ok) throw new Error('Capture details not found');
  return await res.json();
}

/**
 * Built-in known-good fallback demo sessions derived strictly from
 * demo_data/ demo_capture.pcap, weak_capture.pcap, ambiguous_capture.pcap.
 */
export const DEMO_PRESETS = {
  compliant: {
    capture_id: 'demo_capture',
    filename: 'demo_capture.pcap',
    file_size_bytes: 42180,
    ipsec_detected: true,
    ike_detected: true,
    esp_detected: true,
    ike_version: 'IKEv2',
    encryption: 'AES-256-GCM',
    encryption_key_length: 256,
    authentication: 'SHA-256',
    dh_group: 19,
    dh_group_name: 'ecp256',
    pfs: true,
    initiator_spi: '0x8f2d4e1a0b3c5e7f',
    responder_spi: '0x1c9a4b8e2f6d0e3a',
    total_packets: 194,
    ike_packets: 4,
    esp_packets: 190,
    security_assessment: {
      risk_score: 15,
      severity: 'LOW',
      findings: [
        {
          id: 'VPN-001',
          title: 'Traffic Flow Pattern Exposure',
          severity: 'LOW',
          category: 'Metadata Security',
          description: 'Observable packet lengths and inter-arrival timing permit statistical application profiling.',
          evidence: { packet_size_std: 324.5, mean_packet_size: 612.4 },
          impact: 'Passive observers can infer traffic classification without decrypting ESP payloads.',
          recommendation: 'Evaluate IPsec Traffic Flow Confidentiality (TFC) padding (RFC 4303 Section 2.7) if application masking is required.',
          confidence: 0.95,
          source: 'Observed from ESP packet stream',
          references: ['RFC 4303 Section 2.7', 'NIST SP 800-77 Section 4.2'],
        },
      ],
      recommendations: [
        {
          id: 'REC-001',
          priority: 'LOW',
          title: 'Maintain Current AEAD Baseline',
          action: 'Retain AES-256-GCM and DH Group 19 (ecp256) as standard production configuration.',
          target_parameter: 'Cryptography',
          rationale: 'Fully compliant with NIST SP 800-77 Rev. 1 and RFC 8221 MUST requirements.',
        },
      ],
      sub_scores: {
        crypto_risk: 0,
        key_exchange_risk: 0,
        configuration_risk: 0,
        metadata_exposure_risk: 15,
      },
      observed_configuration: {
        vpn_mode: 'Tunnel',
        encryption: 'AES-256-GCM',
        dh_group: 19,
        pfs: true,
        ike_version: 'IKEv2',
      },
    },
    traffic_analysis: {
      traffic_type: 'Web',
      confidence: 1.0,
      model_used: 'RandomForest',
      packet_count: 190,
      flow_duration_sec: 14.82,
      mean_packet_size: 612.4,
      std_packet_size: 324.5,
      min_packet_size: 64,
      max_packet_size: 1420,
      mean_iat_ms: 78.4,
      burst_count: 12,
      probabilities: { Web: 1.0, Video: 0.0, VoIP: 0.0, ICMP: 0.0, Bulk: 0.0 },
    },
    compliance: [
      { control_id: 'COMP-ENC-01', title: 'Symmetric Encryption Suite', status: 'PASS', observed_value: 'AES-256-GCM', expected_standard: 'AES-256-GCM / AES-128-GCM (AEAD)', rationale: 'Complies with NIST SP 800-77 Rev. 1 Table 4-1.' },
      { control_id: 'COMP-DH-01', title: 'Diffie-Hellman Key Exchange Group', status: 'PASS', observed_value: 'Group 19 (ecp256)', expected_standard: 'Group 19 or Group 14', rationale: 'Complies with RFC 8247 Section 2.4.' },
      { control_id: 'COMP-PFS-01', title: 'Perfect Forward Secrecy (PFS)', status: 'PASS', observed_value: 'Enabled', expected_standard: 'Enabled for all Child SAs', rationale: 'Ensures cryptographic isolation across sessions.' },
      { control_id: 'COMP-IKE-01', title: 'IKE Protocol Version', status: 'PASS', observed_value: 'IKEv2 (RFC 7296)', expected_standard: 'IKEv2', rationale: 'Modern anti-DoS cookie handshake active.' },
      { control_id: 'COMP-MODE-01', title: 'Encapsulation Mode', status: 'PASS', observed_value: 'Tunnel Mode', expected_standard: 'Tunnel Mode (Site-to-Site)', rationale: 'Inner IP headers completely masked.' },
    ],
  },
  weak: {
    capture_id: 'weak_capture',
    filename: 'weak_capture.pcap',
    file_size_bytes: 38910,
    ipsec_detected: true,
    ike_detected: true,
    esp_detected: true,
    ike_version: 'IKEv1',
    encryption: 'AES-128-CBC',
    encryption_key_length: 128,
    authentication: 'MD5',
    dh_group: 5,
    dh_group_name: 'modp1536',
    pfs: false,
    initiator_spi: '0x3a4b5c6d7e8f9012',
    responder_spi: '0x9876543210fedcba',
    total_packets: 142,
    ike_packets: 8,
    esp_packets: 134,
    security_assessment: {
      risk_score: 72,
      severity: 'MEDIUM',
      findings: [
        {
          id: 'VPN-002',
          title: 'Legacy Non-AEAD Cipher Mode (AES-128-CBC)',
          severity: 'MEDIUM',
          category: 'Cryptography',
          description: 'The tunnel negotiates CBC mode rather than AEAD. CBC requires separate integrity checks and is historically prone to padding oracle attacks.',
          evidence: { cipher: 'AES-128-CBC', aead: false },
          impact: 'Integrity verification failures may reveal plaintext byte patterns under active probing.',
          recommendation: 'Migrate to AES-256-GCM or AES-128-GCM (NIST SP 800-77 Section 4.2).',
          confidence: 1.0,
          source: 'Observed from IKE transform proposals',
          references: ['NIST SP 800-77 Section 4.2', 'RFC 8221 Section 3'],
        },
        {
          id: 'VPN-003',
          title: 'Sub-2048 Bit Diffie-Hellman Group (Group 5)',
          severity: 'HIGH',
          category: 'Key Exchange',
          description: 'Group 5 (1536-bit MODP) provides insufficient security margin against state-level precomputation attacks.',
          evidence: { dh_group: 5, modulus_bits: 1536 },
          impact: 'Vulnerable to Logjam-style discrete logarithm precomputation.',
          recommendation: 'Upgrade to Group 19 (ecp256) or Group 14 (modp2048).',
          confidence: 1.0,
          source: 'Observed from IKE_SA_INIT exchange',
          references: ['RFC 8247 Section 2.4', 'NIST SP 800-131A'],
        },
        {
          id: 'VPN-004',
          title: 'Perfect Forward Secrecy (PFS) Disabled',
          severity: 'MEDIUM',
          category: 'Key Management',
          description: 'Child SA keys are derived directly from the IKE SA master key without independent Diffie-Hellman renegotiation.',
          evidence: { pfs: false },
          impact: 'Compromise of the master key allows retroactive decryption of all recorded sessions.',
          recommendation: 'Enable PFS for all Phase 2 Child SA proposals.',
          confidence: 1.0,
          source: 'Observed from CREATE_CHILD_SA configuration',
          references: ['NIST SP 800-77 Section 4.4'],
        },
      ],
      recommendations: [
        {
          id: 'REC-001',
          priority: 'HIGH',
          title: 'Upgrade Diffie-Hellman Group',
          action: 'Deprecate Group 5 and mandate Group 19 (ecp256) across all peer gateways.',
          target_parameter: 'DH Group',
          rationale: 'Sub-2048 bit groups are disallowed by NIST SP 800-131A.',
        },
        {
          id: 'REC-002',
          priority: 'MEDIUM',
          title: 'Transition to AEAD Ciphers',
          action: 'Replace AES-128-CBC proposals with AES-256-GCM.',
          target_parameter: 'Encryption',
          rationale: 'Eliminates padding oracle attack vectors and improves throughput.',
        },
      ],
      sub_scores: {
        crypto_risk: 25,
        key_exchange_risk: 30,
        configuration_risk: 17,
        metadata_exposure_risk: 0,
      },
      observed_configuration: {
        vpn_mode: 'Tunnel',
        encryption: 'AES-128-CBC',
        dh_group: 5,
        pfs: false,
        ike_version: 'IKEv1',
      },
    },
    traffic_analysis: {
      traffic_type: 'Bulk/Data Transfer',
      confidence: 0.94,
      model_used: 'RandomForest',
      packet_count: 134,
      flow_duration_sec: 9.41,
      mean_packet_size: 1140.2,
      std_packet_size: 180.6,
      min_packet_size: 64,
      max_packet_size: 1420,
      mean_iat_ms: 12.3,
      burst_count: 18,
      probabilities: { Bulk: 0.94, Web: 0.04, Video: 0.02, VoIP: 0.0, ICMP: 0.0 },
    },
    compliance: [
      { control_id: 'COMP-ENC-01', title: 'Symmetric Encryption Suite', status: 'WARNING', observed_value: 'AES-128-CBC', expected_standard: 'AES-256-GCM / AES-128-GCM (AEAD)', rationale: 'CBC mode requires separate HMAC integrity.' },
      { control_id: 'COMP-DH-01', title: 'Diffie-Hellman Key Exchange Group', status: 'FAIL', observed_value: 'Group 5 (modp1536)', expected_standard: 'Group 19 or Group 14', rationale: 'Sub-2048 bit MODP groups are deprecated.' },
      { control_id: 'COMP-PFS-01', title: 'Perfect Forward Secrecy (PFS)', status: 'WARNING', observed_value: 'Disabled', expected_standard: 'Enabled for all Child SAs', rationale: 'Single master key compromise cascades to past sessions.' },
      { control_id: 'COMP-IKE-01', title: 'IKE Protocol Version', status: 'FAIL', observed_value: 'IKEv1 (Legacy)', expected_standard: 'IKEv2', rationale: 'IKEv1 is deprecated under NIST SP 800-77 Section 4.4.' },
    ],
  },
};
