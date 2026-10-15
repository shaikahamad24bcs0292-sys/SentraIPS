"""
HTML Report Generation Engine for SentraIPS (Phase 5).
Produces professional, standalone, self-contained HTML security assessment audits
with zero external dependencies (works completely offline).
"""

import html
from pathlib import Path
from typing import Union
from reporting.report_schema import SecurityAssessmentReportUnified


class HTMLReportGenerator:
    """
    Renders SecurityAssessmentReportUnified into publication-ready, self-contained HTML.
    """

    @staticmethod
    def _escape(text: str) -> str:
        return html.escape(str(text)) if text is not None else ""

    @staticmethod
    def _get_severity_color(sev: str) -> str:
        s = str(sev).upper()
        if "CRIT" in s:
            return "#DC2626", "#FEE2E2"
        if "HIGH" in s:
            return "#EA580C", "#FFEDD5"
        if "MED" in s:
            return "#D97706", "#FEF3C7"
        if "LOW" in s or "SECURE" in s or "PASS" in s:
            return "#16A34A", "#DCFCE7"
        return "#4F46E5", "#EEF2FF"

    @classmethod
    def generate(cls, report: SecurityAssessmentReportUnified) -> str:
        """Renders report data into standalone HTML markup."""
        s = report.summary
        cfg = report.vpn_configuration
        ta = report.traffic_analysis
        comp = report.compliance

        # Risk score badge color
        risk_color, risk_bg = cls._get_severity_color(s.severity)

        # Build Compliance Rows
        compliance_rows = []
        for c in comp:
            status_color, status_bg = cls._get_severity_color(c.status)
            refs_html = ""
            if c.references:
                ref_items = []
                for r in c.references:
                    if isinstance(r, dict):
                        src = r.get("source", "")
                        gd = r.get("guidance", "")
                        ref_items.append(f"<strong>{cls._escape(src)}</strong>: {cls._escape(gd)}" if gd else f"<strong>{cls._escape(src)}</strong>")
                    else:
                        ref_items.append(f"<strong>{cls._escape(str(r))}</strong>")
                refs_html = f"<div class='ref-snippet'>{'<br>'.join(ref_items)}</div>"

            row = f"""
            <tr>
              <td><code>{cls._escape(c.control_id)}</code></td>
              <td><strong>{cls._escape(c.title)}</strong><div class='subtext'>{cls._escape(c.category)}</div></td>
              <td><span class='badge' style='background:{status_bg}; color:{status_color};'>{cls._escape(c.status)}</span></td>
              <td><code>{cls._escape(c.observed_value)}</code></td>
              <td>{cls._escape(c.expected_standard)}</td>
              <td>{cls._escape(c.rationale)}{refs_html}</td>
            </tr>
            """
            compliance_rows.append(row)

        # Build Findings Cards
        findings_cards = []
        if not report.findings:
            findings_cards.append("<div class='card success-box'><strong>No Security Vulnerabilities Detected:</strong> The observed configuration complies with modern cryptographic guidelines.</div>")
        else:
            for f in report.findings:
                f_color, f_bg = cls._get_severity_color(f.severity)
                if isinstance(f.evidence, dict):
                    ev_str = "<br>".join([f"<strong>{cls._escape(k)}</strong>: {cls._escape(str(v))}" for k, v in f.evidence.items()]) if f.evidence else "None"
                else:
                    ev_str = cls._escape(str(f.evidence)) if f.evidence else "None"
                
                refs_html = ""
                if f.references:
                    ref_items = []
                    for r in f.references:
                        if isinstance(r, dict):
                            src = r.get("source", "")
                            sec = f" ({cls._escape(r.get('section', ''))})" if r.get("section") else ""
                            gd = f": {cls._escape(r.get('guidance', ''))}" if r.get("guidance") else ""
                            ref_items.append(f"<li><strong>{cls._escape(src)}</strong>{sec}{gd}</li>")
                        else:
                            ref_items.append(f"<li><strong>{cls._escape(str(r))}</strong></li>")
                    refs_html = f"<div class='refs-box'><strong>Authoritative Standards Citations:</strong><ul>{''.join(ref_items)}</ul></div>"

                card = f"""
                <div class='finding-card'>
                  <div class='finding-header'>
                    <div>
                      <span class='finding-id'>{cls._escape(f.id)}</span>
                      <span class='finding-title'>{cls._escape(f.title)}</span>
                    </div>
                    <span class='badge' style='background:{f_bg}; color:{f_color}; font-weight:700;'>{cls._escape(f.severity)}</span>
                  </div>
                  <p class='finding-desc'>{cls._escape(f.description)}</p>
                  
                  <div class='finding-grid'>
                    <div class='finding-item'>
                      <strong>Evidence Observed</strong>
                      <div class='snippet'>{ev_str}</div>
                    </div>
                    <div class='finding-item'>
                      <strong>Threat & Impact</strong>
                      <div class='impact-text'>{cls._escape(f.impact)}</div>
                    </div>
                  </div>

                  <div class='recommendation-box'>
                    <strong>Remediation:</strong> {cls._escape(f.recommendation)}
                  </div>
                  {refs_html}
                </div>
                """
                findings_cards.append(card)

        # Build Recommendations Rows
        rec_rows = []
        for r in report.recommendations:
            r_color, r_bg = cls._get_severity_color(r.priority)
            rec_rows.append(f"""
            <tr>
              <td><span class='badge' style='background:{r_bg}; color:{r_color}; font-weight:700;'>{cls._escape(r.priority)}</span></td>
              <td><strong>{cls._escape(r.title)}</strong></td>
              <td>{cls._escape(r.action)}</td>
              <td><code>{cls._escape(r.target_parameter)}</code></td>
            </tr>
            """)

        # Probability distribution bars
        prob_bars = []
        if ta.probabilities:
            for cls_name, p_val in sorted(ta.probabilities.items(), key=lambda x: x[1], reverse=True):
                pct = round(p_val * 100, 1)
                prob_bars.append(f"""
                <div class='prob-row'>
                  <span class='prob-label'>{cls._escape(cls_name)}</span>
                  <div class='prob-bar-track'><div class='prob-bar-fill' style='width: {pct}%;'></div></div>
                  <span class='prob-val'>{pct}%</span>
                </div>
                """)

        # Build Limitations
        lim_items = "".join([f"<li>{cls._escape(lim)}</li>" for lim in report.limitations])

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentraIPS Security Assessment Report - {cls._escape(report.report_id)}</title>
  <style>
    :root {{
      --primary: #1E293B;
      --secondary: #3B82F6;
      --accent: #0EA5E9;
      --bg: #F8FAFC;
      --card-bg: #FFFFFF;
      --text: #0F172A;
      --muted: #64748B;
      --border: #E2E8F0;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 30px 20px;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .header {{
      background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
      color: #FFFFFF;
      padding: 32px 40px;
      border-radius: 12px;
      margin-bottom: 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 20px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    .header h1 {{ font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }}
    .header .subtitle {{ color: #94A3B8; font-size: 14px; margin-top: 4px; }}
    .header-meta {{ text-align: right; font-size: 13px; color: #CBD5E1; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 20px;
      margin-bottom: 28px;
    }}
    .card {{
      background: var(--card-bg);
      border-radius: 10px;
      padding: 24px;
      border: 1px solid var(--border);
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .metric-title {{ font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
    .metric-value {{ font-size: 32px; font-weight: 800; margin: 8px 0; }}
    .metric-sub {{ font-size: 13px; color: var(--muted); }}
    .section-title {{
      font-size: 20px;
      font-weight: 700;
      margin: 32px 0 16px 0;
      color: var(--primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
      font-size: 14px;
      background: var(--card-bg);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    th {{
      background-color: #F1F5F9;
      color: var(--primary);
      text-align: left;
      padding: 12px 16px;
      font-weight: 600;
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background-color: #F8FAFC; }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: #F1F5F9;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 13px;
      color: #0F172A;
    }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 18px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      border-bottom: 1px solid #F1F5F9;
      padding-bottom: 10px;
    }}
    .finding-id {{ font-size: 13px; font-weight: 700; color: #4F46E5; background: #EEF2FF; padding: 2px 8px; border-radius: 4px; margin-right: 8px; }}
    .finding-title {{ font-size: 16px; font-weight: 700; color: var(--primary); }}
    .finding-desc {{ font-size: 14px; color: #334155; margin-bottom: 16px; }}
    .finding-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 16px;
    }}
    .snippet {{
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 13px;
      font-family: monospace;
      margin-top: 6px;
    }}
    .impact-text {{ font-size: 13px; color: #475569; margin-top: 6px; }}
    .recommendation-box {{
      background: #ECFDF5;
      border-left: 4px solid #10B981;
      padding: 12px 16px;
      border-radius: 4px;
      font-size: 14px;
      color: #065F46;
    }}
    .refs-box {{
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      border-radius: 6px;
      padding: 12px 16px;
      margin-top: 14px;
      font-size: 13px;
      color: #334155;
    }}
    .refs-box ul {{ padding-left: 18px; margin-top: 6px; }}
    .ref-snippet {{ font-size: 12px; color: #475569; margin-top: 4px; }}
    .prob-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; font-size: 13px; }}
    .prob-label {{ width: 140px; font-weight: 600; color: #334155; }}
    .prob-bar-track {{ flex: 1; height: 12px; background: #E2E8F0; border-radius: 6px; overflow: hidden; }}
    .prob-bar-fill {{ height: 100%; background: #3B82F6; border-radius: 6px; }}
    .prob-val {{ width: 50px; text-align: right; color: #64748B; }}
    .limitations-box {{
      background: #FEF3C7;
      border-left: 4px solid #F59E0B;
      padding: 18px 24px;
      border-radius: 8px;
      color: #92400E;
      font-size: 14px;
    }}
    .limitations-box ul {{ padding-left: 20px; margin-top: 8px; }}
    .success-box {{ background: #DCFCE7; color: #166534; padding: 18px; border-radius: 8px; }}
    .subtext {{ font-size: 12px; color: var(--muted); }}
    .footer {{
      margin-top: 40px;
      text-align: center;
      font-size: 13px;
      color: var(--muted);
      border-top: 1px solid var(--border);
      padding-top: 20px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <div>
        <h1>SentraIPS Security Assessment &amp; Compliance Audit Report</h1>
        <div class="subtitle">AI-Driven IPsec VPN Cryptographic & Compliance Evaluation Platform</div>
      </div>
      <div class="header-meta">
        <div><strong>Report ID:</strong> {cls._escape(report.report_id)}</div>
        <div><strong>Generated:</strong> {cls._escape(report.timestamp)}</div>
        <div style="margin-top: 4px;"><span class="badge" style="background:#334155; color:#F8FAFC;">CONFIDENTIAL AUDIT</span></div>
      </div>
    </div>

    <!-- Executive Summary Grid -->
    <div class="summary-grid">
      <div class="card">
        <div class="metric-title">Overall Risk Score</div>
        <div class="metric-value" style="color: {risk_color};">{s.overall_risk_score}<span style="font-size: 18px; font-weight: 500; color: #94A3B8;"> / 100</span></div>
        <div class="metric-sub"><span class="badge" style="background: {risk_bg}; color: {risk_color}; font-weight: 700;">{cls._escape(s.severity)}</span> Rating</div>
      </div>

      <div class="card">
        <div class="metric-title">Standards Compliance</div>
        <div class="metric-value" style="font-size: 24px; color: #1E293B;">{cls._escape(s.compliance_rating)}</div>
        <div class="metric-sub">{report.compliance_summary.get('passed', 0)} Pass &bull; {report.compliance_summary.get('warnings', 0)} Warnings &bull; {report.compliance_summary.get('failed', 0)} Fails</div>
      </div>

      <div class="card">
        <div class="metric-title">Encrypted Traffic Inference</div>
        <div class="metric-value" style="font-size: 26px; color: #2563EB;">{cls._escape(s.traffic_classification)}</div>
        <div class="metric-sub">Confidence: {round(s.traffic_confidence * 100, 1)}% via {cls._escape(ta.model)}</div>
      </div>

      <div class="card">
        <div class="metric-title">Cryptographic Baseline</div>
        <div style="margin: 8px 0; font-size: 14px;">
          <div><strong>IKE:</strong> {cls._escape(s.ike_version)}</div>
          <div><strong>Cipher:</strong> <code>{cls._escape(s.encryption)}</code></div>
          <div><strong>DH:</strong> {cls._escape(s.dh_group)} &bull; <strong>PFS:</strong> {cls._escape(s.pfs)}</div>
        </div>
      </div>
    </div>

    <!-- VPN Configuration Table -->
    <h2 class="section-title">1. Observed VPN Protocol Configuration</h2>
    <table>
      <thead>
        <tr>
          <th>Parameter</th>
          <th>Detected Value</th>
          <th>Observation Provenance</th>
          <th>Standard Baseline Recommendation</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>VPN Mode</strong></td>
          <td><code>{cls._escape(cfg.vpn_mode)}</code></td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">{cls._escape(cfg.observation_provenance.get('vpn_mode', 'OBSERVED'))}</span></td>
          <td>Tunnel Mode (Site-to-Site Gateways)</td>
        </tr>
        <tr>
          <td><strong>IKE Version</strong></td>
          <td><code>{cls._escape(cfg.ike_version)}</code></td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">{cls._escape(cfg.observation_provenance.get('ike_version', 'OBSERVED'))}</span></td>
          <td>IKEv2 (RFC 7296)</td>
        </tr>
        <tr>
          <td><strong>Symmetric Encryption</strong></td>
          <td><code>{cls._escape(cfg.encryption)}</code></td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">{cls._escape(cfg.observation_provenance.get('encryption', 'OBSERVED'))}</span></td>
          <td>AES-256-GCM / AES-128-GCM (AEAD)</td>
        </tr>
        <tr>
          <td><strong>Diffie-Hellman Group</strong></td>
          <td><code>{cls._escape(cfg.dh_group_name)} ({cls._escape(str(cfg.dh_group))})</code></td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">{cls._escape(cfg.observation_provenance.get('dh_group', 'OBSERVED'))}</span></td>
          <td>Group 19 (ecp256) or Group 14 (modp2048)</td>
        </tr>
        <tr>
          <td><strong>Perfect Forward Secrecy</strong></td>
          <td><code>{cls._escape(str(cfg.pfs))}</code></td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">{cls._escape(cfg.observation_provenance.get('pfs', 'OBSERVED'))}</span></td>
          <td>Enabled (True)</td>
        </tr>
        <tr>
          <td><strong>Authentication Suite</strong></td>
          <td><code>{cls._escape(cfg.authentication)}</code></td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">{cls._escape(cfg.observation_provenance.get('authentication', 'OBSERVED'))}</span></td>
          <td>SHA-256, SHA-384, or AEAD ICV</td>
        </tr>
        <tr>
          <td><strong>Packet Accounting</strong></td>
          <td>Total: {cfg.total_packets:,} (IKE: {cfg.ike_packets:,}, ESP: {cfg.esp_packets:,})</td>
          <td><span class="badge" style="background:#F1F5F9; color:#475569;">OBSERVED</span></td>
          <td>ESP > 0 for operational data payload</td>
        </tr>
      </tbody>
    </table>

    <!-- Traffic Analysis Section -->
    <h2 class="section-title">2. Encrypted ESP Traffic Metadata Classification</h2>
    <div class="card" style="margin-bottom: 24px;">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px;">
        <div><span class="subtext">Classified Profile:</span><div style="font-size: 20px; font-weight: 700; color: #2563EB;">{cls._escape(ta.traffic_type)}</div></div>
        <div><span class="subtext">Inference Confidence:</span><div style="font-size: 20px; font-weight: 700;">{round(ta.confidence * 100, 1)}%</div></div>
        <div><span class="subtext">Observed Flow Duration:</span><div style="font-size: 20px; font-weight: 700;">{round(ta.flow_duration_sec, 2)} s</div></div>
        <div><span class="subtext">Mean Packet Size:</span><div style="font-size: 20px; font-weight: 700;">{round(ta.mean_packet_size, 1)} B</div></div>
        <div><span class="subtext">Mean Inter-Arrival:</span><div style="font-size: 20px; font-weight: 700;">{round(ta.mean_iat_ms, 2)} ms</div></div>
        <div><span class="subtext">Flow Bursts:</span><div style="font-size: 20px; font-weight: 700;">{ta.burst_count}</div></div>
      </div>
      <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 10px; color: var(--muted); text-transform: uppercase;">Class Probability Distribution (Random Forest)</h3>
      {''.join(prob_bars)}
    </div>

    <!-- Security Findings Section -->
    <h2 class="section-title">3. Deterministic Security Findings & Threat Analysis</h2>
    {''.join(findings_cards)}

    <!-- Compliance Section -->
    <h2 class="section-title">4. Compliance & Best Practice Matrix (NIST & RFC Baseline)</h2>
    <table>
      <thead>
        <tr>
          <th>Control ID</th>
          <th>Control Title & Category</th>
          <th>Status</th>
          <th>Observed Value</th>
          <th>Standard Baseline</th>
          <th>Findings & Standards Citation</th>
        </tr>
      </thead>
      <tbody>
        {''.join(compliance_rows)}
      </tbody>
    </table>

    <!-- Recommendations Section -->
    <h2 class="section-title">5. Prioritized Remediation Roadmap</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 120px;">Priority</th>
          <th>Recommendation Title</th>
          <th>Remedial Action</th>
          <th>Target Parameter</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rec_rows) if rec_rows else "<tr><td colspan='4'>No remediation necessary; configuration complies with best practices.</td></tr>"}
      </tbody>
    </table>

    <!-- Limitations Section -->
    <h2 class="section-title">6. Audit Limitations & Security Boundaries</h2>
    <div class="limitations-box">
      <strong>Important Disclaimers & Cryptographic Isolation:</strong>
      <ul>
        {''.join(lim_items)}
      </ul>
    </div>

    <div class="footer">
      Generated automatically by <strong>SentraIPS</strong> &bull; Smart India Hackathon 2026 Prototype &bull; Zero Decryption Architecture
    </div>
  </div>
</body>
</html>"""
        return html_out

    @classmethod
    def save(
        cls,
        report: SecurityAssessmentReportUnified,
        output_path: Union[str, Path],
    ) -> Path:
        """Writes standalone HTML report to disk."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(report)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return target

    @classmethod
    def render_and_save(
        cls,
        report: SecurityAssessmentReportUnified,
        output_path: Union[str, Path],
    ) -> str:
        """Renders HTML report, writes to disk, and returns rendered content."""
        p = cls.save(report, output_path)
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

