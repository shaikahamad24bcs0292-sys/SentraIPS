"""
Backend REST API for SentraIPS.
Provides analysis endpoints (POST /analyze-pcap, POST /evaluate-security), capture listings, and dataset management.
"""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.parser import IPsecPCAPParser, PCAPParseResult
from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures
from dataset.builder import DatasetBuilder
from security_engine import SecurityEngine, SecurityAssessmentReport
from models.ensemble import ESPEnsembleClassifier, EnsemblePredictionResult
from models import predict_traffic, TrafficAnalysisSummary, TrafficPredictionOutput
from reporting import ReportGenerator, SecurityAssessmentReportUnified

app = FastAPI(
    title="SentraIPS API",
    description="AI-Driven IPsec VPN Security Assessment Platform API (Smart India Hackathon 2026)",
    version="0.5.0",
)

# Enable CORS for local dashboards and frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = PROJECT_ROOT / "dataset" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
security_engine = SecurityEngine()
ensemble_classifier = ESPEnsembleClassifier()
report_generator = ReportGenerator()


class PCAPAnalysisResponse(BaseModel):
    capture_id: str
    filename: str
    file_size_bytes: int
    ipsec_detected: bool
    ike_detected: bool
    esp_detected: bool
    ah_detected: bool = False
    ike_version: str
    encryption: str
    encryption_key_length: Optional[int] = None
    authentication: str
    dh_group: Optional[Union[int, str]] = None
    dh_group_name: str
    pfs: Union[bool, str]
    initiator_spi: str
    responder_spi: str
    total_packets: int
    ike_packets: int
    esp_packets: int
    ah_packets: int = 0
    non_ipsec_packets: int = 0
    protocols_detected: List[str]
    features_extracted: bool
    esp_features: Optional[ESPTrafficFeatures] = None
    security_assessment: Optional[SecurityAssessmentReport] = None
    traffic_inference: Optional[EnsemblePredictionResult] = None
    traffic_analysis: Optional[TrafficAnalysisSummary] = None
    ground_truth: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)


@app.get("/health", tags=["Health"])
def health_check():
    """Returns system status and Phase roadmap health."""
    return {
        "status": "healthy",
        "service": "SentraIPS Backend API",
        "phase": "Phase 4 (ESP AI Ensemble + Uncertainty Traffic Inference)",
        "ai_models_loaded": True,
        "project_root": str(PROJECT_ROOT),
    }


@app.post("/analyze-pcap", response_model=PCAPAnalysisResponse, tags=["Analysis"])
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Accepts .pcap / .pcapng file upload, validates magic bytes,
    parses IKE/ESP protocol parameters, extracts ESP traffic metadata features,
    executes deterministic security rules, and returns structured analysis JSON.
    """
    filename = file.filename or "upload.pcap"
    allowed_extensions = {".pcap", ".pcapng", ".cap"}
    ext = Path(filename).suffix.lower()

    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported.",
        )

    # Save to temporary file for analysis
    temp_path = UPLOAD_DIR / f"temp_{os.getpid()}_{filename}"
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Validate file
        is_valid, validation_errors = IPsecPCAPParser.validate_file(temp_path)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File validation failed: {'; '.join(validation_errors)}",
            )

        cid = Path(filename).stem
        # Dissect packets
        parsed = IPsecPCAPParser.parse_pcap(temp_path, capture_id=cid)

        # Extract ESP features if ESP packets exist
        esp_features = None
        features_extracted = False
        traffic_inference = None
        traffic_analysis = None
        if parsed.esp_packets > 0:
            esp_features = ESPFeatureExtractor.extract_from_pcap(temp_path)
            features_extracted = True
            traffic_inference = ensemble_classifier.predict_features(esp_features)
            traffic_pred = predict_traffic(esp_features)
            traffic_analysis = TrafficAnalysisSummary(
                classification=traffic_pred.get("traffic_class", "Unknown"),
                confidence=traffic_pred.get("confidence", 0.0),
                model=traffic_pred.get("model", "RandomForest"),
            )
        else:
            traffic_analysis = TrafficAnalysisSummary(
                classification="Unknown",
                confidence=0.0,
                model="RandomForest",
            )

        # Run deterministic security assessment
        sec_report = security_engine.assess_parsed_pcap(parsed, esp_features)

        # Construct structured response
        response = PCAPAnalysisResponse(
            capture_id=parsed.capture_id,
            filename=filename,
            file_size_bytes=parsed.file_size_bytes,
            ipsec_detected=parsed.ipsec_detected,
            ike_detected=parsed.ike_detected,
            esp_detected=parsed.esp_detected,
            ah_detected=parsed.ah_detected,
            ike_version=parsed.ike.version,
            encryption=parsed.ike.encryption,
            encryption_key_length=parsed.ike.encryption_key_length,
            authentication=parsed.ike.authentication,
            dh_group=parsed.ike.dh_group,
            dh_group_name=parsed.ike.dh_group_name,
            pfs=parsed.ike.pfs,
            initiator_spi=parsed.ike.initiator_spi,
            responder_spi=parsed.ike.responder_spi,
            total_packets=parsed.total_packets,
            ike_packets=parsed.ike_packets,
            esp_packets=parsed.esp_packets,
            ah_packets=parsed.ah_packets,
            non_ipsec_packets=parsed.non_ipsec_packets,
            protocols_detected=parsed.protocols_detected,
            features_extracted=features_extracted,
            esp_features=esp_features,
            security_assessment=sec_report,
            traffic_inference=traffic_inference,
            traffic_analysis=traffic_analysis,
            ground_truth=parsed.ground_truth,
            errors=parsed.errors,
        )
        return response

    finally:
        # Clean up temporary uploaded file
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@app.post("/evaluate-security", response_model=SecurityAssessmentReport, tags=["Security Engine"])
async def evaluate_security(file: UploadFile = File(...)):
    """
    Direct security evaluation endpoint: Accepts a PCAP file and returns the
    complete deterministic SecurityAssessmentReport with threat matrix, risk score, and evidence chain.
    """
    filename = file.filename or "upload.pcap"
    allowed_extensions = {".pcap", ".pcapng", ".cap"}
    ext = Path(filename).suffix.lower()

    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported.",
        )

    temp_path = UPLOAD_DIR / f"sec_eval_{os.getpid()}_{filename}"
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        is_valid, validation_errors = IPsecPCAPParser.validate_file(temp_path)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File validation failed: {'; '.join(validation_errors)}",
            )

        report = security_engine.assess_pcap_file(temp_path)
        return report
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@app.post("/security-assessment", response_model=SecurityAssessmentReport, tags=["Security Engine"])
async def security_assessment(
    request: Request,
    file: Optional[UploadFile] = File(None),
):
    """
    Phase 3 Security Assessment Endpoint:
    Accepts either:
    1. A PCAP file upload (multipart/form-data) for end-to-end parsing and deterministic assessment.
    2. A JSON configuration payload (application/json) containing extracted VPN configuration parameters.

    Returns structured Phase 3 security assessment:
    - configuration: Extracted parameters with OBSERVED / INFERRED / UNKNOWN provenance
    - findings: Deterministic findings with evidence, impact, and recommendation
    - risk_score: Transparent 0-100 score
    - severity: Qualitative rating (LOW, LOW-MEDIUM, MEDIUM, HIGH, CRITICAL)
    - score_breakdown: Itemized points contribution
    - recommendations: Prioritized remedial actions (CRITICAL, HIGH, MEDIUM, LOW)
    - limitations: Disclaimers regarding payload confidentiality and unobserved parameters
    """
    content_type = request.headers.get("content-type", "")

    # 1. Handle file upload (PCAP)
    if "multipart/form-data" in content_type and file is not None and file.filename:
        filename = file.filename
        allowed_extensions = {".pcap", ".pcapng", ".cap"}
        ext = Path(filename).suffix.lower()

        if ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported.",
            )

        temp_path = UPLOAD_DIR / f"sec_assess_{os.getpid()}_{filename}"
        try:
            with open(temp_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            is_valid, validation_errors = IPsecPCAPParser.validate_file(temp_path)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File validation failed: {'; '.join(validation_errors)}",
                )

            report = security_engine.assess_pcap_file(temp_path)
            return report
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    # 2. Handle JSON configuration payload
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request. Provide either a PCAP file upload (multipart/form-data) or a JSON configuration payload.",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configuration payload must be a JSON object.",
        )

    report = security_engine.assess_configuration(body)
    return report


@app.post("/infer-traffic", response_model=EnsemblePredictionResult, tags=["AI Inference"])
async def infer_traffic(file: UploadFile = File(...)):
    """
    ESP AI Traffic Inference endpoint: Accepts PCAP upload, extracts encrypted ESP
    traffic metadata features, and executes dual-model ensemble (1D-CNN + Random Forest)
    with explicit uncertainty arbitration.
    """
    filename = file.filename or "upload.pcap"
    allowed_extensions = {".pcap", ".pcapng", ".cap"}
    ext = Path(filename).suffix.lower()

    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported.",
        )

    temp_path = UPLOAD_DIR / f"infer_{os.getpid()}_{filename}"
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        is_valid, validation_errors = IPsecPCAPParser.validate_file(temp_path)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File validation failed: {'; '.join(validation_errors)}",
            )

        prediction = ensemble_classifier.predict_pcap(temp_path)
        return prediction
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@app.post("/predict-traffic", response_model=TrafficPredictionOutput, tags=["AI Inference"])
async def predict_traffic_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(None),
):
    """
    Phase 4 AI Traffic Classification Endpoint:
    Infers application traffic classification (Web, Video, VoIP, ICMP, Bulk/Data Transfer, Unknown)
    strictly from encrypted ESP metadata/features without decrypting payloads.

    Accepts either:
    1. A PCAP file upload (multipart/form-data).
    2. A JSON payload (application/json) containing extracted ESP features.
    """
    content_type = request.headers.get("content-type", "")

    # 1. PCAP file upload
    if "multipart/form-data" in content_type and file is not None and file.filename:
        filename = file.filename
        allowed_extensions = {".pcap", ".pcapng", ".cap"}
        ext = Path(filename).suffix.lower()

        if ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported.",
            )

        temp_path = UPLOAD_DIR / f"traffic_pred_{os.getpid()}_{filename}"
        try:
            with open(temp_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            is_valid, validation_errors = IPsecPCAPParser.validate_file(temp_path)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File validation failed: {'; '.join(validation_errors)}",
                )

            features = ESPFeatureExtractor.extract_from_pcap(temp_path)
            if features.total_packets == 0:
                return TrafficPredictionOutput(
                    traffic_class="Unknown",
                    confidence=0.0,
                    model="RandomForest",
                    probabilities={},
                )

            pred = predict_traffic(features)
            return TrafficPredictionOutput(
                traffic_class=pred["traffic_class"],
                confidence=pred["confidence"],
                model=pred["model"],
                probabilities=pred.get("probabilities", {}),
            )
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    # 2. JSON feature payload
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request. Provide either a PCAP file upload (multipart/form-data) or a JSON features payload.",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Features payload must be a JSON object.",
        )

    pred = predict_traffic(body)
    return TrafficPredictionOutput(
        traffic_class=pred["traffic_class"],
        confidence=pred["confidence"],
        model=pred["model"],
        probabilities=pred.get("probabilities", {}),
    )


# =============================================================================
# Phase 5: Automated Security Reporting Endpoints
# =============================================================================

@app.post("/reports/generate", response_model=SecurityAssessmentReportUnified, tags=["Reporting"])
async def generate_report_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(None),
):
    """
    Phase 5 Report Generation Endpoint:
    Accepts PCAP upload (multipart/form-data) or JSON configuration,
    executes full security, ML, and compliance evaluation,
    saves both JSON and standalone HTML reports to disk, and returns structured JSON audit.
    """
    content_type = request.headers.get("content-type", "")

    # 1. PCAP file upload
    if "multipart/form-data" in content_type and file is not None and file.filename:
        filename = file.filename
        allowed_extensions = {".pcap", ".pcapng", ".cap"}
        ext = Path(filename).suffix.lower()

        if ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported.",
            )

        temp_path = UPLOAD_DIR / f"report_{os.getpid()}_{filename}"
        try:
            with open(temp_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            is_valid, validation_errors = IPsecPCAPParser.validate_file(temp_path)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File validation failed: {'; '.join(validation_errors)}",
                )

            report = report_generator.generate_report_from_pcap(temp_path)
            report_generator.save_reports(report)
            return report
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    # 2. JSON configuration body fallback
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request. Provide either a PCAP file upload (multipart/form-data) or a JSON payload.",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a JSON object.",
        )

    # If body specifies an existing capture_id or pcap path
    pcap_ref = body.get("pcap_path") or body.get("capture_id")
    if pcap_ref:
        candidate = Path(pcap_ref)
        if not candidate.exists():
            candidate = PROJECT_ROOT / "demo_data" / f"{pcap_ref}.pcap"
        if not candidate.exists():
            candidate = PROJECT_ROOT / "dataset" / "raw" / f"{pcap_ref}.pcap"

        if candidate.exists():
            report = report_generator.generate_report_from_pcap(candidate)
            report_generator.save_reports(report)
            return report

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unable to generate report: provide a valid PCAP file upload or capture_id reference.",
    )


@app.get("/reports/{report_id}", response_model=SecurityAssessmentReportUnified, tags=["Reporting"])
def get_report_json_endpoint(report_id: str):
    """Retrieves machine-readable JSON security assessment report by ID."""
    reports_dir = PROJECT_ROOT / "reports"
    json_path = reports_dir / f"{report_id}.json"
    if not json_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@app.get("/reports/{report_id}/html", response_class=HTMLResponse, tags=["Reporting"])
def get_report_html_endpoint(report_id: str):
    """Serves publication-grade standalone HTML audit report directly to browser."""
    reports_dir = PROJECT_ROOT / "reports"
    html_path = reports_dir / f"{report_id}.html"
    if not html_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HTML report for '{report_id}' not found.",
        )

    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/reports", tags=["Reporting"])
def list_reports_endpoint():
    """Lists all generated assessment reports available on disk."""
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_files = sorted(reports_dir.glob("*.json"), key=os.path.getmtime, reverse=True)

    items = []
    for f in report_files:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            items.append({
                "report_id": data.get("report_id", f.stem),
                "timestamp": data.get("timestamp"),
                "risk_score": data.get("summary", {}).get("overall_risk_score"),
                "severity": data.get("summary", {}).get("severity"),
                "traffic_type": data.get("summary", {}).get("traffic_classification"),
                "json_url": f"/reports/{f.stem}",
                "html_url": f"/reports/{f.stem}/html",
            })
        except Exception:
            items.append({"report_id": f.stem, "json_url": f"/reports/{f.stem}"})

    return {"total_reports": len(items), "reports": items}


@app.get("/captures", tags=["Dataset"])
def list_captures():
    """Lists available captures registered in dataset/labels.csv and dataset/raw/."""
    labels_path = PROJECT_ROOT / "dataset" / "labels.csv"
    if labels_path.exists():
        import pandas as pd
        df = pd.read_csv(labels_path)
        records = df.where(pd.notnull(df), None).to_dict(orient="records")
        return {"total_captures": len(records), "captures": records}

    raw_dir = PROJECT_ROOT / "dataset" / "raw"
    files = [f.stem for f in raw_dir.glob("*.pcap")] if raw_dir.exists() else []
    return {"total_captures": len(files), "captures": files}


@app.get("/captures/{capture_id}", tags=["Dataset"])
def get_capture(capture_id: str):
    """Retrieves parsed summary, extracted features, and security report for a specific capture."""
    processed_file = PROJECT_ROOT / "dataset" / "processed" / f"{capture_id}_features.json"
    raw_pcap = PROJECT_ROOT / "dataset" / "raw" / f"{capture_id}.pcap"
    if not raw_pcap.exists():
        raw_pcap = PROJECT_ROOT / "demo_data" / f"{capture_id}.pcap"

    if not raw_pcap.exists() and not processed_file.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Capture '{capture_id}' not found.")

    if raw_pcap.exists():
        parsed = IPsecPCAPParser.parse_pcap(raw_pcap, capture_id=capture_id)
        features = None
        if parsed.esp_packets > 0:
            features = ESPFeatureExtractor.extract_from_pcap(raw_pcap)
        sec_report = security_engine.assess_parsed_pcap(parsed, features)
        return {
            "capture_id": capture_id,
            "summary": parsed.model_dump(),
            "features": features.model_dump() if features else None,
            "security_assessment": sec_report.model_dump(),
        }

    with open(processed_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@app.post("/dataset/rebuild", tags=["Dataset"])
def rebuild_dataset():
    """Triggers dataset synchronization, feature extraction, and labels.csv generation."""
    builder = DatasetBuilder(PROJECT_ROOT)
    result = builder.build_dataset()
    return result
