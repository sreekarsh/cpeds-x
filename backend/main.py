"""
CPEDS-X: Cloud Privilege Escalation Detection System
FastAPI Application Entry Point

Auth (public):
  POST /api/v1/auth/signup           - create an account -> JWT
  POST /api/v1/auth/login            - sign in -> JWT
  GET  /api/v1/auth/me               - current user (Bearer token)
  POST /api/v1/auth/forgot-password  - issue a single-use reset token
  POST /api/v1/auth/reset-password   - set a new password with that token

Detection (require Bearer token):
  POST /api/v1/predict         - classify a raw audit log (+ SHAP + GenAI + auto-mitigate)
  POST /api/v1/explain         - SHAP top-5 feature importances
  POST /api/v1/mitigate        - trigger containment playbook
  GET  /api/v1/metrics         - model benchmark metrics
  POST /api/v1/simulate        - generate a synthetic audit log for a given class
  POST /api/v1/analyze         - batch-classify an uploaded log file (JSON/JSONL/CSV/CloudTrail)
  GET  /api/v1/analyze/sample  - a realistic mixed CloudTrail export for the upload demo
  GET  /api/v1/incidents       - the operator's saved detections (history)
  GET  /api/v1/incidents/{id}  - one saved incident
  DELETE /api/v1/incidents     - clear the operator's history
  GET  /api/v1/scenarios       - list purple-team attack scenarios
  POST /api/v1/scenario/run    - run a scenario step-by-step through the detector

Live AWS containment (real sandbox account, human-approved; require Bearer token):
  GET  /api/v1/live/status     - is live mode armed? which AWS identity?
  POST /api/v1/live/poll       - poll real CloudTrail -> classify -> stage pending
  POST /api/v1/live/contain    - execute an analyst-confirmed real IAM revoke
  POST /api/v1/live/undo       - reverse a live containment via its rollback token

Public:
  GET  /api/v1/health    - health/status ping
"""
# ------------------------------------------------------------------
# .env loader (dependency-free)
# Load backend/.env if present so local dev can set SUPABASE_URL /
# SUPABASE_KEY / JWT_SECRET_KEY without extra tooling. Must run BEFORE the
# auth imports below, because security.py reads JWT_SECRET_KEY at import time
# and database.py reads SUPABASE_* at first use.
# ------------------------------------------------------------------
def _load_dotenv() -> None:
    import os

    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except FileNotFoundError:
        pass


_load_dotenv()

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import json
import random
import threading
import time

from ml_engine.model import get_classifier, retrain_classifier, CLASS_LABELS
from ml_engine.shap_explainer import get_explainer
from ml_engine.genai_copilot import generate_soc_summary
from ml_engine.preprocessor import generate_synthetic_audit_log
from ml_engine.log_ingest import parse_logs, LogParseError
from playbooks.mitigation import execute_containment
import attack_scenarios
from ml_engine import live_watcher

from auth import database as auth_db
from auth.routes import router as auth_router
from auth.security import get_current_user

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------
app = FastAPI(
    title="CPEDS-X API",
    description="Cloud Privilege Escalation Detection System",
    version="1.0.0",
)

# CORS - allow frontend (Vercel / localhost) to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your Vercel domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication routes (signup / login / me / forgot- & reset-password)
app.include_router(auth_router)

# Confidence threshold gate for auto-mitigation
THRESHOLD = 0.75


# ------------------------------------------------------------------
# Pydantic schemas
# ------------------------------------------------------------------
class AuditLogRequest(BaseModel):
    audit_log: Dict = Field(..., description="Raw CloudTrail-style JSON event")


class ExplainRequest(BaseModel):
    scaled_features: List[float] = Field(..., description="Scaled 28-vector")
    predicted_class: int = Field(..., ge=0, le=4)


class MitigateRequest(BaseModel):
    principal: str = Field(..., description="IAM principal ARN or username")
    predicted_class: int = Field(..., ge=0, le=4)
    confidence: float = Field(..., ge=0.0, le=1.0)
    instance_id: Optional[str] = "i-0123456789abcdef0"


class SimulateRequest(BaseModel):
    threat_class: int = Field(0, ge=0, le=4)


class AnalyzeRequest(BaseModel):
    content: str = Field(..., description="Raw uploaded file text (JSON/JSONL/CSV)")
    format: str = Field("auto", description="auto | json | jsonl | csv")
    filename: Optional[str] = Field("", description="Original filename (for format hint)")


class ScenarioRunRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario id from GET /api/v1/scenarios")


class LivePollRequest(BaseModel):
    minutes: int = Field(60, ge=1, le=1440,
                         description="Look-back window for CloudTrail LookupEvents")


class LiveContainRequest(BaseModel):
    principal: str = Field(..., description="IAM principal ARN or username to contain")
    predicted_class: int = Field(..., ge=0, le=4)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    raw_log: Optional[Dict] = Field(None, description="The triggering CloudTrail event")


class LiveUndoRequest(BaseModel):
    incident_id: int = Field(..., description="Incident whose live containment to reverse")


class TrainReloadRequest(BaseModel):
    mode: str = Field("synthetic", description="synthetic | real")
    dataset_content: Optional[str] = Field(
        None, description="Raw labeled dataset text (JSON/JSONL/CSV) for real mode")
    dataset_filename: Optional[str] = Field(
        "", description="Original filename, for format auto-detection")
    label_key: Optional[str] = Field(
        None, description="Override the label column name (else label/threat_class/...)")


# Max events analyzed per upload (keeps a live demo snappy and responses light).
MAX_ANALYZE_ROWS = 1000

# Cap how many detections a single upload writes to history, so a large file
# can't flood the incident view. The live simulator and scenario runner are
# user-paced and always recorded in full.
MAX_INCIDENTS_PER_UPLOAD = 50

# Cap uploaded training datasets (raw text) — same 8 MB ceiling as /analyze.
MAX_DATASET_BYTES = 8 * 1024 * 1024

# Single-flight lock: retraining swaps the shared model singleton, so two
# concurrent retrains must never overlap. A second one gets HTTP 409.
_RETRAIN_LOCK = threading.Lock()


def _training_status(clf) -> Dict:
    """Provenance of what the model was last trained on (for /metrics, /health).

    Read-only view over the classifier's training_info; safe if fields are
    absent (older builds) — everything degrades to None/'synthetic'.
    """
    info = dict(getattr(clf, "training_info", {}) or {})
    dataset = None
    if info.get("dataset_rows_used") is not None:
        dataset = {
            "filename": info.get("dataset_filename"),
            "rows_used": info.get("dataset_rows_used"),
            "rows_total": info.get("dataset_rows_total"),
            "rows_skipped": info.get("dataset_rows_skipped"),
            "per_class": info.get("dataset_per_class"),
            "label_key": info.get("dataset_label_key"),
            "shape": info.get("dataset_shape"),
        }
    return {
        "effective_mode": getattr(clf, "effective_mode", "synthetic"),
        "requested_mode": getattr(clf, "training_mode", "synthetic"),
        "fallback_reason": getattr(clf, "fallback_reason", None),
        "train_rows": info.get("train_rows"),
        "test_rows": info.get("test_rows"),
        "dataset": dataset,
    }


# ------------------------------------------------------------------
# Startup: train model once
# ------------------------------------------------------------------
@app.on_event("startup")
def _startup():
    print("[CPEDS-X] Initializing user database...")
    auth_db.init_db()
    print("[CPEDS-X] Initializing threat classifier...")
    get_classifier()  # triggers training
    print("[CPEDS-X] Ready.")


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------
@app.get("/api/v1/health")
def health():
    clf = get_classifier()
    return {
        "status": "active",
        "service": "CPEDS-X",
        "model_trained": clf.is_trained,
        "training_mode": getattr(clf, "effective_mode", "synthetic"),
        "auth_backend": auth_db.active_backend(),
        "containment_mode": live_watcher.live_ready()["mode"],
    }


@app.post("/api/v1/predict")
def predict(req: AuditLogRequest, current_user: dict = Depends(get_current_user)):
    """
    Full detection pipeline: classify -> SHAP -> GenAI summary ->
    auto-mitigate if confidence >= threshold and class != C0.
    """
    clf = get_classifier()
    try:
        result = clf.predict(req.audit_log)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

    pred_class = result["predicted_class"]
    confidence = result["confidence"]

    # SHAP explanation
    explainer = get_explainer(clf.lgbm_model, clf.preprocessor.feature_names)
    shap_result = explainer.explain(result["scaled_features"], pred_class)

    # Auto-mitigation gate
    mitigation = None
    containment_time = None
    if confidence >= THRESHOLD and pred_class != 0:
        principal = req.audit_log.get("userIdentity", {}).get("arn", "unknown-principal")
        mitigation = execute_containment(principal, pred_class,
                                         req.audit_log.get("instance_id", "i-0123456789abcdef0"))
        containment_time = mitigation["mttc_seconds"]

    # GenAI co-pilot summary
    summary = generate_soc_summary(
        pred_class, result["class_label"], confidence,
        shap_result["top_features"], containment_time
    )

    # Record this detection in the operator's incident history.
    incident = _record_detection(
        current_user["id"], "live",
        req.audit_log, result,
        "CONTAINED" if (confidence >= THRESHOLD and pred_class != 0) else "MONITORED",
    )

    return {
        "incident_id": incident["id"] if incident else None,
        "prediction": {
            "predicted_class": pred_class,
            "class_label": result["class_label"],
            "confidence": confidence,
            "probabilities": result["probabilities"],
            "execution_latency_ms": result["execution_latency_ms"],
        },
        "xai": shap_result,
        "soc_summary": summary,
        "mitigation": mitigation,
        "threshold_exceeded": confidence >= THRESHOLD and pred_class != 0,
    }


@app.post("/api/v1/explain")
def explain(req: ExplainRequest, current_user: dict = Depends(get_current_user)):
    """Return SHAP top-5 feature importances for a scaled feature vector."""
    clf = get_classifier()
    explainer = get_explainer(clf.lgbm_model, clf.preprocessor.feature_names)
    try:
        return explainer.explain(req.scaled_features, req.predicted_class)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SHAP failed: {e}")


@app.post("/api/v1/mitigate")
def mitigate(req: MitigateRequest, current_user: dict = Depends(get_current_user)):
    """Manually trigger the containment playbook (gated on threshold)."""
    if req.confidence < THRESHOLD or req.predicted_class == 0:
        return {
            "containment_triggered": False,
            "reason": f"Confidence {req.confidence} below threshold {THRESHOLD} "
                      f"or class is benign (C0).",
        }
    return execute_containment(req.principal, req.predicted_class, req.instance_id)


@app.get("/api/v1/metrics")
def metrics(current_user: dict = Depends(get_current_user)):
    """
    Model evaluation metrics.

    'benchmark' = reference numbers from the CPEDS paper baseline.
    'measured'  = REAL accuracy from this session's training run (honest).
    """
    clf = get_classifier()
    return {
        "benchmark": {
            "lightgbm_accuracy": 0.970,
            "xgboost_accuracy": 0.931,
            "adaboost_accuracy": 0.884,
            "random_forest_accuracy": 0.862,
            "roc_auc": 0.990,
            "macro_f1": 0.962,
            "mttd_seconds": 1.8,
            "note": "Reference values from CPEDS paper baseline.",
        },
        "measured": clf.measured_metrics,
        "measured_note": (
            "Real held-out test-set metrics from this session's training run. "
            "Data is synthetic but classes are generated to overlap in feature "
            "space (attackers hide inside benign-looking API calls), so these "
            "numbers reflect genuine difficulty — cite these, not the benchmark."
        ),
        "training": _training_status(clf),
        "class_labels": CLASS_LABELS,
    }


@app.post("/api/v1/train/reload")
def train_reload(req: TrainReloadRequest,
                 current_user: dict = Depends(get_current_user)):
    """
    Retrain the model on a chosen data source and hot-swap it in.

    mode="synthetic" (default) retrains on the built-in synthetic generator —
    always succeeds, and is how you revert. mode="real" trains on an uploaded
    labeled dataset (dataset_content) or the server-configured dataset path; if
    the dataset is unusable the PREVIOUS model is kept and a 422 explains why.

    Guardrails: auth-gated like every detection endpoint; a single-flight lock
    rejects an overlapping retrain with 409; uploaded content is size-capped.
    This only rebuilds the in-memory model — it makes no AWS calls and never
    touches live containment.
    """
    mode = (req.mode or "synthetic").lower()
    if mode not in ("synthetic", "real"):
        raise HTTPException(status_code=422,
                            detail="mode must be 'synthetic' or 'real'.")

    content = req.dataset_content
    if mode == "real" and content is not None:
        if len(content.encode("utf-8")) > MAX_DATASET_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Dataset exceeds the {MAX_DATASET_BYTES // (1024 * 1024)} MB limit.")

    # Non-blocking: a second concurrent retrain is rejected rather than queued.
    if not _RETRAIN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409,
                            detail="A retrain is already in progress. Try again shortly.")
    try:
        label_keys = [req.label_key] if req.label_key else None
        clf = retrain_classifier(
            mode=mode,
            dataset_content=content,
            dataset_filename=req.dataset_filename or "",
            label_keys=label_keys,
        )
    except ValueError as e:
        # DatasetError (bad/too-small/unlabeled data) — old model left intact.
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retrain failed: {e}")
    finally:
        _RETRAIN_LOCK.release()

    return {
        "status": "retrained",
        "training": _training_status(clf),
        "measured": clf.measured_metrics,
    }


@app.post("/api/v1/simulate")
def simulate(req: SimulateRequest, current_user: dict = Depends(get_current_user)):
    """Generate a synthetic CloudTrail audit log for a given threat class."""
    return {"audit_log": generate_synthetic_audit_log(req.threat_class)}


def _principal_of(log: dict) -> str:
    ui = log.get("userIdentity", {}) if isinstance(log, dict) else {}
    return ui.get("arn") or ui.get("userName") or "unknown-principal"


def _safe_create_incident(user_id, incident: dict) -> Optional[dict]:
    """Persist an incident, swallowing storage errors.

    Used by the live-containment path: the destructive AWS call has already
    succeeded by the time we write history, so a storage hiccup must not turn a
    successful containment into a 500. Returns the stored row or None.
    """
    try:
        return auth_db.create_incident(user_id, incident)
    except Exception as e:  # pragma: no cover - storage-dependent
        print(f"[CPEDS-X][WARN] Could not persist live incident: {e}")
        return None


def _record_detection(user_id, source: str, log: dict, pred: dict,
                      action_status: str) -> Optional[dict]:
    """Persist one detection to the operator's incident history.

    Best-effort: a storage hiccup must never break the detection response, so
    any failure is logged and swallowed. Returns the stored row (with id), or
    None if it couldn't be saved.
    """
    try:
        return auth_db.create_incident(user_id, {
            "source": source,
            "event_name": log.get("eventName", "") if isinstance(log, dict) else "",
            "principal": _principal_of(log),
            "source_ip": log.get("sourceIPAddress", "") if isinstance(log, dict) else "",
            "predicted_class": pred["predicted_class"],
            "class_label": pred["class_label"],
            "confidence": pred["confidence"],
            "action_status": action_status,
            "raw_log": log,
        })
    except Exception as e:  # pragma: no cover - storage-dependent
        print(f"[CPEDS-X][WARN] Could not persist incident: {e}")
        return None


@app.post("/api/v1/analyze")
def analyze(req: AnalyzeRequest, current_user: dict = Depends(get_current_user)):
    """
    Batch-analyze an uploaded log file.

    Accepts real CloudTrail exports ({"Records":[...]}), JSON arrays, JSON Lines,
    or CSV. Every event is run through the SAME trained classifier as the live
    simulator, auto-containment is evaluated per row, and a summary is returned
    for the dashboard. Per-row SHAP is computed on demand (row click) to keep
    batch responses fast.
    """
    try:
        events = parse_logs(req.content, req.format, req.filename or "")
    except LogParseError as e:
        raise HTTPException(status_code=422, detail=str(e))

    total_received = len(events)
    truncated = total_received > MAX_ANALYZE_ROWS
    events = events[:MAX_ANALYZE_ROWS]

    clf = get_classifier()
    started = time.perf_counter()

    results: List[Dict] = []
    class_counts = {label: 0 for label in CLASS_LABELS.values()}
    contained = 0
    errors = 0
    confidence_sum = 0.0
    incidents_recorded = 0

    for idx, log in enumerate(events):
        try:
            pred = clf.predict(log)
        except Exception as e:
            errors += 1
            results.append({
                "row": idx + 1,
                "error": f"Could not analyze this event: {e}",
                "raw_log": log,
            })
            continue

        pred_class = pred["predicted_class"]
        confidence = pred["confidence"]
        auto_contained = confidence >= THRESHOLD and pred_class != 0
        if auto_contained:
            contained += 1
        class_counts[pred["class_label"]] = class_counts.get(pred["class_label"], 0) + 1
        confidence_sum += confidence

        # Persist detected threats (not benign) to history, capped so a large
        # upload can't flood the incident view.
        if pred_class != 0 and incidents_recorded < MAX_INCIDENTS_PER_UPLOAD:
            if _record_detection(
                current_user["id"], "upload", log, pred,
                "CONTAINED" if auto_contained else "MONITORED",
            ):
                incidents_recorded += 1

        results.append({
            "row": idx + 1,
            "timestamp": log.get("eventTime", ""),
            "event_name": log.get("eventName", ""),
            "principal": _principal_of(log),
            "source_ip": log.get("sourceIPAddress", ""),
            "predicted_class": pred_class,
            "class_label": pred["class_label"],
            "confidence": confidence,
            "probabilities": pred["probabilities"],
            "execution_latency_ms": pred["execution_latency_ms"],
            "action": "CONTAINED" if auto_contained else "MONITORED",
            "raw_log": log,
        })

    analyzed = len(events)
    threats = sum(
        c for label, c in class_counts.items() if not label.startswith("C0")
    )
    processing_ms = round((time.perf_counter() - started) * 1000, 1)
    avg_conf = round(confidence_sum / analyzed, 4) if analyzed else 0.0

    return {
        "summary": {
            "total_received": total_received,
            "analyzed": analyzed,
            "truncated": truncated,
            "max_rows": MAX_ANALYZE_ROWS,
            "threats_detected": threats,
            "benign": class_counts.get("C0: Benign", 0),
            "auto_contained": contained,
            "errors": errors,
            "avg_confidence": avg_conf,
            "processing_ms": processing_ms,
            "class_counts": class_counts,
            "incidents_recorded": incidents_recorded,
        },
        "results": results,
        "class_labels": CLASS_LABELS,
    }


@app.get("/api/v1/analyze/sample")
def analyze_sample(current_user: dict = Depends(get_current_user)):
    """
    Return a realistic mixed CloudTrail export (as raw text) for the upload demo.

    Shaped exactly like an AWS CloudTrail file ({"Records":[...]}) so reviewers
    see the product ingest a genuine-looking log, not a toy payload.
    """
    rng = random.Random()
    # A believable incident window: mostly benign with a few escalations woven in.
    class_plan = [0, 0, 0, 1, 0, 2, 0, 3, 0, 0, 4, 0, 2, 0, 0]
    rng.shuffle(class_plan)
    records = [generate_synthetic_audit_log(c) for c in class_plan]
    payload = {"Records": records}
    return {
        "filename": "cloudtrail_events_sample.json",
        "format": "json",
        "content": json.dumps(payload, indent=2),
        "event_count": len(records),
    }


# ------------------------------------------------------------------
# Incident history
# ------------------------------------------------------------------
@app.get("/api/v1/incidents")
def list_incidents(limit: int = 200, current_user: dict = Depends(get_current_user)):
    """Return the operator's saved detections, newest first."""
    limit = min(max(limit, 1), 500)
    incidents = auth_db.list_incidents(current_user["id"], limit)
    return {"incidents": incidents, "count": len(incidents)}


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: int, current_user: dict = Depends(get_current_user)):
    """Return one saved incident (scoped to the owning operator)."""
    incident = auth_db.get_incident(current_user["id"], incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"incident": incident}


@app.delete("/api/v1/incidents")
def clear_incidents(current_user: dict = Depends(get_current_user)):
    """Clear the operator's incident history."""
    removed = auth_db.clear_incidents(current_user["id"])
    return {"cleared": removed}


# ------------------------------------------------------------------
# Attack Scenario Runner (purple-team loop)
# ------------------------------------------------------------------
@app.get("/api/v1/scenarios")
def scenarios(current_user: dict = Depends(get_current_user)):
    """List the attack scenarios available to run."""
    return {"scenarios": attack_scenarios.list_scenarios()}


@app.post("/api/v1/scenario/run")
def scenario_run(req: ScenarioRunRequest,
                 current_user: dict = Depends(get_current_user)):
    """
    Execute one attack scenario step by step.

    Every step: build the CloudTrail event -> classify with the SAME model as
    the live simulator -> SHAP -> auto-contain if the gate fires -> persist to
    the operator's incident history. The verdict is always the model's real
    prediction; the step's intended threat class only seeds the event.
    """
    scenario = attack_scenarios.get_scenario(req.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Unknown scenario id.")

    clf = get_classifier()
    explainer = get_explainer(clf.lgbm_model, clf.preprocessor.feature_names)
    steps_out: List[Dict] = []
    threats = 0
    contained = 0
    started = time.perf_counter()

    for step in scenario["steps"]:
        event = attack_scenarios.build_step_event(
            step, scenario["attacker_principal"], scenario["source_ip"])
        pred = clf.predict(event)
        pred_class = pred["predicted_class"]
        confidence = pred["confidence"]

        # SHAP + co-pilot summary for the step.
        shap_result = explainer.explain(pred["scaled_features"], pred_class)
        mitigation = None
        if confidence >= THRESHOLD and pred_class != 0:
            mitigation = execute_containment(
                scenario["attacker_principal"], pred_class,
                event.get("instance_id", "i-0123456789abcdef0"))
            contained += 1
        summary = generate_soc_summary(
            pred_class, pred["class_label"], confidence,
            shap_result["top_features"],
            mitigation["mttc_seconds"] if mitigation else None)

        action_status = "CONTAINED" if mitigation else "MONITORED"
        if pred_class != 0:
            threats += 1
            _record_detection(current_user["id"], "scenario", event, pred,
                              action_status)

        # Optional real LocalStack execution (best-effort, never live AWS).
        localstack = attack_scenarios.maybe_execute_localstack(step)

        steps_out.append({
            "step": len(steps_out) + 1,
            "name": step["name"],
            "technique_id": step["technique_id"],
            "technique": step["technique"],
            "tactic": step["tactic"],
            "description": step["description"],
            "event_name": event.get("eventName", ""),
            "event_source": event.get("eventSource", ""),
            "predicted_class": pred_class,
            "class_label": pred["class_label"],
            "confidence": confidence,
            "probabilities": pred["probabilities"],
            "execution_latency_ms": pred["execution_latency_ms"],
            "action_status": action_status,
            "soc_summary": summary,
            "xai": shap_result,
            "mitigation": mitigation,
            "localstack": localstack,
        })

    return {
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "tactic": scenario["tactic"],
        "summary": scenario["summary"],
        "attacker_principal": scenario["attacker_principal"],
        "source_ip": scenario["source_ip"],
        "steps_total": len(scenario["steps"]),
        "threats_detected": threats,
        "auto_contained": contained,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "steps": steps_out,
        "note": (
            "Verdicts are the model's real predictions. Recon steps are "
            "expected to read benign and escape containment; that honest mix "
            "mirrors a real purple-team engagement."
        ),
    }


# ------------------------------------------------------------------
# Live AWS containment (real account, sandbox-only, human-approved)
# ------------------------------------------------------------------
@app.get("/api/v1/live/status")
def live_status(current_user: dict = Depends(get_current_user)):
    """Report whether live mode is armed and which AWS identity it would use.

    Never raises on missing credentials — returns a clear reason so the UI can
    explain what to configure. The mock/localstack teaching tabs are unaffected.
    """
    status = live_watcher.live_ready()
    return {
        "ready": status["ready"],
        "mode": status["mode"],
        "reason": status.get("reason"),
        "identity": status.get("identity"),
        "threshold": live_watcher.DEFAULT_THRESHOLD,
        "blast_cap": live_watcher.MAX_CONTAINMENTS_PER_WINDOW,
        "blast_window_seconds": live_watcher.BLAST_WINDOW_SECONDS,
        "blast_room": live_watcher._blast_room_left(),
        "protected_principals": sorted(live_watcher.PROTECTED_PRINCIPALS),
    }


@app.post("/api/v1/live/poll")
def live_poll(req: LivePollRequest, current_user: dict = Depends(get_current_user)):
    """Poll the real account's CloudTrail and classify recent events.

    Runs every event through the SAME model as every other tab, then applies the
    safety gate. NOTHING is contained here: threats come back as 'pending' for an
    analyst to confirm. If live mode isn't configured, returns ready=False with a
    reason instead of failing.
    """
    clf = get_classifier()
    return live_watcher.evaluate(clf, minutes=req.minutes)


@app.post("/api/v1/live/contain")
def live_contain(req: LiveContainRequest,
                 current_user: dict = Depends(get_current_user)):
    """Execute an analyst-confirmed live IAM revoke on the sandbox account.

    Re-checks every guardrail at execution time (protected principals, blast cap,
    threshold), performs the real revoke, records the incident with its rollback
    token, and returns the result. Guardrail violations -> HTTP 403.
    """
    try:
        result = live_watcher.confirm_containment(
            req.principal, req.predicted_class, req.confidence)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Live containment failed: {e}")

    # Persist to history as a live incident carrying its rollback token.
    log = req.raw_log or {"userIdentity": {"arn": req.principal},
                          "eventName": "LiveContainment"}
    incident = _safe_create_incident(current_user["id"], {
        "source": "live-aws",
        "event_name": log.get("eventName", "LiveContainment"),
        "principal": req.principal,
        "source_ip": log.get("sourceIPAddress", ""),
        "predicted_class": req.predicted_class,
        "class_label": CLASS_LABELS.get(req.predicted_class, str(req.predicted_class)),
        "confidence": req.confidence,
        "action_status": "CONTAINED",
        "raw_log": log,
        "rollback": result.get("rollback"),
    })

    return {
        "incident_id": incident["id"] if incident else None,
        "containment": result,
    }


@app.post("/api/v1/live/undo")
def live_undo(req: LiveUndoRequest, current_user: dict = Depends(get_current_user)):
    """Reverse a previously executed live containment using its rollback token."""
    incident = auth_db.get_incident(current_user["id"], req.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    rollback = incident.get("rollback")
    if not rollback:
        raise HTTPException(status_code=400,
                            detail="This incident has no rollback token to undo.")
    try:
        result = live_watcher.undo_containment(rollback)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Undo failed: {e}")

    updated = auth_db.update_incident(current_user["id"], req.incident_id, {
        "action_status": "REVERSED",
        "rollback": None,
    })
    return {"incident": updated, "undo": result}


@app.get("/")
def root():
    return {"service": "CPEDS-X API", "docs": "/docs", "version": "1.0.0"}
