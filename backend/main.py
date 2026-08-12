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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import json
import random
import time

from ml_engine.model import get_classifier, retrain_classifier, CLASS_LABELS
from ml_engine.shap_explainer import get_explainer
from ml_engine.genai_copilot import generate_soc_summary
from ml_engine.preprocessor import generate_synthetic_audit_log
from ml_engine.log_ingest import parse_logs, LogParseError
from ml_engine import dataset_loader
from train_job import RetrainJob
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
    scaled_features: List[float] = Field(..., description="Scaled feature vector")
    predicted_class: int = Field(..., ge=0, le=4)


class MitigateRequest(BaseModel):
    principal: str = Field(..., description="IAM principal ARN or username")
    predicted_class: int = Field(..., ge=0, le=4)
    confidence: float = Field(..., ge=0.0, le=1.0)
    instance_id: Optional[str] = "i-0123456789abcdef0"


class SimulateRequest(BaseModel):
    threat_class: int = Field(0, ge=0, le=4)
    source: str = Field("synthetic",
                        description="'synthetic' fabricates an event from a "
                        "template; 'real' samples a labeled CloudTrail event.")


class AnalyzeRequest(BaseModel):
    content: str = Field(..., description="Raw uploaded file text (JSON/JSONL/CSV)")
    format: str = Field("auto", description="auto | json | jsonl | csv")
    filename: Optional[str] = Field("", description="Original filename (for format hint)")


class ScenarioRunRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario id from GET /api/v1/scenarios")
    source: str = Field("synthetic",
                        description="'synthetic' seeds each step from a template; "
                        "'real' replays a labeled CloudTrail event of the step's class.")


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

# Background retrain manager. Retraining rebuilds the shared model singleton, so
# it must be single-flight (never two at once) AND must not block the request —
# real-mode training + k-fold CV is heavy. RetrainJob runs it on a daemon thread
# and exposes a pollable status; a second start() while running is refused (409).
_RETRAIN_JOB = RetrainJob()


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
        "imbalance_strategy": info.get("imbalance_strategy"),
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
    Kick off a retrain on a background thread and return immediately.

    mode="synthetic" (default) retrains on the built-in synthetic generator —
    always succeeds, and is how you revert. mode="real" trains on an uploaded
    labeled dataset (dataset_content) or the server-configured dataset path; if
    the dataset is unusable the PREVIOUS model is kept and the job ends in an
    "error" state whose message explains why (poll GET /train/status).

    This is NON-BLOCKING: real-mode training + k-fold CV is heavy enough that
    running it inside the request made the UI look frozen and, on refresh, wedge
    on a bare 409. Now the work runs on a daemon thread; the client polls
    /train/status for stage + elapsed and the final result. Single-flight: a
    second start while one is running returns 409.

    Guardrails: auth-gated like every detection endpoint; uploaded content is
    size-capped. This only rebuilds the in-memory model — it makes no AWS calls
    and never touches live containment.
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

    label_keys = [req.label_key] if req.label_key else None
    dataset_filename = req.dataset_filename or ""

    def _runner(progress):
        # Runs on the background thread. retrain_classifier trains strictly in
        # real mode (DatasetError propagates -> job "error", old model kept) and
        # atomically hot-swaps the singleton only on success.
        clf = retrain_classifier(
            mode=mode,
            dataset_content=content,
            dataset_filename=dataset_filename,
            label_keys=label_keys,
            progress=progress,
        )
        return {
            "status": "retrained",
            "training": _training_status(clf),
            "measured": clf.measured_metrics,
        }

    if not _RETRAIN_JOB.start(mode, _runner):
        raise HTTPException(
            status_code=409,
            detail="A retrain is already in progress. Watch its progress or try again shortly.")

    # 202 Accepted: work has started; poll /train/status for stage + result.
    return JSONResponse(status_code=202,
                        content={"status": "started", **_RETRAIN_JOB.status()})


@app.get("/api/v1/train/status")
def train_status(current_user: dict = Depends(get_current_user)):
    """
    Live status of the background retrain, for the UI to poll.

    Returns {state: idle|running|done|error, mode, stage, elapsed_ms, error,
    result}. `result` (present when state=="done") carries the same
    {status, training, measured} payload the old synchronous call returned, so
    the frontend can refresh its charts without a second request.
    """
    return _RETRAIN_JOB.status()


@app.get("/api/v1/simulate/availability")
def simulate_availability(current_user: dict = Depends(get_current_user)):
    """Report whether Real mode can be used and how many events exist per class.

    The frontend calls this to enable/disable the Synthetic/Real toggle and to
    grey out per-class buttons that have no real examples. `available` is False
    when no labeled dataset is present at all.
    """
    avail = dataset_loader.real_event_availability()
    if avail is None:
        return {
            "available": False,
            "note": ("No labeled dataset found. Set CPEDS_TRAIN_DATASET or add "
                     "backend/sample_data/stratus_real_labeled.json to enable "
                     "Real mode."),
        }
    return {"available": True, **avail}


@app.post("/api/v1/simulate")
def simulate(req: SimulateRequest, current_user: dict = Depends(get_current_user)):
    """Produce a CloudTrail audit log for a given threat class.

    - source="synthetic" (default): fabricate an event from the class template.
    - source="real": sample a REAL labeled CloudTrail event of that class from
      the dataset (label stripped) and also return its ground-truth label, so the
      UI can show truth-vs-prediction (a real hit/miss for the trained model).
    """
    source = (req.source or "synthetic").lower()
    if source == "real":
        try:
            event, ground_truth = dataset_loader.sample_real_event(req.threat_class)
        except dataset_loader.DatasetError as e:
            raise HTTPException(status_code=422, detail=str(e))
        return {
            "audit_log": event,
            "source": "real",
            "ground_truth_label": ground_truth,
            "ground_truth_class_label": CLASS_LABELS[ground_truth],
        }
    return {"audit_log": generate_synthetic_audit_log(req.threat_class),
            "source": "synthetic"}


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

    source = (req.source or "synthetic").lower()
    # In real mode, verify a dataset is present up front so we fail cleanly with
    # a 422 (and the UI keeps its toggle off) rather than erroring mid-campaign.
    if source == "real" and dataset_loader.real_event_availability() is None:
        raise HTTPException(
            status_code=422,
            detail=("Real mode needs a labeled dataset. Set CPEDS_TRAIN_DATASET "
                    "or add backend/sample_data/stratus_real_labeled.json."))

    clf = get_classifier()
    explainer = get_explainer(clf.lgbm_model, clf.preprocessor.feature_names)
    steps_out: List[Dict] = []
    threats = 0
    contained = 0
    real_steps = 0
    started = time.perf_counter()

    for step in scenario["steps"]:
        seeded_class = step.get("threat_class", 0)
        ground_truth = None
        step_source = "synthetic"
        if source == "real":
            try:
                event, ground_truth = dataset_loader.sample_real_event(seeded_class)
                event = attack_scenarios.stamp_identity(
                    event, scenario["attacker_principal"], scenario["source_ip"])
                step_source = "real"
                real_steps += 1
            except dataset_loader.DatasetError:
                # This class has no real examples — seed synthetically for this
                # step so the campaign still plays out end to end.
                event = attack_scenarios.build_step_event(
                    step, scenario["attacker_principal"], scenario["source_ip"])
        else:
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
            "step_source": step_source,
            "ground_truth_label": ground_truth,
            "ground_truth_class_label": (
                CLASS_LABELS[ground_truth] if ground_truth is not None else None),
            "correct": (ground_truth is not None and pred_class == ground_truth),
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
        "source": source,
        "real_steps": real_steps,
        "note": (
            "Verdicts are the model's real predictions. Recon steps are "
            "expected to read benign and escape containment; that honest mix "
            "mirrors a real purple-team engagement."
            + (" Real mode replays labeled CloudTrail events; steps show the "
               "model's prediction against the dataset's ground-truth label."
               if source == "real" else "")
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
