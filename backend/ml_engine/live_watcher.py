"""
CPEDS-X: Live CloudTrail watcher + safety gate.

This is the live-mode ingestion loop. It turns a REAL AWS account's CloudTrail
records into the same CloudTrail-shaped dicts the rest of the pipeline already
understands, scores them with the SAME trained classifier as every other tab,
and — crucially — NEVER fires a destructive AWS change on its own. A detected
threat becomes a *pending* action that a human analyst must confirm.

The loop
--------
    cloudtrail:LookupEvents
        -> parse_logs()                 (reuse the upload parser)
        -> clf.predict()                (reuse the trained model)
        -> SAFETY GATE                  (confidence + class + guardrails)
        -> "pending approval"           (nothing has touched AWS yet)
        -> analyst clicks Confirm
        -> playbooks.mitigation.live_contain_user()   (the only live call)
        -> incident + rollback token

Safety gate (all enforced BEFORE anything executes)
---------------------------------------------------
1. Confidence >= threshold AND class != C0   (same gate as auto-mitigation).
2. Human approval — verdicts are staged as PENDING; a real revoke only happens
   on an explicit confirm. Model confidence alone never fires live.
3. Protected-principals denylist — root, break-glass admins, and CPEDS-X's own
   responder identity are refused (enforced again in mitigation.live_contain_user).
4. Blast-radius cap — at most MAX_CONTAINMENTS_PER_WINDOW confirmed containments
   per BLAST_WINDOW_SECONDS, so a burst of false positives can't cascade.
5. Every executed action returns a rollback token (stored by the caller) so it
   is always reversible with one click.

Credentials come from the cpeds-responder profile / default chain via boto3.
This module only runs live calls when CONTAINMENT_MODE=live AND the responder
credentials are actually present; otherwise poll_events() explains what's missing
instead of raising.
"""
import json
import os
import threading
import time
from collections import deque
from typing import Dict, List, Optional

from ml_engine.log_ingest import parse_logs
from playbooks.mitigation import (
    _containment_mode,
    live_contain_user,
    live_rollback_user,
    PROTECTED_PRINCIPALS,
    _strip_arn,
)

# Same gate as auto-mitigation everywhere else in the app.
DEFAULT_THRESHOLD = 0.75

# Blast-radius cap: refuse more than N confirmed containments per rolling window.
MAX_CONTAINMENTS_PER_WINDOW = int(os.getenv("CPEDS_BLAST_CAP", "5"))
BLAST_WINDOW_SECONDS = int(os.getenv("CPEDS_BLAST_WINDOW", "600"))  # 10 min

# Timestamps (epoch secs) of recently *confirmed* live containments.
_containment_times: deque = deque()
_gate_lock = threading.Lock()


# ----------------------------------------------------------------------
# Availability
# ----------------------------------------------------------------------
def live_ready() -> Dict:
    """Report whether live mode can actually run, without raising.

    Returns {"ready": bool, "mode": str, "reason"/"identity": ...} so the API and
    UI can show a clear status instead of surfacing a boto3 stack trace.
    """
    mode = _containment_mode()
    if mode != "live":
        return {"ready": False, "mode": mode,
                "reason": "CONTAINMENT_MODE is not 'live'. Live polling and "
                          "containment are disabled; the app is in "
                          f"'{mode}' mode."}
    try:
        import boto3  # noqa: F401
    except Exception:
        return {"ready": False, "mode": mode,
                "reason": "boto3 is not installed in this environment."}
    try:
        from playbooks.mitigation import _get_boto3_client
        sts = _get_boto3_client("sts", allow_live=True)
        ident = sts.get_caller_identity()
        return {"ready": True, "mode": mode,
                "identity": {"account": ident.get("Account"),
                             "arn": ident.get("Arn")}}
    except Exception as e:
        return {"ready": False, "mode": mode,
                "reason": f"Live AWS credentials are not usable: {e}. "
                          "Set the cpeds-responder profile (AWS_PROFILE) or the "
                          "default credential chain on the operational host."}


# ----------------------------------------------------------------------
# Poll CloudTrail
# ----------------------------------------------------------------------
def poll_events(minutes: int = 60, max_results: int = 50) -> List[Dict]:
    """Pull recent CloudTrail events and normalize them into audit-log dicts.

    Uses cloudtrail:LookupEvents (no extra infra). Each event's CloudTrailEvent
    is the full JSON record (userIdentity / eventName / requestParameters / …),
    which is exactly what the feature extractor reads. Returns [] if live mode
    is not ready (never raises for a missing-creds situation).
    """
    ready = live_ready()
    if not ready["ready"]:
        return []

    from datetime import datetime, timedelta, timezone
    from playbooks.mitigation import _live_session

    ct = _live_session().client("cloudtrail")
    start_time = datetime.now(timezone.utc) - timedelta(minutes=max(1, minutes))

    events: List[Dict] = []
    next_token: Optional[str] = None
    # Page through, but keep the demo bounded.
    while len(events) < max_results:
        kwargs = {"StartTime": start_time,
                  "MaxResults": min(50, max_results - len(events))}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ct.lookup_events(**kwargs)
        for e in resp.get("Events", []):
            raw = e.get("CloudTrailEvent")
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except (ValueError, TypeError):
                continue
            events.append(record)
        next_token = resp.get("NextToken")
        if not next_token:
            break

    if not events:
        return []
    # Reuse the exact same parser the upload path uses.
    return parse_logs(json.dumps({"Records": events}), fmt="json")


# ----------------------------------------------------------------------
# Safety gate
# ----------------------------------------------------------------------
def _blast_room_left() -> int:
    """How many more confirmed containments the blast-radius cap allows now."""
    now = time.time()
    with _gate_lock:
        while _containment_times and now - _containment_times[0] > BLAST_WINDOW_SECONDS:
            _containment_times.popleft()
        return max(0, MAX_CONTAINMENTS_PER_WINDOW - len(_containment_times))


def _record_containment_now() -> None:
    with _gate_lock:
        _containment_times.append(time.time())


def gate_decision(principal: str, predicted_class: int, confidence: float,
                  threshold: float = DEFAULT_THRESHOLD) -> Dict:
    """Decide what live mode should do with one verdict — WITHOUT executing.

    Returns a decision dict:
      status: "pending"  -> a real threat that an analyst may confirm
              "monitor"  -> benign or below threshold; no action offered
              "blocked"  -> a threat, but a guardrail forbids auto-offering it
                            (protected principal, or blast cap reached)
    """
    username = _strip_arn(principal)
    is_threat = predicted_class != 0 and confidence >= threshold

    if not is_threat:
        return {"status": "monitor", "principal": principal,
                "reason": "Benign or below the confidence threshold; monitored only."}

    if username.lower() in PROTECTED_PRINCIPALS:
        return {"status": "blocked", "principal": principal, "protected": True,
                "reason": f"'{username}' is a protected principal (root / "
                          "break-glass / responder) and is never contained."}

    room = _blast_room_left()
    if room <= 0:
        return {"status": "blocked", "principal": principal, "blast_capped": True,
                "reason": f"Blast-radius cap reached "
                          f"({MAX_CONTAINMENTS_PER_WINDOW} per "
                          f"{BLAST_WINDOW_SECONDS // 60} min). Review pending "
                          "actions before containing more."}

    return {"status": "pending", "principal": principal,
            "predicted_class": predicted_class, "confidence": confidence,
            "blast_room": room,
            "reason": "High-confidence threat. Awaiting analyst confirmation "
                      "before any real IAM change."}


def evaluate(clf, minutes: int = 60, threshold: float = DEFAULT_THRESHOLD) -> Dict:
    """Poll live CloudTrail, classify each event, and stage decisions.

    Never contains anything — it produces the list the UI shows as
    "pending / monitored / blocked". Confirmation happens separately via
    confirm_containment().
    """
    ready = live_ready()
    events = poll_events(minutes=minutes) if ready["ready"] else []

    verdicts: List[Dict] = []
    pending = 0
    for event in events:
        pred = clf.predict(event)
        principal = _principal_of(event)
        decision = gate_decision(principal, pred["predicted_class"],
                                 pred["confidence"], threshold)
        if decision["status"] == "pending":
            pending += 1
        verdicts.append({
            "event_name": event.get("eventName", ""),
            "event_time": event.get("eventTime", ""),
            "principal": principal,
            "source_ip": event.get("sourceIPAddress", ""),
            "predicted_class": pred["predicted_class"],
            "class_label": pred["class_label"],
            "confidence": pred["confidence"],
            "probabilities": pred["probabilities"],
            "execution_latency_ms": pred["execution_latency_ms"],
            "decision": decision,
            "scaled_features": pred["scaled_features"],
            "raw_log": event,
        })

    return {
        "ready": ready["ready"],
        "mode": ready["mode"],
        "status_reason": ready.get("reason"),
        "identity": ready.get("identity"),
        "polled_minutes": minutes,
        "events_seen": len(events),
        "pending_count": pending,
        "blast_room": _blast_room_left(),
        "threshold": threshold,
        "verdicts": verdicts,
    }


# ----------------------------------------------------------------------
# Confirm / execute (the ONLY place a live revoke happens)
# ----------------------------------------------------------------------
def confirm_containment(principal: str, predicted_class: int,
                        confidence: float = 1.0,
                        threshold: float = DEFAULT_THRESHOLD) -> Dict:
    """Execute a live IAM revoke for an analyst-confirmed principal.

    Re-checks the whole gate at execution time (so a stale UI can't bypass a
    guardrail), performs the real revoke, records it against the blast cap, and
    returns the containment result + rollback token.

    Raises PermissionError if a guardrail forbids the action.
    """
    decision = gate_decision(principal, predicted_class, confidence, threshold)
    if decision["status"] != "pending":
        raise PermissionError(decision["reason"])

    # The real, destructive call. mitigation re-validates protected principals.
    result = live_contain_user(principal, predicted_class)
    _record_containment_now()
    result["confirmed"] = True
    result["blast_room"] = _blast_room_left()
    return result


def undo_containment(rollback: Dict) -> Dict:
    """Reverse a previously executed live containment using its rollback token."""
    if not rollback or rollback.get("kind") != "iam_user":
        raise ValueError("Missing or unsupported rollback token.")
    result = live_rollback_user(rollback)
    result["undone"] = True
    return result


def _principal_of(log: dict) -> str:
    ui = log.get("userIdentity", {}) if isinstance(log, dict) else {}
    return ui.get("arn") or ui.get("userName") or "unknown-principal"
