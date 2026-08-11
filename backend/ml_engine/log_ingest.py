"""
CPEDS-X: Log ingestion / parsing.

Turns an uploaded file's raw text into a list of CloudTrail-style audit-log
dicts that the feature extractor understands. Supports the formats security
teams actually have on hand:

  * AWS CloudTrail export .......  {"Records": [ {...}, {...} ]}
  * JSON array .................  [ {...}, {...} ]
  * Single JSON event .........  {...}
  * JSON Lines (.jsonl) ........  one JSON object per line
  * CSV .......................  header row + one event per row
                                 (dotted headers like "userIdentity.arn" are
                                  un-flattened into nested objects; numeric
                                  looking cells are coerced to int/float)

Kept dependency-free (stdlib json + csv) so it runs anywhere the backend runs.
"""
import csv
import io
import json
from typing import Dict, List


class LogParseError(ValueError):
    """Raised when uploaded content can't be parsed into any known format."""


# Keys whose values must stay strings even if they look boolean/numeric.
_FORCE_STR_KEYS = {"mfaAuthenticated", "accountId", "recipientAccountId"}


def _coerce_scalar(key: str, value):
    """Best-effort convert a CSV string cell to int/float; leave others as-is."""
    if not isinstance(value, str):
        return value
    v = value.strip()
    if v == "":
        return v
    if key.split(".")[-1] in _FORCE_STR_KEYS:
        return v
    # int?
    try:
        if v.lstrip("-").isdigit():
            return int(v)
    except Exception:
        pass
    # float?
    try:
        return float(v)
    except (ValueError, TypeError):
        return v


def _unflatten(row: Dict) -> Dict:
    """Turn dotted CSV keys ('userIdentity.arn') into nested dicts."""
    out: Dict = {}
    for key, value in row.items():
        if key is None:
            continue
        value = _coerce_scalar(key, value)
        parts = str(key).split(".")
        cursor = out
        for p in parts[:-1]:
            cursor = cursor.setdefault(p, {})
            if not isinstance(cursor, dict):
                # Conflicting shape; bail out to a flat key to avoid crashing.
                cursor = out
                parts = [key]
                break
        cursor[parts[-1]] = value
    return out


def _looks_like_event(obj) -> bool:
    return isinstance(obj, dict) and (
        "eventName" in obj
        or "userIdentity" in obj
        or "eventSource" in obj
        or "eventTime" in obj
    )


def _from_json_obj(obj) -> List[Dict]:
    """Normalize a parsed-JSON object/array into a list of event dicts."""
    if isinstance(obj, list):
        return [e for e in obj if isinstance(e, dict)]
    if isinstance(obj, dict):
        # CloudTrail console/CLI export wraps events under "Records".
        if isinstance(obj.get("Records"), list):
            return [e for e in obj["Records"] if isinstance(e, dict)]
        # Some tools wrap a single event as {"audit_log": {...}}.
        if isinstance(obj.get("audit_log"), dict):
            return [obj["audit_log"]]
        # Otherwise treat the object itself as one event.
        return [obj]
    raise LogParseError("JSON did not contain any event objects.")


def _try_jsonl(text: str) -> List[Dict]:
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    if not events:
        raise LogParseError("No JSON objects found.")
    return [e for e in events if isinstance(e, dict)]


def _from_csv(text: str) -> List[Dict]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise LogParseError("CSV has no header row.")
    rows = [_unflatten(row) for row in reader]
    if not rows:
        raise LogParseError("CSV contained a header but no data rows.")
    return rows


def parse_logs(content: str, fmt: str = "auto", filename: str = "") -> List[Dict]:
    """
    Parse raw uploaded text into a list of audit-log dicts.

    Args:
        content:  the raw file text
        fmt:      "auto" | "json" | "jsonl" | "csv"
        filename: original name, used only to disambiguate when fmt == "auto"

    Raises:
        LogParseError: if nothing parseable is found.
    """
    if content is None or not content.strip():
        raise LogParseError("The file is empty.")

    fmt = (fmt or "auto").lower()
    name = (filename or "").lower()

    if fmt == "auto":
        if name.endswith(".csv"):
            fmt = "csv"
        elif name.endswith(".jsonl") or name.endswith(".ndjson"):
            fmt = "jsonl"
        else:
            fmt = "json"  # default; falls back to jsonl/csv below on failure

    # Try the chosen format first, then fall back intelligently so users don't
    # have to care about the exact extension.
    attempts = [fmt] + [f for f in ("json", "jsonl", "csv") if f != fmt]
    last_err = None
    for attempt in attempts:
        try:
            if attempt == "json":
                events = _from_json_obj(json.loads(content))
            elif attempt == "jsonl":
                events = _try_jsonl(content)
            elif attempt == "csv":
                events = _from_csv(content)
            else:
                continue
            events = [e for e in events if isinstance(e, dict)]
            if events:
                return events
        except LogParseError as e:
            last_err = e
        except Exception as e:  # json.JSONDecodeError, csv.Error, etc.
            last_err = e

    raise LogParseError(
        "Could not parse the file as JSON, JSON Lines, or CSV. "
        "Expected a CloudTrail export, a JSON array of events, or a CSV with a "
        f"header row. ({last_err})"
    )
