"""
CPEDS-X: Labeled dataset loader for REAL training data.

The threat classifier normally trains on synthetically generated CloudTrail
events (ml_engine.model._generate_training_set). This module is the "real data"
counterpart: it turns a LABELED file into the same (X, y) arrays training
expects, so the honest train/test/SMOTE pipeline in model.py is reused unchanged.

Two accepted dataset shapes (auto-detected per row):

  1. Raw CloudTrail events + a label field  (recommended)
     Each record looks like a normal CloudTrail event (eventName, userIdentity,
     ...) PLUS a label column. Every event is run through the SAME
     FeaturePreprocessor.extract_features_from_log() used everywhere else, so
     real training data is featurized identically to live inference.

  2. Pre-computed 28-feature rows + a label field
     Each record already carries all 28 canonical feature columns (see
     FeaturePreprocessor.feature_names) plus a label. Used directly, no
     re-featurization.

Accepts the same formats as the upload tab (CloudTrail JSON export, JSON array,
JSON Lines, CSV) because it reuses ml_engine.log_ingest.parse_logs.

Labels may be an int (0-4), a numeric string ("2"), or a class code ("C2" or
"C2: Vertical Escalation"). Rows without a usable label are skipped and counted,
not fatal — but if the surviving, validated data is too small or single-class,
load_labeled_dataset raises DatasetError so the caller can fall back to
synthetic training cleanly.
"""
import re
from typing import Dict, List, Optional, Tuple

import numpy as np

from .log_ingest import parse_logs, LogParseError


class DatasetError(ValueError):
    """Raised when a labeled dataset can't be turned into usable (X, y)."""


# Label columns tried, in order, when the caller doesn't specify one.
DEFAULT_LABEL_KEYS = ("label", "threat_class", "class", "y")

# A present class needs at least this many rows to survive stratified splitting
# and (adaptive) SMOTE without degenerate behaviour.
MIN_ROWS_PER_CLASS = 10

# Total usable rows floor — below this a "real" run isn't credible.
MIN_ROWS_TOTAL = 40

_VALID_LABELS = {0, 1, 2, 3, 4}
_CODE_RE = re.compile(r"^\s*c?\s*([0-4])\b", re.IGNORECASE)


def _coerce_label(value) -> Optional[int]:
    """Best-effort convert a raw label cell to an int class 0-4, else None."""
    if value is None or isinstance(value, bool):  # bool is an int subclass
        return None
    if isinstance(value, (int, float)):
        iv = int(round(value))
        return iv if iv in _VALID_LABELS else None
    if isinstance(value, str):
        m = _CODE_RE.match(value)
        if m:
            return int(m.group(1))
    return None


def _find_label(event: Dict, label_keys) -> Tuple[Optional[int], Optional[str]]:
    """Return (label, key_used); label is None if no usable label is found."""
    for k in label_keys:
        if k in event:
            lab = _coerce_label(event.get(k))
            if lab is not None:
                return lab, k
    return None, None


def _has_precomputed_features(event: Dict, feature_names) -> bool:
    """True if the row already carries all 28 canonical feature columns."""
    return all(name in event for name in feature_names)


def _vector_from_precomputed(event: Dict, feature_names) -> np.ndarray:
    """Build a 28-vector from a row that already has the feature columns."""
    vec = np.empty(len(feature_names), dtype=float)
    for i, name in enumerate(feature_names):
        try:
            vec[i] = float(event.get(name, 0.0) or 0.0)
        except (TypeError, ValueError):
            raise DatasetError(
                f"Feature column '{name}' has a non-numeric value: "
                f"{event.get(name)!r}."
            )
    return vec


def load_labeled_dataset(
    content: str,
    preprocessor,
    fmt: str = "auto",
    filename: str = "",
    label_keys: Optional[List[str]] = None,
) -> Dict:
    """
    Parse + validate + featurize a labeled dataset into training arrays.

    Args:
        content:      raw file text (CloudTrail JSON / JSON array / JSONL / CSV).
        preprocessor: a FeaturePreprocessor — supplies feature_names and the
                      shared extract_features_from_log() so real data is
                      featurized exactly like live inference.
        fmt:          "auto" | "json" | "jsonl" | "csv" (passed to parse_logs).
        filename:     original name, used only for format auto-detection.
        label_keys:   candidate label column names; defaults to
                      DEFAULT_LABEL_KEYS ("label", "threat_class", ...).

    Returns:
        dict with:
          X (np.ndarray Nx28), y (np.ndarray N),
          rows_total, rows_used, rows_skipped,
          per_class_counts {0..4: n},
          label_key (the column actually used),
          mode ("raw_events" | "precomputed_features" | "mixed").

    Raises:
        DatasetError: nothing parseable, no labels found, too few rows, or only
                      one class present. The caller is expected to fall back to
                      synthetic training on this error.
    """
    keys = tuple(label_keys) if label_keys else DEFAULT_LABEL_KEYS
    feature_names = preprocessor.feature_names

    try:
        events = parse_logs(content, fmt, filename)
    except LogParseError as e:
        raise DatasetError(f"Could not parse the dataset file: {e}")

    if not events:
        raise DatasetError("The dataset file contained no rows.")

    X_list: List[np.ndarray] = []
    y_list: List[int] = []
    per_class = {c: 0 for c in _VALID_LABELS}
    rows_skipped = 0
    label_key_used: Optional[str] = None
    saw_raw = False
    saw_precomputed = False
    featurize_errors = 0

    for event in events:
        if not isinstance(event, dict):
            rows_skipped += 1
            continue

        label, key = _find_label(event, keys)
        if label is None:
            rows_skipped += 1
            continue
        if label_key_used is None:
            label_key_used = key

        try:
            if _has_precomputed_features(event, feature_names):
                vec = _vector_from_precomputed(event, feature_names)
                saw_precomputed = True
            else:
                # Same feature path as live inference (single shared function).
                vec = preprocessor.extract_features_from_log(event)
                saw_raw = True
        except DatasetError:
            raise
        except Exception:
            # A malformed individual event shouldn't kill the whole load.
            featurize_errors += 1
            rows_skipped += 1
            continue

        if vec.shape[0] != len(feature_names):
            rows_skipped += 1
            continue

        X_list.append(vec)
        y_list.append(label)
        per_class[label] += 1

    rows_used = len(y_list)
    if rows_used == 0:
        raise DatasetError(
            "No labeled rows found. Add a label column (one of: "
            f"{', '.join(keys)}) with values 0-4 (or C0-C4)."
        )

    present_classes = [c for c, n in per_class.items() if n > 0]
    if len(present_classes) < 2:
        raise DatasetError(
            "The dataset has only one threat class "
            f"(class {present_classes[0]}). Training needs at least two "
            "distinct classes."
        )

    if rows_used < MIN_ROWS_TOTAL:
        raise DatasetError(
            f"Only {rows_used} usable labeled rows (minimum {MIN_ROWS_TOTAL}). "
            "Provide a larger labeled dataset."
        )

    thin = {c: n for c in present_classes
            if 0 < (n := per_class[c]) < MIN_ROWS_PER_CLASS}
    if thin:
        detail = ", ".join(f"class {c}: {n}" for c, n in sorted(thin.items()))
        raise DatasetError(
            f"Some classes have too few rows ({detail}); need at least "
            f"{MIN_ROWS_PER_CLASS} each for a reliable train/test split."
        )

    mode = ("mixed" if saw_raw and saw_precomputed
            else "precomputed_features" if saw_precomputed
            else "raw_events")

    return {
        "X": np.array(X_list),
        "y": np.array(y_list),
        "rows_total": len(events),
        "rows_used": rows_used,
        "rows_skipped": rows_skipped,
        "featurize_errors": featurize_errors,
        "per_class_counts": per_class,
        "label_key": label_key_used,
        "mode": mode,
    }
