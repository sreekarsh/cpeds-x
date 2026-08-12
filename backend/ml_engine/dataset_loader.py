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

  2. Pre-computed feature rows + a label field
     Each record already carries all canonical feature columns (see
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
import os
import random as _random
import re
import threading
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
    """True if the row already carries all canonical feature columns."""
    return all(name in event for name in feature_names)


def _vector_from_precomputed(event: Dict, feature_names) -> np.ndarray:
    """Build a feature vector from a row that already has the feature columns."""
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
          X (np.ndarray Nx n_features), y (np.ndarray N),
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


# ======================================================================
# Real-event SAMPLING for the simulator (distinct from training above).
#
# The Attack Simulator / Scenario Runner normally FABRICATE a CloudTrail event
# from a synthetic template. These helpers instead pull a REAL event of a chosen
# class straight out of a labeled dataset, so "Simulate Vertical (C2)" can replay
# an actual C2 event and let the real-trained model judge it (honest, apples to
# apples). The label column is stripped from the returned event so the model
# can't peek. Parsing is cached by (path, mtime) — a click shouldn't re-read MBs.
# ======================================================================

_REAL_CACHE: Dict = {}
_REAL_CACHE_LOCK = threading.Lock()


def default_real_dataset_path() -> Optional[str]:
    """Resolve the dataset the simulator's Real mode should sample from.

    Precedence: $CPEDS_TRAIN_DATASET (the same var real-mode training reads),
    then the bundled Stratus sample beside this package. Returns None if nothing
    is present, so callers can disable Real mode cleanly.
    """
    env = os.getenv("CPEDS_TRAIN_DATASET", "").strip()
    if env and os.path.isfile(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))          # backend/ml_engine
    backend_dir = os.path.dirname(here)                        # backend/
    candidate = os.path.join(backend_dir, "sample_data",
                             "stratus_real_labeled.json")
    return candidate if os.path.isfile(candidate) else None


def _events_by_class(path: str, label_keys: Tuple[str, ...]) -> Dict[int, List[Dict]]:
    """Parse a labeled dataset into {class: [event, ...]}, cached by (path, mtime).

    Each event is stored with its label column(s) removed, so what we hand to
    the model is a clean CloudTrail record. Rows without a usable 0-4 label are
    skipped (not fatal).
    """
    try:
        mtime = os.path.getmtime(path)
    except OSError as e:
        raise DatasetError(f"Could not read dataset file '{path}': {e}")

    cache_key = (os.path.abspath(path), label_keys)
    with _REAL_CACHE_LOCK:
        hit = _REAL_CACHE.get(cache_key)
        if hit is not None and hit[0] == mtime:
            return hit[1]

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        raise DatasetError(f"Could not read dataset file '{path}': {e}")
    try:
        events = parse_logs(content, "auto", os.path.basename(path))
    except LogParseError as e:
        raise DatasetError(f"Could not parse the dataset file: {e}")

    by_class: Dict[int, List[Dict]] = {c: [] for c in _VALID_LABELS}
    for event in events:
        if not isinstance(event, dict):
            continue
        label, _ = _find_label(event, label_keys)
        if label is None:
            continue
        clean = {k: v for k, v in event.items() if k not in label_keys}
        by_class[label].append(clean)

    with _REAL_CACHE_LOCK:
        _REAL_CACHE[cache_key] = (mtime, by_class)
    return by_class


def real_event_availability(dataset_path: Optional[str] = None,
                            label_keys: Optional[List[str]] = None
                            ) -> Optional[Dict]:
    """Per-class count of real events available for sampling.

    Returns {"dataset": name, "per_class": {0..4: n}, "total": n} or None when no
    dataset is present (so the UI can disable the Real toggle with a clear note).
    """
    keys = tuple(label_keys) if label_keys else DEFAULT_LABEL_KEYS
    path = dataset_path or default_real_dataset_path()
    if not path:
        return None
    try:
        by_class = _events_by_class(path, keys)
    except DatasetError:
        return None
    per_class = {c: len(by_class[c]) for c in _VALID_LABELS}
    return {
        "dataset": os.path.basename(path),
        "per_class": per_class,
        "total": sum(per_class.values()),
    }


def sample_real_event(threat_class: int,
                      dataset_path: Optional[str] = None,
                      label_keys: Optional[List[str]] = None,
                      rng=None) -> Tuple[Dict, int]:
    """Return (event, ground_truth_label): a random REAL event of `threat_class`.

    The event is a real CloudTrail record (label stripped) that the caller feeds
    straight into the model. Raises DatasetError if no dataset is available or the
    requested class has no real examples — callers surface that as a clean 422.
    """
    if threat_class not in _VALID_LABELS:
        raise DatasetError(f"threat_class must be 0-4, got {threat_class!r}.")
    keys = tuple(label_keys) if label_keys else DEFAULT_LABEL_KEYS
    path = dataset_path or default_real_dataset_path()
    if not path:
        raise DatasetError(
            "No real dataset available for sampling. Set CPEDS_TRAIN_DATASET to "
            "a labeled CloudTrail file, or add sample_data/stratus_real_labeled.json.")

    by_class = _events_by_class(path, keys)
    pool = by_class.get(threat_class, [])
    if not pool:
        counts = {c: len(by_class[c]) for c in _VALID_LABELS}
        raise DatasetError(
            f"The real dataset has no class-{threat_class} events to sample "
            f"(available per class: {counts}).")

    idx = int(rng.integers(len(pool))) if rng is not None else _random.randrange(len(pool))
    # Copy so callers can stamp fields without mutating the cached pool.
    return dict(pool[idx]), threat_class
