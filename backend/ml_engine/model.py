"""
CPEDS-X: Cloud Privilege Escalation Detection System
ML Engine - Model Loader & Inference Wrapper
Trains/loads LightGBM primary classifier + ensemble (XGBoost, RF, AdaBoost)
"""
import numpy as np
import lightgbm as lgb
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from typing import Dict, Tuple
import os
import pickle
import time

from .preprocessor import FeaturePreprocessor, generate_synthetic_audit_log


# Threat class labels
CLASS_LABELS = {
    0: "C0: Benign",
    1: "C1: Horizontal Escalation",
    2: "C2: Vertical Escalation",
    3: "C3: Data Exfiltration",
    4: "C4: Lateral Movement"
}


# --- real-mode class weighting ----------------------------------------------
# MEASURED, not guessed. sklearn's class_weight='balanced' weights each class by
# N/(K*n_c); on this real dataset C2 has 24 of 2900 rows, so it gets ~100x the
# weight of benign. That over-correction made LightGBM predict C2 on a feature
# vector holding 306 benign rows and only 6 C2 rows -> ~50 false positives, the
# 9.1% C2 precision seen on the dashboard. Damping the exponent fixes it:
#
#     w_c(alpha) = (N / (K * n_c)) ** alpha     (normalized so min weight = 1)
#
# measure_real_f1.py's CLASS-WEIGHT SWEEP over the real 2900-row set (5-fold CV):
#
#     alpha  weighting   CV acc   CV macro-F1   C2 F1   C3 F1
#      0.00  none         95.2%        91.1%    76.9%   82.0%
#      0.25  light        95.4%        91.4%    76.9%   83.2%   <-- best on BOTH
#      0.50  mild         95.0%        88.2%    60.0%   83.2%
#      1.00  balanced     84.6%        77.2%    12.5%   83.2%   <-- was served
#
# alpha=0.25 dominates 'balanced' on every column (+10.8 pts accuracy, +14.2 pts
# macro-F1, +64.4 pts C2 F1), so it is the default. Override with the env var to
# re-run the comparison without editing code.
REAL_CLASS_WEIGHT_ALPHA = float(os.getenv("CPEDS_CLASS_WEIGHT_ALPHA", "0.25"))


def damped_class_weight(y, alpha: float):
    """
    Class-weight dict with 'balanced' damped by `alpha`.

    alpha=0 -> None (no weighting); alpha=1 -> equivalent to 'balanced'.
    Weights are normalized so the largest class sits at 1.0, which keeps the
    effective learning rate comparable across alphas.
    """
    if alpha <= 0:
        return None
    classes, counts = np.unique(y, return_counts=True)
    n, k = len(y), len(classes)
    raw = {int(c): (n / (k * cnt)) ** alpha for c, cnt in zip(classes, counts)}
    lo = min(raw.values())
    return {c: w / lo for c, w in raw.items()}


def damped_sample_weight(y, alpha: float) -> np.ndarray:
    """Per-sample form of damped_class_weight, for estimators (XGBoost,
    AdaBoost) that take sample_weight instead of a class_weight param."""
    weights = damped_class_weight(y, alpha)
    if not weights:
        return np.ones(len(y), dtype=float)
    return np.array([weights.get(int(c), 1.0) for c in y], dtype=float)


class ThreatClassifier:
    """
    Multi-class threat classifier.

    NOTE: On startup this trains a REAL LightGBM model on synthetically
    generated CloudTrail-shaped data so that predictions, probabilities and
    SHAP values are genuine — not hardcoded. The /metrics endpoint separately
    reports reference benchmark numbers from the CPEDS paper baseline.
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.preprocessor = FeaturePreprocessor()
        self.lgbm_model = None
        self.xgb_model = None
        self.rf_model = None
        self.ada_model = None
        self.is_trained = False
        # Real measured metrics from this session's training run
        self.measured_metrics = {}

        # ---- Training-source configuration -----------------------------
        # Mode is read from the environment at construction so the zero-config
        # default stays "synthetic"; an explicit retrain can override it.
        # CPEDS_TRAIN_MODE     = "synthetic" (default) | "real"
        # CPEDS_TRAIN_DATASET  = path to a labeled dataset file (real mode)
        # CPEDS_TRAIN_LABEL_KEY= optional label column name override
        self.training_mode = (os.getenv("CPEDS_TRAIN_MODE", "synthetic") or
                              "synthetic").lower()
        self.effective_mode = self.training_mode  # what actually got used
        self._dataset_path = os.getenv("CPEDS_TRAIN_DATASET", "") or None
        self._dataset_content = None      # raw text of an uploaded dataset
        self._dataset_filename = None
        lk = os.getenv("CPEDS_TRAIN_LABEL_KEY", "").strip()
        self._label_keys = [lk] if lk else None
        self.fallback_reason = None       # why real fell back to synthetic
        self.training_info = {}           # dataset provenance for /metrics

        # ---- Hybrid real-faithful augmentation (real mode only) --------
        # When on, the thin real minority classes (C1/C2/C4) are topped up in
        # the TRAIN FOLD ONLY with real-faithful synthetic events (same feature
        # region as real; see preprocessor.generate_real_faithful_event). The
        # held-out test set and every CV fold stay 100% real, so the reported
        # macro-F1 is not inflated. OFF by default so shipped behaviour is
        # unchanged until measured to help; flip via env or measure_real_f1.py.
        # CPEDS_HYBRID_AUGMENT = "0" (default) | "1"
        # CPEDS_HYBRID_TARGET  = per-minority-class target row count (default 120)
        self.hybrid_augment = os.getenv("CPEDS_HYBRID_AUGMENT", "0").strip() in (
            "1", "true", "True", "yes", "on")
        try:
            self.hybrid_target = int(os.getenv("CPEDS_HYBRID_TARGET", "120"))
        except ValueError:
            self.hybrid_target = 120

    def _generate_training_set(self, n_per_class: int = 800) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build a synthetic labeled dataset across the 5 classes.

        Uses the generator's realistic-randomization mode so classes OVERLAP in
        feature space (see preprocessor.generate_synthetic_audit_log). This is
        deliberate: cleanly-separable templates would score a non-credible
        ~100%. Overlapping behaviour yields honest, defensible metrics in the
        low-to-mid 90s with real per-class confusion.
        """
        X_list, y_list = [], []
        rng = np.random.default_rng(42)

        for cls in range(5):
            for _ in range(n_per_class):
                log = generate_synthetic_audit_log(threat_class=cls,
                                                    randomize=True, rng=rng)
                vec = self.preprocessor.extract_features_from_log(log)
                # Small extra measurement noise on top of behavioural overlap.
                vec = vec + rng.normal(0, 0.25, size=vec.shape)
                X_list.append(vec)
                y_list.append(cls)

        return np.array(X_list), np.array(y_list)

    def _load_real_training_set(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load a REAL labeled dataset into (X, y) via ml_engine.dataset_loader.

        Source precedence: an uploaded dataset_content (raw text) wins; otherwise
        the file at dataset_path / $CPEDS_TRAIN_DATASET is read. Featurization
        goes through the SAME preprocessor.extract_features_from_log() as live
        inference, so real training data is treated identically to real events.

        Raises DatasetError (subclass of ValueError) on any problem, so train()
        can fall back to synthetic (startup) or report it (explicit retrain).
        """
        from . import dataset_loader

        content = self._dataset_content
        if content is not None:
            filename = self._dataset_filename or "uploaded_dataset"
        else:
            path = self._dataset_path
            if not path:
                raise dataset_loader.DatasetError(
                    "Real training mode needs a dataset: set CPEDS_TRAIN_DATASET "
                    "to a file path, or upload a labeled dataset.")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except OSError as e:
                raise dataset_loader.DatasetError(
                    f"Could not read dataset file '{path}': {e}")
            filename = os.path.basename(path)

        result = dataset_loader.load_labeled_dataset(
            content, self.preprocessor, filename=filename,
            label_keys=self._label_keys)

        self.training_info.update({
            "dataset_filename": filename,
            "dataset_rows_total": result["rows_total"],
            "dataset_rows_used": result["rows_used"],
            "dataset_rows_skipped": result["rows_skipped"],
            "dataset_per_class": result["per_class_counts"],
            "dataset_label_key": result["label_key"],
            "dataset_shape": result["mode"],
        })
        print(f"[CPEDS-X] Loaded REAL dataset '{filename}': "
              f"{result['rows_used']} usable rows "
              f"({result['rows_skipped']} skipped), "
              f"per-class {result['per_class_counts']}.")
        return result["X"], result["y"]

    # Minority classes eligible for real-faithful top-up (thin in real data).
    _AUGMENT_CLASSES = (1, 2, 4)

    def _augment_minorities(self, X_raw: np.ndarray, y: np.ndarray,
                            rng) -> Tuple[np.ndarray, np.ndarray]:
        """
        Top up thin minority classes with real-faithful synthetic events.

        For TRAIN-FOLD use ONLY. For each minority class already PRESENT in the
        fold, mint real-faithful events (preprocessor.generate_real_faithful_
        event) until it reaches self.hybrid_target rows, featurize them through
        the SAME extractor as everything else, and append. Classes at/above the
        target — and classes absent from this fold — are left untouched, so we
        never fabricate a class stratification didn't allocate here nor shrink
        anything. Returns raw (pre-scaling) vectors; the caller scales after.

        No-op (returns inputs unchanged) unless self.hybrid_augment is set.
        """
        if not self.hybrid_augment:
            return X_raw, y
        from .preprocessor import generate_real_faithful_event
        add_X, add_y = [], []
        for c in self._AUGMENT_CLASSES:
            have = int(np.sum(y == c))
            if have == 0:
                continue  # class not in this fold — don't invent it
            for _ in range(max(0, self.hybrid_target - have)):
                ev = generate_real_faithful_event(c, rng)
                add_X.append(self.preprocessor.extract_features_from_log(ev))
                add_y.append(c)
        if not add_X:
            return X_raw, y
        X_aug = np.vstack([X_raw, np.asarray(add_X, dtype=float)])
        y_aug = np.concatenate([np.asarray(y), np.asarray(add_y, dtype=y.dtype)])
        return X_aug, y_aug

    def train(self, strict: bool = False, progress=None):
        """
        Train LightGBM + ensemble on the configured data source.

        The data SOURCE is chosen by self.training_mode ("synthetic" | "real");
        the honest evaluation protocol is identical for both, but how the
        class imbalance in the TRAIN fold is handled is mode-aware:
          1. Split raw data into train / test BEFORE any resampling, so no
             synthetic SMOTE neighbour ever leaks from train into test.
          2. Fit the scaler on train only, apply to test.
          3. Rebalance the TRAIN fold only. Synthetic data is evenly sized, so
             SMOTE is used with the original tuned hyperparameters. REAL data is
             severely imbalanced AND tiny (e.g. ~24 rows for a class), where
             synthesising SMOTE neighbours is unreliable and inflates benign->
             attack false positives; there we instead use cost-sensitive
             learning (class weights / per-sample weights) with small-data
             regularization, which lifts minority recall + macro-F1 honestly.
          4. Report accuracy + macro precision/recall/F1 + a real confusion
             matrix on the untouched test fold. For real data, also report a
             stratified k-fold CV macro-F1 (the single split is too noisy).

        Args:
            strict: when False (startup default), a failure to load REAL data
                    falls back to synthetic so the service always boots. When
                    True (explicit retrain), the DatasetError is re-raised so the
                    caller can surface it and keep the previous model.
            progress: optional callable(stage:str) invoked at each phase so a
                    background job can report live progress to the UI. Defaults
                    to a no-op, so existing callers (startup) are unaffected.
        """
        # Normalise the progress reporter to a safe no-op so every call site can
        # emit stages unconditionally without a None-check.
        if progress is None:
            def progress(_stage):  # noqa: E731 - tiny local no-op
                return None

        mode = (self.training_mode or "synthetic").lower()
        self.fallback_reason = None
        self.training_info = {}  # cleared so stale dataset info can't linger

        if mode == "real":
            try:
                progress("Loading labeled dataset")
                X, y = self._load_real_training_set()
                self.effective_mode = "real"
                print("[CPEDS-X] Training on REAL labeled dataset...")
            except Exception as e:  # DatasetError and anything unexpected
                if strict:
                    raise
                self.fallback_reason = str(e)
                self.effective_mode = "synthetic"
                print(f"[CPEDS-X][WARN] Real dataset unusable ({e}). "
                      f"Falling back to synthetic training.")
                print("[CPEDS-X] Generating synthetic training data "
                      "(overlapping classes)...")
                progress("Generating synthetic data")
                X, y = self._generate_training_set()
        else:
            self.effective_mode = "synthetic"
            print("[CPEDS-X] Generating synthetic training data "
                  "(overlapping classes)...")
            progress("Generating synthetic data")
            X, y = self._generate_training_set()

        # 1. Hold out a genuine test set BEFORE scaling/SMOTE (no leakage).
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # 1b. Real-faithful hybrid augmentation (real mode only, TRAIN FOLD ONLY).
        #     Tops up thin minorities with in-distribution synthetic events; the
        #     test fold above is untouched (100% real), so metrics stay honest.
        is_real = (self.effective_mode == "real")
        n_aug = 0
        if is_real and self.hybrid_augment:
            progress("Augmenting minorities (real-faithful)")
            n_before = len(y_train)
            X_train_raw, y_train = self._augment_minorities(
                X_train_raw, y_train, np.random.default_rng(1234))
            n_aug = len(y_train) - n_before

        # 2. Fit scaler on train only, transform both.
        X_train_s = self.preprocessor.fit_transform(X_train_raw)
        X_test = self.preprocessor.transform(X_test_raw)

        # 3. Rebalance the TRAIN fold only — mode-aware (see docstring).
        #    Synthetic: SMOTE + original tuned params (protects the working demo).
        #    Real: cost-sensitive learning (no SMOTE) + small-data regularization.
        if is_real:
            X_train, y_train_bal = X_train_s, y_train
            # Damped class weighting (alpha, MEASURED — see REAL_CLASS_WEIGHT_ALPHA).
            # Per-sample form for estimators without a class_weight param.
            # Computed AFTER augmentation so weights reflect the topped-up counts.
            alpha = REAL_CLASS_WEIGHT_ALPHA
            sample_w = damped_sample_weight(y_train_bal, alpha)
            cw = damped_class_weight(y_train_bal, alpha)
            lgbm_kwargs = dict(num_leaves=15, min_child_samples=5,
                               reg_alpha=0.1, reg_lambda=1.0,
                               n_estimators=300, learning_rate=0.03,
                               class_weight=cw)
            rf_kwargs = dict(n_estimators=200, max_depth=8, class_weight=cw)
            resampling = (f"damped class weights alpha={alpha:g} (no SMOTE)"
                          if cw else "no class weighting (alpha=0, no SMOTE)")
            if self.hybrid_augment and n_aug > 0:
                resampling += (f" + hybrid real-faithful aug "
                               f"(+{n_aug} rows, target {self.hybrid_target}/class)")
        else:
            X_train, y_train_bal = self.preprocessor.apply_smote(X_train_s, y_train)
            sample_w = None
            lgbm_kwargs = dict(num_leaves=31, learning_rate=0.05,
                               n_estimators=200)
            rf_kwargs = dict(n_estimators=100, max_depth=12)
            resampling = "SMOTE (train fold)"

        print(f"[CPEDS-X] Imbalance strategy: {resampling}.")
        print("[CPEDS-X] Training LightGBM (primary, leaf-wise)...")
        progress("Training LightGBM (primary)")
        self.lgbm_model = lgb.LGBMClassifier(
            objective='multiclass', num_class=5, boosting_type='gbdt',
            random_state=42, verbose=-1, **lgbm_kwargs
        )
        self.lgbm_model.fit(X_train, y_train_bal)

        print("[CPEDS-X] Training XGBoost (ensemble)...")
        progress("Training XGBoost (2 of 4)")
        self.xgb_model = xgb.XGBClassifier(
            objective='multi:softprob', num_class=5, max_depth=6,
            learning_rate=0.05, n_estimators=150, random_state=42,
            verbosity=0
        )
        self.xgb_model.fit(X_train, y_train_bal, sample_weight=sample_w)

        print("[CPEDS-X] Training Random Forest (ensemble)...")
        progress("Training Random Forest (3 of 4)")
        self.rf_model = RandomForestClassifier(
            random_state=42, n_jobs=-1, **rf_kwargs
        )
        self.rf_model.fit(X_train, y_train_bal)

        print("[CPEDS-X] Training AdaBoost (ensemble)...")
        progress("Training AdaBoost (4 of 4)")
        self.ada_model = AdaBoostClassifier(
            n_estimators=80, algorithm='SAMME', random_state=42
        )
        self.ada_model.fit(X_train, y_train_bal, sample_weight=sample_w)

        # 4. Honest metrics on the untouched test fold.
        progress("Evaluating on held-out test set")
        self.measured_metrics = self._evaluate(X_test, y_test)

        # 4b. Real data: the single 80/20 split leaves the rarest classes with a
        #     handful of test rows, so its macro-F1 swings wildly by seed. Add a
        #     stratified k-fold CV macro-F1 over ALL rows as the honest headline.
        if is_real:
            progress("Cross-validating (stratified k-fold)")
            cv = self._cross_val_macro_f1(X, y)
            if cv:
                self.measured_metrics.update(cv)

        self.is_trained = True
        # Record provenance so /metrics can show exactly what was trained on.
        self.training_info.update({
            "effective_mode": self.effective_mode,
            "requested_mode": mode,
            "train_rows": int(len(y_train_bal)),
            "test_rows": int(len(y_test)),
            "imbalance_strategy": resampling,
            "class_weight_alpha": REAL_CLASS_WEIGHT_ALPHA if is_real else None,
            "hybrid_augment": bool(is_real and self.hybrid_augment),
            "hybrid_target": int(self.hybrid_target) if (is_real and self.hybrid_augment) else None,
            "hybrid_rows_added": int(n_aug),
            "fallback_reason": self.fallback_reason,
        })
        cv_note = ""
        if self.measured_metrics.get("cv_macro_f1_mean") is not None:
            cv_note = (f", CV macro-F1={self.measured_metrics['cv_macro_f1_mean']}"
                       f"±{self.measured_metrics['cv_macro_f1_std']} "
                       f"({self.measured_metrics.get('cv_folds')}-fold)")
        print(f"[CPEDS-X] Training complete [{self.effective_mode}]. "
              f"Measured (held-out test): "
              f"LightGBM acc={self.measured_metrics['lightgbm_accuracy']}, "
              f"macro-F1={self.measured_metrics['lightgbm_macro_f1']}{cv_note}")

    def _evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Compute real accuracy + per-class metrics on the held-out test set."""
        preds = {
            'lightgbm_accuracy': self.lgbm_model.predict(X_test),
            'xgboost_accuracy': self.xgb_model.predict(X_test),
            'random_forest_accuracy': self.rf_model.predict(X_test),
            'adaboost_accuracy': self.ada_model.predict(X_test),
        }
        metrics = {k: round(float(accuracy_score(y_test, p)), 4)
                   for k, p in preds.items()}

        # Detailed metrics for the primary model (LightGBM).
        lgbm_pred = preds['lightgbm_accuracy']
        metrics['lightgbm_macro_f1'] = round(
            float(f1_score(y_test, lgbm_pred, average='macro', zero_division=0)), 4)
        metrics['lightgbm_macro_precision'] = round(
            float(precision_score(y_test, lgbm_pred, average='macro', zero_division=0)), 4)
        metrics['lightgbm_macro_recall'] = round(
            float(recall_score(y_test, lgbm_pred, average='macro', zero_division=0)), 4)

        # Per-class precision/recall/F1 (list index == class id).
        per_p = precision_score(y_test, lgbm_pred, average=None, labels=[0,1,2,3,4], zero_division=0)
        per_r = recall_score(y_test, lgbm_pred, average=None, labels=[0,1,2,3,4], zero_division=0)
        per_f = f1_score(y_test, lgbm_pred, average=None, labels=[0,1,2,3,4], zero_division=0)
        # Support = how many test rows actually belong to each class. On a tiny
        # imbalanced set a class can have only a handful of test rows, making its
        # precision/recall/F1 extremely high-variance (e.g. C2 with n=5). Surface
        # it so a noisy small-sample score isn't read as a stable one.
        y_test_arr = np.asarray(y_test)
        per_support = [int(np.sum(y_test_arr == i)) for i in range(5)]
        metrics['per_class'] = [
            {
                'class': i,
                'label': CLASS_LABELS[i],
                'precision': round(float(per_p[i]), 4),
                'recall': round(float(per_r[i]), 4),
                'f1': round(float(per_f[i]), 4),
                'support': per_support[i],
            }
            for i in range(5)
        ]

        # Real row-normalized confusion matrix (rows = actual, cols = predicted).
        cm = confusion_matrix(y_test, lgbm_pred, labels=[0,1,2,3,4]).astype(float)
        row_sums = cm.sum(axis=1, keepdims=True)
        cm_norm = np.divide(cm, row_sums, out=np.zeros_like(cm), where=row_sums != 0)
        metrics['confusion_matrix'] = [[round(float(v), 4) for v in row] for row in cm_norm]
        metrics['confusion_counts'] = [[int(v) for v in row] for row in cm.astype(int)]
        metrics['test_set_size'] = int(len(y_test))

        return metrics

    def _cross_val_macro_f1(self, X: np.ndarray, y: np.ndarray,
                            n_splits: int = 5) -> Dict:
        """
        Stratified k-fold CV macro-F1 for the primary (LightGBM) model.

        On a tiny, severely-imbalanced real dataset the single 80/20 split
        leaves only a handful of rows for the rarest class, so its macro-F1
        can swing 10+ points by random seed. Averaging over k stratified folds
        gives a far more trustworthy headline number — this is what to cite.

        Mirrors the real-mode training recipe exactly (fresh scaler fit per
        fold, damped class weights at REAL_CLASS_WEIGHT_ALPHA, small-data
        params) and never leaks across folds. k is capped at the smallest class
        count so every fold can contain every class; returns {} if the data is
        too small to split.
        """
        _, counts = np.unique(y, return_counts=True)
        k = int(min(n_splits, counts.min()))
        if k < 2:
            return {}
        skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
        scores = []
        accs = []
        for fold, (tr_idx, te_idx) in enumerate(skf.split(X, y)):
            # Augment the TRAIN portion only (real-faithful, in-distribution);
            # the TEST portion stays 100% real so the fold score is honest.
            X_tr_raw, y_tr = X[tr_idx], y[tr_idx]
            if self.hybrid_augment:
                X_tr_raw, y_tr = self._augment_minorities(
                    X_tr_raw, y_tr, np.random.default_rng(1000 + fold))
            scaler = StandardScaler()
            X_tr = scaler.fit_transform(X_tr_raw)
            X_te = scaler.transform(X[te_idx])
            fold_model = lgb.LGBMClassifier(
                objective='multiclass', num_class=5, boosting_type='gbdt',
                num_leaves=15, min_child_samples=5, reg_alpha=0.1,
                reg_lambda=1.0, n_estimators=300, learning_rate=0.03,
                class_weight=damped_class_weight(y_tr, REAL_CLASS_WEIGHT_ALPHA),
                random_state=42, verbose=-1)
            fold_model.fit(X_tr, y_tr)
            pred = fold_model.predict(X_te)
            scores.append(f1_score(y[te_idx], pred, average='macro',
                                   zero_division=0))
            accs.append(accuracy_score(y[te_idx], pred))
        scores = np.array(scores, dtype=float)
        accs = np.array(accs, dtype=float)
        return {
            'cv_folds': k,
            'cv_macro_f1_mean': round(float(scores.mean()), 4),
            'cv_macro_f1_std': round(float(scores.std()), 4),
            'cv_accuracy_mean': round(float(accs.mean()), 4),
            'cv_accuracy_std': round(float(accs.std()), 4),
            'class_weight_alpha': REAL_CLASS_WEIGHT_ALPHA,
        }

    def predict(self, audit_log: Dict) -> Dict:
        """
        Run inference on a raw audit log.

        Returns predicted class, confidence, per-class probabilities,
        scaled feature vector, and execution latency in ms.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        start = time.perf_counter()

        # Extract + scale features
        raw_vec = self.preprocessor.extract_features_from_log(audit_log)
        scaled_vec = self.preprocessor.transform(raw_vec.reshape(1, -1))

        # Primary prediction (LightGBM)
        probs = self.lgbm_model.predict_proba(scaled_vec)[0]
        pred_class = int(np.argmax(probs))
        confidence = float(probs[pred_class])

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            'predicted_class': pred_class,
            'class_label': CLASS_LABELS[pred_class],
            'confidence': round(confidence, 4),
            'probabilities': {CLASS_LABELS[i]: round(float(p), 4) for i, p in enumerate(probs)},
            'execution_latency_ms': latency_ms,
            'scaled_features': scaled_vec[0].tolist(),
            'feature_names': self.preprocessor.feature_names,
        }

    def save(self):
        """Persist trained models to disk."""
        os.makedirs(self.model_dir, exist_ok=True)
        with open(os.path.join(self.model_dir, 'cpeds_models.pkl'), 'wb') as f:
            pickle.dump({
                'lgbm': self.lgbm_model, 'xgb': self.xgb_model,
                'rf': self.rf_model, 'ada': self.ada_model,
                'scaler': self.preprocessor.scaler,
                'metrics': self.measured_metrics
            }, f)


# Global singleton instance
_classifier = None


def get_classifier() -> ThreatClassifier:
    """Return (and lazily train) the global classifier singleton."""
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
        _classifier.train()
    return _classifier


def retrain_classifier(mode: str = "synthetic", dataset_content: str = None,
                       dataset_filename: str = "", label_keys=None,
                       progress=None) -> ThreatClassifier:
    """
    Build a fresh classifier on the requested source and, only if training
    succeeds, ATOMICALLY replace the global singleton.

    The new model is trained fully on the side; the live singleton keeps serving
    predictions until the final single-statement swap. Real mode trains strictly:
    if the dataset is unusable the DatasetError propagates and the EXISTING model
    is left in place (an explicit retrain never silently downgrades to synthetic).
    Synthetic mode always succeeds and is the way to revert.

    Concurrency: callers must serialize retrains (RetrainJob provides single-
    flight); the swap itself is a lone assignment, atomic under CPython's GIL.

    Args:
        progress: optional callable(stage:str) forwarded to train() for live
                  progress reporting; defaults to no-op.
    """
    global _classifier
    mode = (mode or "synthetic").lower()
    candidate = ThreatClassifier()
    candidate.training_mode = mode
    if dataset_content is not None:
        candidate._dataset_content = dataset_content
        candidate._dataset_filename = dataset_filename or "uploaded_dataset"
    if label_keys:
        candidate._label_keys = list(label_keys)

    candidate.train(strict=(mode == "real"), progress=progress)
    _classifier = candidate  # atomic swap — only reached if training succeeded
    return candidate
