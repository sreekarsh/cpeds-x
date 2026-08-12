"""
measure_real_f1.py — A/B the OLD vs NEW real-mode training recipe.

Run this on a machine that HAS the ML stack installed (scikit-learn, lightgbm,
imbalanced-learn). It loads your real labeled dataset through the SAME
preprocessor + dataset_loader the app uses, then trains the primary model
(LightGBM) two ways on an identical split and reports macro-F1 both on a
held-out test set AND via 5-fold stratified cross-validation:

  OLD recipe : SMOTE on the train fold + default params
               (num_leaves=31, lr=0.05, n_estimators=200, no class weights)
  NEW recipe : NO SMOTE + class_weight='balanced' + small-data params
               (num_leaves=15, min_child_samples=5, reg, n_estimators=300, lr=0.03)

Macro-F1 (not accuracy) is the honest metric on an imbalanced dataset: a model
that always says "benign" scores ~83% accuracy while catching zero attacks.

It then runs a FEATURE ABLATION: holding the recipe fixed at NEW, it compares
CV macro-F1 with vs without the four added real-signal features
(access_denied_flag, sensitive_privilege_action, credential_access_action,
lateral_movement_action) so you can see the lift attributable to the FEATURES
separately from the recipe.

Finally it runs a HYBRID A/B: holding the recipe fixed at NEW, it compares
real-only training against training where the thin minority classes (C1/C2/C4)
are topped up on the TRAIN FOLD ONLY with real-faithful synthetic events
(preprocessor.generate_real_faithful_event). Every test/CV test fold stays
100% real, so the reported macro-F1 stays honest — this is exactly what flipping
CPEDS_HYBRID_AUGMENT=1 does in the app, measured before you commit to it.

Usage (from the backend/ directory, in your venv):
    # uses backend/sample_data/stratus_real_labeled.json by default
    python measure_real_f1.py
    # or point at another labeled file:
    set CPEDS_TRAIN_DATASET=C:\path\to\labeled.json   (Windows)
    python measure_real_f1.py
"""
import os
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, recall_score, accuracy_score
from sklearn.utils.class_weight import compute_sample_weight
import lightgbm as lgb

from ml_engine.preprocessor import (
    FeaturePreprocessor, generate_real_faithful_event)
from ml_engine import dataset_loader

CLASS_LABELS = ["C0 Benign", "C1 Horizontal", "C2 Vertical",
                "C3 Exfil", "C4 Lateral"]

# The real-signal features added on top of the original 28. The feature
# ablation below holds the training recipe fixed (NEW) and drops these columns
# to isolate the lift attributable to the FEATURES from the lift attributable
# to the recipe change measured above.
NEW_FEATURE_NAMES = [
    "access_denied_flag", "sensitive_privilege_action",
    "credential_access_action", "lateral_movement_action",
]

# Minority classes the hybrid augmenter tops up (thin in real data).
AUGMENT_CLASSES = (1, 2, 4)
HYBRID_TARGET = int(os.getenv("CPEDS_HYBRID_TARGET", "120"))

# A stateless featurizer used only to turn minted real-faithful events into
# feature vectors. extract_features_from_log does not depend on a fitted scaler,
# so one shared instance is safe across folds.
_AUG_PRE = FeaturePreprocessor()


def load_dataset():
    path = (os.getenv("CPEDS_TRAIN_DATASET", "").strip() or
            os.path.join(os.path.dirname(__file__), "sample_data",
                         "stratus_real_labeled.json"))
    if not os.path.isfile(path):
        raise SystemExit(f"Dataset not found: {path}\n"
                         "Set CPEDS_TRAIN_DATASET to your labeled file.")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    pre = FeaturePreprocessor()
    res = dataset_loader.load_labeled_dataset(
        content, pre, filename=os.path.basename(path))
    print(f"Loaded {res['rows_used']} rows from {os.path.basename(path)} "
          f"({res['rows_skipped']} skipped)")
    print(f"Per-class counts: {res['per_class_counts']}\n")
    return res["X"], res["y"], list(pre.feature_names)


def make_lgbm(recipe):
    if recipe == "new":
        return lgb.LGBMClassifier(
            objective="multiclass", num_class=5, boosting_type="gbdt",
            num_leaves=15, min_child_samples=5, reg_alpha=0.1, reg_lambda=1.0,
            n_estimators=300, learning_rate=0.03, class_weight="balanced",
            random_state=42, verbose=-1)
    return lgb.LGBMClassifier(
        objective="multiclass", num_class=5, boosting_type="gbdt",
        num_leaves=31, learning_rate=0.05, n_estimators=200,
        random_state=42, verbose=-1)


# --- class-weight sweep -----------------------------------------------------
# The served real recipe uses class_weight='balanced', which weights each class
# by N/(K*n_c). On a 24-row class (C2) that is ~100x, and on the collision
# feature-vectors it flips the model into predicting the MINORITY class — the
# documented C0->C2 false positives. This sweep varies a single damping knob:
#
#     w_c(alpha) = (N / (K * n_c)) ** alpha        (normalized so min weight = 1)
#
#   alpha = 0.0  -> all weights 1        ("none": pure accuracy / logloss)
#   alpha = 0.5  -> sqrt-balanced        ("mild": partial minority emphasis)
#   alpha = 1.0  -> full 'balanced'      (current served setting)
#
# For each alpha we report CV accuracy AND CV macro-F1 (they usually move
# together here, not against each other) plus the two honest per-class F1s
# (C2, C3). Recipe is held at NEW; hybrid is OFF, to isolate the weight effect.
SWEEP_ALPHAS = (0.0, 0.25, 0.5, 0.75, 1.0)
_ALPHA_NAME = {0.0: "none", 0.25: "light", 0.5: "mild",
               0.75: "strong", 1.0: "balanced"}


def damped_class_weight(y, alpha):
    """Return a LightGBM class_weight dict damped by alpha (None when alpha=0)."""
    if alpha <= 0:
        return None
    classes, counts = np.unique(y, return_counts=True)
    N, K = len(y), len(classes)
    raw = {int(c): (N / (K * n)) ** alpha for c, n in zip(classes, counts)}
    lo = min(raw.values())                      # normalize so the floor is 1.0
    return {c: w / lo for c, w in raw.items()}


def make_lgbm_alpha(y_train, alpha):
    """NEW small-data params, but with class weighting damped by alpha."""
    return lgb.LGBMClassifier(
        objective="multiclass", num_class=5, boosting_type="gbdt",
        num_leaves=15, min_child_samples=5, reg_alpha=0.1, reg_lambda=1.0,
        n_estimators=300, learning_rate=0.03,
        class_weight=damped_class_weight(y_train, alpha),
        random_state=42, verbose=-1)


def cv_weight(X, y, alpha, n_splits=5):
    """Stratified k-fold; returns CV accuracy, CV macro-F1 and pooled per-class F1."""
    _, counts = np.unique(y, return_counts=True)
    k = int(min(n_splits, counts.min()))
    if k < 2:
        return None
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    accs, f1s, yt_all, yp_all = [], [], [], []
    for tr, te in skf.split(X, y):
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(X[tr]); Xte = scaler.transform(X[te])
        m = make_lgbm_alpha(y[tr], alpha); m.fit(Xtr, y[tr])
        pred = m.predict(Xte)
        accs.append(accuracy_score(y[te], pred))
        f1s.append(f1_score(y[te], pred, average="macro", zero_division=0))
        yt_all.extend(y[te].tolist()); yp_all.extend(pred.tolist())
    per = f1_score(yt_all, yp_all, average=None, labels=[0, 1, 2, 3, 4],
                   zero_division=0)
    return {"acc": float(np.mean(accs)), "acc_std": float(np.std(accs)),
            "f1": float(np.mean(f1s)), "f1_std": float(np.std(f1s)), "per": per}


def class_weight_sweep(X, y, alphas=SWEEP_ALPHAS):
    print("\n" + "=" * 66)
    print("CLASS-WEIGHT SWEEP (recipe fixed = NEW, hybrid OFF; varies weighting)")
    print("=" * 66)
    print("Damping alpha: 0=no weighting ... 1.0='balanced' (current served).")
    print(f"{'alpha':>6} {'weighting':>10} {'CV acc':>9} {'CV macroF1':>12}"
          f"{'C2 F1':>8}{'C3 F1':>8}")
    print("-" * 60)
    best = None
    for a in alphas:
        r = cv_weight(X, y, a)
        if r is None:
            print("  (too few samples in the rarest class for CV)")
            return
        star = _ALPHA_NAME.get(a, f"{a:.2f}")
        print(f"{a:>6.2f} {star:>10} {r['acc']*100:>8.1f}% {r['f1']*100:>10.1f}% "
              f"{r['per'][2]*100:>7.1f}%{r['per'][3]*100:>7.1f}%")
        # pick the alpha with the best CV macro-F1, tie-broken by accuracy
        key = (round(r["f1"], 4), round(r["acc"], 4))
        if best is None or key > best[0]:
            best = (key, a, r)
    (_, ba, br) = best
    print("-" * 60)
    print(f"Best CV macro-F1 at alpha={ba:.2f} ({_ALPHA_NAME.get(ba,'')}): "
          f"acc {br['acc']*100:.1f}%, macro-F1 {br['f1']*100:.1f}%.")
    print("If a LOWER alpha beats alpha=1.00 on BOTH columns, the served "
          "'balanced' setting is dominated — switch real mode to that alpha.\n"
          "Note: C1/C4 sit at ~100% by eventName leakage; the honest movers "
          "here are C2 and C3 (and overall accuracy).")


def augment_train_fold(X_raw, y, rng, target=HYBRID_TARGET):
    """
    Mirror of model.ThreatClassifier._augment_minorities for the A/B here.

    TRAIN-FOLD ONLY. For each minority class already PRESENT in the fold, mint
    real-faithful CloudTrail events (generate_real_faithful_event) up to `target`
    rows, featurize them through the SAME extractor as everything else, and
    append the RAW (pre-scaling) vectors. Classes absent from the fold are left
    alone — we never invent a class stratification didn't allocate here. The
    caller fits the scaler AFTER this, exactly as model.py does, so the minted
    rows are scaled together with the real train rows and the test fold (scaled
    with that same scaler) stays 100% real.
    """
    add_X, add_y = [], []
    for c in AUGMENT_CLASSES:
        have = int(np.sum(y == c))
        if have == 0:
            continue
        for _ in range(max(0, target - have)):
            ev = generate_real_faithful_event(c, rng)
            add_X.append(_AUG_PRE.extract_features_from_log(ev))
            add_y.append(c)
    if not add_X:
        return X_raw, y
    X_aug = np.vstack([X_raw, np.asarray(add_X, dtype=float)])
    y_aug = np.concatenate([np.asarray(y), np.asarray(add_y, dtype=y.dtype)])
    return X_aug, y_aug


def single_split(X, y, recipe, hybrid=False, target=HYBRID_TARGET):
    Xtr_raw, Xte_raw, ytr, yte = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)
    if hybrid:
        # Top up the train fold BEFORE scaling; test fold stays 100% real.
        Xtr_raw, ytr = augment_train_fold(
            Xtr_raw, ytr, np.random.default_rng(1234), target)
    scaler = StandardScaler()
    Xtr = scaler.fit_transform(Xtr_raw)
    Xte = scaler.transform(Xte_raw)
    if recipe == "old":
        # OLD path SMOTE-balanced the train fold (adaptive k for tiny classes).
        _, counts = np.unique(ytr, return_counts=True)
        if int(counts.min()) >= 2:
            from imblearn.over_sampling import SMOTE
            k = min(5, int(counts.min()) - 1)
            Xtr, ytr = SMOTE(k_neighbors=k, random_state=42).fit_resample(Xtr, ytr)
    m = make_lgbm(recipe)
    m.fit(Xtr, ytr)
    pred = m.predict(Xte)
    f1 = f1_score(yte, pred, average="macro", zero_division=0)
    rec = recall_score(yte, pred, average="macro", zero_division=0)
    per = f1_score(yte, pred, average=None, labels=[0, 1, 2, 3, 4], zero_division=0)
    return f1, rec, per


def cv_macro_f1(X, y, recipe, n_splits=5, hybrid=False, target=HYBRID_TARGET):
    _, counts = np.unique(y, return_counts=True)
    k = int(min(n_splits, counts.min()))
    if k < 2:
        return None, None
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    scores = []
    for fold, (tr, te) in enumerate(skf.split(X, y)):
        Xtr_raw, ytr = X[tr], y[tr]
        if hybrid:
            # Per-fold rng so each fold's top-up is independent but reproducible.
            Xtr_raw, ytr = augment_train_fold(
                Xtr_raw, ytr, np.random.default_rng(1000 + fold), target)
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(Xtr_raw); Xte = scaler.transform(X[te])
        if recipe == "old":
            _, c = np.unique(ytr, return_counts=True)
            if int(c.min()) >= 2:
                from imblearn.over_sampling import SMOTE
                kk = min(5, int(c.min()) - 1)
                Xtr, ytr = SMOTE(k_neighbors=kk, random_state=42).fit_resample(Xtr, ytr)
        m = make_lgbm(recipe)
        m.fit(Xtr, ytr)
        # Scored on the held-out fold, which stays 100% real even with hybrid.
        scores.append(f1_score(y[te], m.predict(Xte), average="macro", zero_division=0))
    scores = np.array(scores)
    return float(scores.mean()), float(scores.std())


def cv_per_class_f1(X, y, recipe, n_splits=5, hybrid=False, target=HYBRID_TARGET):
    """NEW-recipe per-class F1, aggregated across CV folds (pooled predictions)."""
    _, counts = np.unique(y, return_counts=True)
    k = int(min(n_splits, counts.min()))
    if k < 2:
        return None
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    y_true_all, y_pred_all = [], []
    for fold, (tr, te) in enumerate(skf.split(X, y)):
        Xtr_raw, ytr = X[tr], y[tr]
        if hybrid:
            Xtr_raw, ytr = augment_train_fold(
                Xtr_raw, ytr, np.random.default_rng(1000 + fold), target)
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(Xtr_raw); Xte = scaler.transform(X[te])
        m = make_lgbm(recipe); m.fit(Xtr, ytr)
        # Pool predictions on the pure-real held-out folds.
        y_true_all.extend(y[te].tolist()); y_pred_all.extend(m.predict(Xte).tolist())
    return f1_score(y_true_all, y_pred_all, average=None,
                    labels=[0, 1, 2, 3, 4], zero_division=0)


def feature_ablation(X, y, feature_names):
    """
    Isolate the FEATURE lift from the RECIPE lift: hold the recipe fixed (NEW)
    and compare CV macro-F1 with vs without the newly added feature columns.
    """
    idx_new = [i for i, n in enumerate(feature_names) if n in NEW_FEATURE_NAMES]
    print("\n" + "=" * 58)
    print("FEATURE ABLATION (recipe held fixed = NEW; varies feature set)")
    print("=" * 58)
    if not idx_new:
        print("No new-feature columns found in this dataset's vectors — "
              "nothing to ablate. (Are you on a build with the added features?)")
        return
    present = [feature_names[i] for i in idx_new]
    keep = [i for i in range(X.shape[1]) if i not in idx_new]
    X_base, X_full = X[:, keep], X

    base_m, base_s = cv_macro_f1(X_base, y, "new")
    full_m, full_s = cv_macro_f1(X_full, y, "new")
    print(f"New features present ({len(present)}): {', '.join(present)}")
    print(f"{'':22}{'without':>12}{'with':>12}{'delta':>10}")
    print("-" * 56)
    if base_m is not None:
        print(f"{'CV macro-F1':22}{base_m*100:>11.1f}%{full_m*100:>11.1f}%"
              f"{(full_m-base_m)*100:>+9.1f}")
        print(f"{'  (std)':22}{base_s*100:>10.1f}% {full_s*100:>10.1f}%")

    per_base = cv_per_class_f1(X_base, y, "new")
    per_full = cv_per_class_f1(X_full, y, "new")
    if per_base is not None:
        print("\nPer-class F1 (pooled over CV folds), feature effect:")
        print(f"{'class':16}{'without':>10}{'with':>10}{'delta':>10}")
        print("-" * 46)
        for i, name in enumerate(CLASS_LABELS):
            print(f"{name:16}{per_base[i]*100:>9.1f}%{per_full[i]*100:>9.1f}%"
                  f"{(per_full[i]-per_base[i])*100:>+9.1f}")
    print("\nThis delta is the pure feature contribution — it targets C1 "
          "(access-denied), C2 (sensitive-priv), C3 (credential-access), and "
          "C4 (lateral-movement).")


def hybrid_ab(X, y):
    """
    Isolate the HYBRID-AUGMENTATION lift: hold the recipe fixed (NEW) and
    compare real-only training against train-fold-only real-faithful top-up of
    the thin minority classes (C1/C2/C4). Every test/CV fold stays 100% real,
    so this is an honest read of what CPEDS_HYBRID_AUGMENT=1 buys you.
    """
    print("\n" + "=" * 58)
    print(f"HYBRID A/B (recipe fixed = NEW; train-fold top-up target "
          f"{HYBRID_TARGET}/class)")
    print("=" * 58)

    f1_r, rec_r, per_r = single_split(X, y, "new", hybrid=False)
    f1_h, rec_h, per_h = single_split(X, y, "new", hybrid=True)
    print(f"{'':22}{'real-only':>12}{'+hybrid':>12}{'delta':>10}")
    print("-" * 56)
    print(f"{'split macro-F1':22}{f1_r*100:>11.1f}%{f1_h*100:>11.1f}%"
          f"{(f1_h-f1_r)*100:>+9.1f}")
    print(f"{'split macro-rec':22}{rec_r*100:>11.1f}%{rec_h*100:>11.1f}%"
          f"{(rec_h-rec_r)*100:>+9.1f}")

    cvr_m, cvr_s = cv_macro_f1(X, y, "new", hybrid=False)
    cvh_m, cvh_s = cv_macro_f1(X, y, "new", hybrid=True)
    if cvr_m is not None:
        print(f"{'CV macro-F1':22}{cvr_m*100:>11.1f}%{cvh_m*100:>11.1f}%"
              f"{(cvh_m-cvr_m)*100:>+9.1f}")
        print(f"{'  (std)':22}{cvr_s*100:>10.1f}% {cvh_s*100:>10.1f}%")

    per_cr = cv_per_class_f1(X, y, "new", hybrid=False)
    per_ch = cv_per_class_f1(X, y, "new", hybrid=True)
    if per_cr is not None:
        print("\nPer-class F1 (pooled over CV folds), hybrid effect:")
        print(f"{'class':16}{'real-only':>11}{'+hybrid':>10}{'delta':>10}")
        print("-" * 47)
        for i, name in enumerate(CLASS_LABELS):
            print(f"{name:16}{per_cr[i]*100:>10.1f}%{per_ch[i]*100:>9.1f}%"
                  f"{(per_ch[i]-per_cr[i])*100:>+9.1f}")
    print("\nKeep hybrid ONLY if the CV macro-F1 row rises. Augmentation lifts "
          "C1/C2/C4 recall but can trade a little C0 precision — the CV row is "
          "the net honest verdict. Set CPEDS_HYBRID_AUGMENT=1 to enable it.")


def main():
    X, y, feature_names = load_dataset()
    print(f"{'':16}{'OLD (SMOTE)':>16}{'NEW (weighted)':>16}{'delta':>10}")
    print("-" * 58)

    f1_old, rec_old, per_old = single_split(X, y, "old")
    f1_new, rec_new, per_new = single_split(X, y, "new")
    print(f"{'split macro-F1':16}{f1_old*100:>15.1f}%{f1_new*100:>15.1f}%"
          f"{(f1_new-f1_old)*100:>+9.1f}")
    print(f"{'split macro-rec':16}{rec_old*100:>15.1f}%{rec_new*100:>15.1f}%"
          f"{(rec_new-rec_old)*100:>+9.1f}")

    cvo_m, cvo_s = cv_macro_f1(X, y, "old")
    cvn_m, cvn_s = cv_macro_f1(X, y, "new")
    if cvo_m is not None:
        print(f"{'CV macro-F1':16}{cvo_m*100:>15.1f}%{cvn_m*100:>15.1f}%"
              f"{(cvn_m-cvo_m)*100:>+9.1f}")
        print(f"{'  (std)':16}{cvo_s*100:>14.1f}% {cvn_s*100:>14.1f}%")

    print("\nPer-class F1 (held-out split):")
    print(f"{'class':16}{'OLD':>10}{'NEW':>10}{'delta':>10}")
    print("-" * 46)
    for i, name in enumerate(CLASS_LABELS):
        print(f"{name:16}{per_old[i]*100:>9.1f}%{per_new[i]*100:>9.1f}%"
              f"{(per_new[i]-per_old[i])*100:>+9.1f}")

    print("\nCite the CV macro-F1 row — it averages over folds and is the honest "
          "headline for imbalanced data.")

    # Isolate the feature lift (recipe held at NEW) from the recipe lift above.
    feature_ablation(X, y, feature_names)

    # Sweep the class-weight damping knob (alpha). Tests whether the served
    # 'balanced' (alpha=1) is dominated by a milder weighting on BOTH accuracy
    # and macro-F1 — the fix for the C2 over-prediction / low accuracy.
    class_weight_sweep(X, y)

    # Isolate the hybrid-augmentation lift (recipe held at NEW): real-only vs
    # train-fold-only real-faithful top-up of C1/C2/C4. Test folds stay real.
    hybrid_ab(X, y)


if __name__ == "__main__":
    main()
