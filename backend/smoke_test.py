"""
CPEDS-X - Offline smoke test
Runs the FULL pipeline (feature extraction -> model -> SHAP -> co-pilot ->
mitigation) WITHOUT starting the web server. Run this after `pip install`
to confirm your environment is healthy.

    cd backend
    python smoke_test.py
"""
import sys


def main():
    print("=" * 60)
    print("CPEDS-X SMOKE TEST")
    print("=" * 60)

    # 1. Imports
    try:
        from ml_engine.model import get_classifier, CLASS_LABELS
        from ml_engine.shap_explainer import get_explainer
        from ml_engine.genai_copilot import generate_soc_summary
        from ml_engine.preprocessor import generate_synthetic_audit_log
        from playbooks.mitigation import execute_containment
        print("[1/6] Imports............................ OK")
    except Exception as e:
        print(f"[1/6] Imports FAILED: {e}")
        sys.exit(1)

    # 2. Train model (real training on synthetic data)
    try:
        clf = get_classifier()
        assert clf.is_trained
        print(f"[2/6] Model training..................... OK  {clf.measured_metrics}")
    except Exception as e:
        print(f"[2/6] Training FAILED: {e}")
        sys.exit(1)

    # 3. Prediction on each class
    try:
        for cls in range(5):
            log = generate_synthetic_audit_log(cls)
            result = clf.predict(log)
            print(f"      class C{cls} -> predicted {result['class_label']} "
                  f"({result['confidence']*100:.1f}%, {result['execution_latency_ms']}ms)")
        print("[3/6] Prediction......................... OK")
    except Exception as e:
        print(f"[3/6] Prediction FAILED: {e}")
        sys.exit(1)

    # 4. SHAP explanation
    try:
        log = generate_synthetic_audit_log(2)
        result = clf.predict(log)
        explainer = get_explainer(clf.lgbm_model, clf.preprocessor.feature_names)
        shap_result = explainer.explain(result['scaled_features'], result['predicted_class'])
        top = shap_result['top_features'][0]
        print(f"[4/6] SHAP explainer..................... OK  top='{top['feature']}'")
    except Exception as e:
        print(f"[4/6] SHAP FAILED: {e}")
        sys.exit(1)

    # 5. GenAI co-pilot
    try:
        summary = generate_soc_summary(2, "C2: Vertical Escalation", 0.97,
                                       shap_result['top_features'], 1.8)
        print(f"[5/6] GenAI co-pilot..................... OK")
        print(f"      \"{summary}\"")
    except Exception as e:
        print(f"[5/6] Co-pilot FAILED: {e}")
        sys.exit(1)

    # 6. Mitigation playbook
    try:
        mit = execute_containment("arn:aws:iam::123:user/alice", 2)
        assert mit['mttc_target_met']
        print(f"[6/6] Mitigation playbook................ OK  MTTC={mit['mttc_seconds']}s")
    except Exception as e:
        print(f"[6/6] Mitigation FAILED: {e}")
        sys.exit(1)

    print("=" * 60)
    print("ALL CHECKS PASSED ✓  Backend is healthy.")
    print("Start the server with:  uvicorn main:app --reload --port 8000")
    print("=" * 60)


if __name__ == "__main__":
    main()
