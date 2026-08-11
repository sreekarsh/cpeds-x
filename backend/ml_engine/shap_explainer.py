"""
CPEDS-X: Cloud Privilege Escalation Detection System
ML Engine - SHAP Explainer
Computes local Shapley values and returns top-5 risk features per alert
"""
import numpy as np
import shap
from typing import Dict, List


class ShapExplainer:
    """
    Wraps SHAP TreeExplainer over the primary LightGBM model to produce
    local (per-alert) feature attributions.
    """

    def __init__(self, model, feature_names: List[str]):
        self.feature_names = feature_names
        # TreeExplainer is exact & fast for gradient-boosted trees
        self.explainer = shap.TreeExplainer(model)

    def explain(self, scaled_features: List[float], predicted_class: int,
                top_k: int = 5) -> Dict:
        """
        Compute SHAP values for a single prediction.

        Args:
            scaled_features: The scaled 28-vector used for prediction
            predicted_class: The class index to explain
            top_k: Number of top contributing features to return

        Returns:
            Dict with top-k features, their SHAP values, and direction
        """
        X = np.array(scaled_features).reshape(1, -1)

        # shap_values for multiclass: list of arrays (one per class)
        shap_values = self.explainer.shap_values(X)

        # Handle both old (list) and new (ndarray) SHAP output formats
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class][0]
        else:
            # ndarray shape (n_samples, n_features, n_classes)
            class_shap = shap_values[0, :, predicted_class]

        # Rank by absolute contribution
        abs_vals = np.abs(class_shap)
        top_idx = np.argsort(abs_vals)[::-1][:top_k]

        top_features = []
        for idx in top_idx:
            top_features.append({
                'feature': self.feature_names[idx],
                'shap_value': round(float(class_shap[idx]), 4),
                'contribution': round(float(abs_vals[idx]), 4),
                'direction': 'increases_risk' if class_shap[idx] > 0 else 'decreases_risk'
            })

        return {
            'predicted_class': predicted_class,
            'top_features': top_features,
            'base_value': round(float(np.mean(self.explainer.expected_value)), 4)
        }


# Global singleton
_explainer = None


def get_explainer(model, feature_names: List[str]) -> ShapExplainer:
    """Return (and lazily build) the global SHAP explainer singleton."""
    global _explainer
    if _explainer is None:
        _explainer = ShapExplainer(model, feature_names)
    return _explainer
