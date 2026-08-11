"""
CPEDS-X: Cloud Privilege Escalation Detection System
ML Engine - GenAI Security Co-Pilot
Converts SHAP output into plain-English SOC incident summaries.
Uses OpenAI or local Ollama if configured; otherwise a template fallback.
"""
import os
import requests
from typing import Dict, List


# Human-readable descriptions for feature drivers
FEATURE_DESCRIPTIONS = {
    'priv_api_call_freq': 'high privileged API call frequency',
    'admin_policy_attach': 'administrative policy attachment',
    'off_hours_activity': 'off-hours administrative activity',
    'geo_anomaly_score': 'anomalous geographic access location',
    'api_burst_rate': 'abnormal API request burst rate',
    'data_exfil_volume_mb': 'large outbound data transfer volume',
    'lateral_movement_score': 'lateral movement indicators',
    'cross_account_access': 'cross-account resource access',
    'privilege_escalation_chain': 'chained privilege escalation pattern',
    'failed_auth_rate': 'elevated failed authentication rate',
    'mfa_disabled': 'multi-factor authentication disabled',
    'assume_role_freq': 'frequent role assumption calls',
    's3_sensitive_access': 'sensitive S3 bucket access',
    'kms_decrypt_freq': 'frequent KMS decryption operations',
}


def _describe_feature(feature_name: str) -> str:
    """Map a raw feature name to human-readable text."""
    return FEATURE_DESCRIPTIONS.get(feature_name, feature_name.replace('_', ' '))


def _severity_for_class(prediction_class: int) -> str:
    """Map class index to a SOC severity level."""
    return {
        0: "INFO",
        1: "WARNING",
        2: "CRITICAL",
        3: "CRITICAL",
        4: "HIGH",
    }.get(prediction_class, "WARNING")


def generate_soc_summary(prediction_class: int, class_label: str,
                         confidence: float, shap_features: List[Dict],
                         containment_time: float = None) -> str:
    """
    Generate a plain-English SOC incident summary.

    Tries OpenAI (if OPENAI_API_KEY set) then Ollama (if OLLAMA_URL set),
    falling back to a deterministic template that always works offline.
    """
    # Build driver phrases from top SHAP features that increase risk
    drivers = [
        _describe_feature(f['feature'])
        for f in shap_features
        if f.get('direction') == 'increases_risk'
    ][:3]
    drivers_text = ", ".join(drivers) if drivers else "aggregate anomaly indicators"

    # --- Attempt LLM providers ---
    prompt = (
        f"Write a concise 2-sentence SOC security incident summary. "
        f"Threat: {class_label}. Confidence: {confidence*100:.0f}%. "
        f"Top risk drivers: {drivers_text}. "
        f"Containment time: {containment_time}s. "
        f"Use a professional security-analyst tone."
    )

    llm_result = _try_llm_providers(prompt)
    if llm_result:
        return llm_result

    # --- Deterministic template fallback ---
    severity = _severity_for_class(prediction_class)
    conf_pct = f"{confidence*100:.0f}%"

    if prediction_class == 0:
        return (
            f"INFO: Activity classified as {class_label} with {conf_pct} confidence. "
            f"No malicious privilege escalation indicators detected. No action required."
        )

    action = ""
    if containment_time is not None:
        action = f" Action Taken: IAM tokens revoked in {containment_time}s."

    return (
        f"{severity} ALERT: {class_label} detected with {conf_pct} confidence. "
        f"Top drivers: {drivers_text}.{action}"
    )


def _try_llm_providers(prompt: str) -> str:
    """Try OpenAI, then Ollama. Return None if neither is available."""
    # OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {openai_key}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 120, "temperature": 0.3,
                },
                timeout=8,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

    # Ollama (local Llama 3)
    ollama_url = os.getenv("OLLAMA_URL")
    if ollama_url:
        try:
            resp = requests.post(
                f"{ollama_url}/api/generate",
                json={"model": "llama3", "prompt": prompt, "stream": False},
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
        except Exception:
            pass

    return None
