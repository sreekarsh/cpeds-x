"""
CPEDS-X: Cloud Privilege Escalation Detection System
ML Engine - Feature Preprocessor
Handles 28-feature extraction, scaling, and SMOTE rebalancing
"""
import numpy as np
import pandas as pd
from datetime import datetime, time
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from imblearn.over_sampling import SMOTE
from typing import Dict, List, Tuple
import json


class FeaturePreprocessor:
    """Extracts and normalizes 28 security features from CloudTrail audit logs"""

    def __init__(self):
        self.scaler = StandardScaler()
        self.minmax_scaler = MinMaxScaler()
        self.smote = SMOTE(k_neighbors=5, random_state=42)
        self.feature_names = self._get_feature_names()

    def _get_feature_names(self) -> List[str]:
        """Returns the 28 canonical feature names"""
        return [
            'login_freq_1h', 'login_freq_24h', 'failed_auth_rate',
            'resource_entropy', 'priv_api_call_freq', 'admin_policy_attach',
            'assume_role_freq', 'cross_account_access', 'mfa_disabled',
            'geo_anomaly_score', 'off_hours_activity', 'weekend_activity',
            'api_burst_rate', 'data_exfil_volume_mb', 'iam_change_freq',
            'security_group_mod', 'unusual_ip_count', 's3_sensitive_access',
            'kms_decrypt_freq', 'secret_access_freq', 'privilege_escalation_chain',
            'lateral_movement_score', 'user_account_age_days', 'role_session_duration_min',
            'console_login_anomaly', 'cli_tool_usage', 'suspicious_user_agent',
            'anomaly_aggregate_score'
        ]

    def extract_features_from_log(self, audit_log: Dict) -> np.ndarray:
        """
        Extracts 28 features from a single CloudTrail audit log entry

        Args:
            audit_log: Raw JSON CloudTrail event

        Returns:
            28-dimensional feature vector
        """
        features = {}

        # Parse event metadata
        event_time_str = audit_log.get('eventTime', datetime.now().isoformat())
        # CloudTrail uses 'Z' suffix; fromisoformat can't handle it in Python 3.10
        if event_time_str.endswith('Z'):
            event_time_str = event_time_str[:-1] + '+00:00'
        event_time = datetime.fromisoformat(event_time_str)
        event_name = audit_log.get('eventName', '')
        user_identity = audit_log.get('userIdentity', {})
        source_ip = audit_log.get('sourceIPAddress', '')
        user_agent = audit_log.get('userAgent', '')

        # Feature 1-3: Login and auth patterns
        features['login_freq_1h'] = audit_log.get('login_freq_1h', 0)
        features['login_freq_24h'] = audit_log.get('login_freq_24h', 0)
        features['failed_auth_rate'] = audit_log.get('failed_auth_rate', 0.0)

        # Feature 4: Resource access entropy (Shannon entropy of accessed resources)
        features['resource_entropy'] = self._calculate_entropy(
            audit_log.get('accessed_resources', [])
        )

        # Feature 5-6: Privileged operations
        features['priv_api_call_freq'] = 1 if event_name in [
            'CreateAccessKey', 'PutUserPolicy', 'AttachUserPolicy', 'CreateRole'
        ] else 0
        features['admin_policy_attach'] = 1 if 'AttachUserPolicy' in event_name else 0

        # Feature 7-8: Role assumption and cross-account
        features['assume_role_freq'] = 1 if event_name == 'AssumeRole' else 0
        features['cross_account_access'] = 1 if audit_log.get('recipientAccountId') != audit_log.get('accountId') else 0

        # Feature 9: MFA status
        features['mfa_disabled'] = 0 if user_identity.get('mfaAuthenticated') == 'true' else 1

        # Feature 10: Geolocation anomaly (mock Z-score)
        features['geo_anomaly_score'] = audit_log.get('geo_anomaly_score', 0.0)

        # Feature 11-12: Temporal anomalies
        features['off_hours_activity'] = 1 if self._is_off_hours(event_time) else 0
        features['weekend_activity'] = 1 if event_time.weekday() >= 5 else 0

        # Feature 13: API burst detection
        features['api_burst_rate'] = audit_log.get('api_burst_rate', 0.0)

        # Feature 14: Data exfiltration volume
        features['data_exfil_volume_mb'] = audit_log.get('data_exfil_volume_mb', 0.0)

        # Feature 15-16: Configuration changes
        features['iam_change_freq'] = 1 if any(x in event_name for x in ['Create', 'Delete', 'Update', 'Put']) else 0
        features['security_group_mod'] = 1 if 'SecurityGroup' in event_name else 0

        # Feature 17: Unusual source IPs
        features['unusual_ip_count'] = audit_log.get('unusual_ip_count', 0)

        # Feature 18-20: Sensitive resource access
        features['s3_sensitive_access'] = 1 if 's3' in audit_log.get('eventSource', '').lower() else 0
        features['kms_decrypt_freq'] = 1 if event_name == 'Decrypt' else 0
        features['secret_access_freq'] = 1 if 'secretsmanager' in audit_log.get('eventSource', '') else 0

        # Feature 21-22: Attack pattern indicators
        features['privilege_escalation_chain'] = audit_log.get('privilege_escalation_chain', 0)
        features['lateral_movement_score'] = audit_log.get('lateral_movement_score', 0.0)

        # Feature 23-24: User profile
        features['user_account_age_days'] = audit_log.get('user_account_age_days', 365)
        features['role_session_duration_min'] = audit_log.get('role_session_duration_min', 60)

        # Feature 25-27: Access method anomalies
        features['console_login_anomaly'] = 1 if 'ConsoleLogin' in event_name and features['off_hours_activity'] == 1 else 0
        features['cli_tool_usage'] = 1 if 'aws-cli' in user_agent.lower() or 'boto3' in user_agent.lower() else 0
        features['suspicious_user_agent'] = 1 if user_agent == '' or 'python' in user_agent.lower() else 0

        # Feature 28: Aggregate anomaly score (composite)
        features['anomaly_aggregate_score'] = (
            features['geo_anomaly_score'] * 0.3 +
            features['off_hours_activity'] * 0.2 +
            features['api_burst_rate'] * 0.25 +
            features['lateral_movement_score'] * 0.25
        )

        # Convert to ordered array matching feature_names
        return np.array([features[name] for name in self.feature_names])

    def _calculate_entropy(self, resource_list: List[str]) -> float:
        """Calculate Shannon entropy of resource access patterns"""
        if not resource_list:
            return 0.0

        counts = pd.Series(resource_list).value_counts()
        probs = counts / counts.sum()
        return -np.sum(probs * np.log2(probs + 1e-10))

    def _is_off_hours(self, dt: datetime) -> bool:
        """Check if time is outside business hours (9 AM - 6 PM)"""
        return dt.time() < time(9, 0) or dt.time() > time(18, 0)

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit scaler and transform features"""
        return self.scaler.fit_transform(X)

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform features using fitted scaler"""
        return self.scaler.transform(X)

    def apply_smote(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Apply SMOTE to balance classes.

        k_neighbors is chosen ADAPTIVELY from the smallest class so real,
        unevenly-sized datasets never crash SMOTE (which requires
        k_neighbors < the count of the rarest class). Synthetic data is evenly
        sized, so this reduces to the usual k=5. If the rarest class is too
        small to synthesize from at all, SMOTE is skipped and the original
        (X, y) is returned unchanged rather than raising.
        """
        # Only training calls this; inference never does.
        _, counts = np.unique(y, return_counts=True)
        min_count = int(counts.min())
        if min_count < 2:
            # Can't synthesize neighbours for a singleton class; skip cleanly.
            return X, y
        k = min(5, min_count - 1)
        smote = SMOTE(k_neighbors=k, random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)
        return X_resampled, y_resampled


def generate_synthetic_audit_log(threat_class: int = 0, randomize: bool = False,
                                  rng=None) -> Dict:
    """
    Generate synthetic CloudTrail-style audit log.

    Args:
        threat_class: 0=Benign, 1=Horizontal, 2=Vertical, 3=Exfil, 4=Lateral
        randomize:    when False (default) returns the canonical, deterministic
                      template for the class — used by /simulate and the demo so
                      results are predictable. When True, samples the numeric
                      fields from realistic, deliberately OVERLAPPING ranges so
                      the training/test distributions reflect real-world
                      ambiguity (adjacent threat classes share feature space).
                      This is what makes the measured metrics honest instead of
                      a trivial ~100%.
        rng:          optional numpy Generator (for reproducible randomization).

    Returns:
        Synthetic audit log dictionary
    """
    if randomize and rng is None:
        rng = np.random.default_rng()

    base_log = {
        'eventVersion': '1.08',
        'eventTime': datetime.now().isoformat(),
        'eventName': 'DescribeInstances',
        'eventSource': 'ec2.amazonaws.com',
        'userIdentity': {
            'type': 'IAMUser',
            'principalId': 'AIDAI23HXK2LMQ',
            'arn': 'arn:aws:iam::123456789012:user/alice',
            'accountId': '123456789012',
            'userName': 'alice',
            'mfaAuthenticated': 'true'
        },
        'sourceIPAddress': '203.0.113.42',
        'userAgent': 'aws-cli/2.13.0',
        'accountId': '123456789012',
        'recipientAccountId': '123456789012',
        'login_freq_1h': 2,
        'login_freq_24h': 12,
        'failed_auth_rate': 0.0,
        'accessed_resources': ['i-0123456789abcdef0'],
        'geo_anomaly_score': 0.1,
        'api_burst_rate': 5.0,
        'data_exfil_volume_mb': 0.0,
        'unusual_ip_count': 1,
        'privilege_escalation_chain': 0,
        'lateral_movement_score': 0.0,
        'user_account_age_days': 180,
        'role_session_duration_min': 60
    }

    # Modify based on threat class
    if threat_class == 1:  # C1: Horizontal Escalation
        base_log.update({
            'eventName': 'AssumeRole',
            'eventSource': 'sts.amazonaws.com',
            'login_freq_1h': 8,
            'failed_auth_rate': 0.25,
            'geo_anomaly_score': 1.8,
            'off_hours_activity': 1
        })
        # Assumed-role escalation without MFA — keep the principal's identity
        # intact and just flip the MFA flag. (Only mfaAuthenticated is read as a
        # feature, so preserving arn/userName is display-only and behaviour-safe.)
        base_log['userIdentity']['mfaAuthenticated'] = 'false'
    elif threat_class == 2:  # C2: Vertical Escalation
        base_log.update({
            'eventName': 'AttachUserPolicy',
            'eventSource': 'iam.amazonaws.com',
            'priv_api_call_freq': 5,
            'admin_policy_attach': 1,
            'iam_change_freq': 3,
            'privilege_escalation_chain': 1,
            'api_burst_rate': 25.0,
            'geo_anomaly_score': 2.5
        })
    elif threat_class == 3:  # C3: Data Exfiltration
        base_log.update({
            'eventName': 'GetObject',
            'eventSource': 's3.amazonaws.com',
            'data_exfil_volume_mb': 1250.0,
            's3_sensitive_access': 1,
            'api_burst_rate': 120.0,
            'unusual_ip_count': 3,
            'lateral_movement_score': 0.7
        })
    elif threat_class == 4:  # C4: Lateral Movement
        base_log.update({
            'eventName': 'DescribeInstances',
            'recipientAccountId': '987654321098',  # Cross-account
            'cross_account_access': 1,
            'lateral_movement_score': 0.95,
            'unusual_ip_count': 5,
            'geo_anomaly_score': 3.2,
            'privilege_escalation_chain': 1
        })

    # ------------------------------------------------------------------
    # Optional realistic randomization (training/eval only).
    #
    # The canonical templates above are cleanly separable, which is why a model
    # trained and tested on them scores ~100% — not a credible result. When
    # `randomize` is on we jitter the numeric drivers with wide, overlapping
    # spreads so neighbouring classes genuinely share feature space (e.g. a
    # stealthy exfil can look like benign; horizontal and vertical escalation
    # blur). The event NAME is kept as the class template so feature extraction
    # stays valid; only the behavioural magnitudes move.
    # ------------------------------------------------------------------
    if randomize:
        def jitter(mean, spread, lo=0.0, hi=None):
            val = float(rng.normal(mean, spread))
            val = max(lo, val)
            if hi is not None:
                val = min(hi, val)
            return round(val, 3)

        # Per-class behavioural profiles: (mean, spread) chosen to OVERLAP.
        profiles = {
            0: {'geo': (0.3, 0.6), 'burst': (6, 8), 'exfil': (5, 40),
                'lat': (0.05, 0.15), 'fail': (0.02, 0.05), 'login1h': (2, 2)},
            1: {'geo': (1.4, 1.0), 'burst': (12, 12), 'exfil': (10, 60),
                'lat': (0.2, 0.25), 'fail': (0.18, 0.15), 'login1h': (7, 4)},
            2: {'geo': (2.0, 1.1), 'burst': (22, 18), 'exfil': (20, 80),
                'lat': (0.3, 0.3), 'fail': (0.12, 0.12), 'login1h': (5, 4)},
            3: {'geo': (1.6, 1.2), 'burst': (90, 60), 'exfil': (900, 700),
                'lat': (0.6, 0.35), 'fail': (0.08, 0.1), 'login1h': (4, 4)},
            4: {'geo': (2.6, 1.3), 'burst': (30, 30), 'exfil': (40, 120),
                'lat': (0.85, 0.3), 'fail': (0.1, 0.12), 'login1h': (5, 5)},
        }
        p = profiles[threat_class]
        base_log['geo_anomaly_score'] = jitter(*p['geo'], lo=0.0, hi=5.0)
        base_log['api_burst_rate'] = jitter(*p['burst'], lo=0.0)
        base_log['data_exfil_volume_mb'] = jitter(*p['exfil'], lo=0.0)
        base_log['lateral_movement_score'] = jitter(*p['lat'], lo=0.0, hi=1.0)
        base_log['failed_auth_rate'] = jitter(*p['fail'], lo=0.0, hi=1.0)
        base_log['login_freq_1h'] = int(jitter(*p['login1h'], lo=0.0))
        base_log['unusual_ip_count'] = int(jitter(1 + threat_class, 2.0, lo=0.0))
        # MFA is frequently on even during attacks and occasionally off when benign.
        mfa_off_prob = [0.05, 0.5, 0.5, 0.35, 0.55][threat_class]
        base_log['userIdentity'] = dict(base_log.get('userIdentity', {}))
        base_log['userIdentity']['mfaAuthenticated'] = (
            'false' if rng.random() < mfa_off_prob else 'true'
        )

        # ---- Break the eventName label-leak -------------------------------
        # In the canonical templates each class maps to ONE signature API call
        # (only C2 attaches policies, only C3 touches S3, etc.), so the derived
        # binary features perfectly reveal the class. Real life isn't like that:
        # admins legitimately attach policies, and attackers hide inside benign
        # calls like DescribeInstances. So we draw the event from OVERLAPPING
        # per-class distributions — the same API can appear in several classes.
        EVENTS = {
            'DescribeInstances': ('ec2.amazonaws.com', False),
            'GetObject':         ('s3.amazonaws.com', False),
            'AssumeRole':        ('sts.amazonaws.com', False),
            'AttachUserPolicy':  ('iam.amazonaws.com', False),
            'CreateAccessKey':   ('iam.amazonaws.com', False),
            'ConsoleLogin':      ('signin.amazonaws.com', False),
        }
        event_mix = {
            0: [('DescribeInstances', 0.45), ('GetObject', 0.20), ('ConsoleLogin', 0.15),
                ('AssumeRole', 0.12), ('AttachUserPolicy', 0.08)],
            1: [('AssumeRole', 0.45), ('ConsoleLogin', 0.20), ('DescribeInstances', 0.20),
                ('CreateAccessKey', 0.15)],
            2: [('AttachUserPolicy', 0.42), ('CreateAccessKey', 0.20), ('AssumeRole', 0.16),
                ('DescribeInstances', 0.22)],
            3: [('GetObject', 0.52), ('DescribeInstances', 0.26), ('AssumeRole', 0.12),
                ('AttachUserPolicy', 0.10)],
            4: [('DescribeInstances', 0.48), ('AssumeRole', 0.24), ('GetObject', 0.16),
                ('AttachUserPolicy', 0.12)],
        }[threat_class]
        names = [e[0] for e in event_mix]
        weights = np.array([e[1] for e in event_mix], dtype=float)
        weights /= weights.sum()
        chosen = names[int(rng.choice(len(names), p=weights))]
        base_log['eventName'] = chosen
        base_log['eventSource'] = EVENTS[chosen][0]

        # Cross-account access is a strong-but-imperfect lateral-movement signal:
        # common in C4, but it happens occasionally in other classes too.
        xacct_prob = [0.02, 0.10, 0.10, 0.08, 0.6][threat_class]
        if rng.random() < xacct_prob:
            base_log['recipientAccountId'] = '987654321098'
        else:
            base_log['recipientAccountId'] = base_log.get('accountId', '123456789012')

    return base_log
