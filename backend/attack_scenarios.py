"""
CPEDS-X: Attack Scenario Runner — purple-team campaigns.

A "scenario" is a named, multi-step privilege-escalation campaign. Each step is
mapped to a MITRE ATT&CK technique and produces a CloudTrail-shaped event that
is fed through the SAME trained classifier the live simulator uses. The result
is a purple-team loop: emulate an attacker's kill-chain, watch CPEDS-X classify
each action, and see auto-containment fire on the steps that cross the
confidence threshold.

Design notes
------------
* Events are built from the deterministic (non-randomized) class templates in
  ml_engine.preprocessor, then overridden per step. That keeps all 28 features
  valid while making each step's API call specific to its technique — so the
  demo is reliable and each step reads like a real attacker action.
* The intended `threat_class` on a step only seeds the event; the verdict shown
  to the operator is always the model's real prediction. Early recon steps are
  expected to read benign (and correctly NOT be contained) — that honest mix is
  what makes the timeline credible.
* Optional real execution: with USE_LOCALSTACK=1 and LocalStack running, each
  step can also fire the emulated AWS API against localhost:4566 for realism.
  LocalStack does not emit CloudTrail, so the detection event is constructed
  either way; the boto3 call is best-effort and never affects detection. This
  path NEVER touches live AWS — dummy test/test creds against localhost only.

Orchestration (predict -> SHAP -> containment -> persist) lives in main.py; this
module stays free of ML/auth imports so there is no circular dependency.
"""
import copy
import os
from typing import Dict, List, Optional

from ml_engine.preprocessor import generate_synthetic_audit_log


def _deep_merge(base: dict, overrides: dict) -> dict:
    """Recursively merge `overrides` onto a copy of `base` (dicts only)."""
    out = copy.deepcopy(base)
    for k, v in (overrides or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def build_step_event(step: Dict, principal: str, source_ip: str) -> Dict:
    """
    Construct the CloudTrail event for one scenario step.

    Seeds from the deterministic template for the step's intended threat class
    (so every numeric feature is present), applies the step's event overrides,
    then stamps the campaign's attacker principal and source IP so containment
    targets the right identity.
    """
    base = generate_synthetic_audit_log(step.get("threat_class", 0), randomize=False)
    event = _deep_merge(base, step.get("event", {}))

    # Stamp the attacker identity + origin consistently across the campaign.
    ui = dict(event.get("userIdentity", {}))
    ui["arn"] = principal
    ui.setdefault("type", "IAMUser")
    ui["userName"] = principal.split("/")[-1]
    event["userIdentity"] = ui
    if source_ip:
        event["sourceIPAddress"] = source_ip
    return event


# ======================================================================
# Scenario catalog
# ======================================================================
# Each step's `threat_class` only SEEDS the CloudTrail event from the matching
# deterministic template; the verdict the operator sees is always the model's
# real prediction. Recon steps seed class 0 and are expected to read benign (and
# correctly escape containment) — that honest mix is the point of a purple-team
# timeline. The "loud" steps keep their class-signature API call so the trained
# classifier reliably flags and contains them.
SCENARIOS: List[Dict] = [
    {
        "id": "iam-privilege-escalation",
        "name": "IAM Privilege Escalation",
        "tactic": "Privilege Escalation",
        "summary": (
            "A low-privilege contractor identity quietly maps its own access, "
            "plants a persistence key, then attaches AdministratorAccess to "
            "itself and pivots into a privileged role."
        ),
        "attacker_principal": "arn:aws:iam::123456789012:user/contractor-temp",
        "source_ip": "185.220.101.47",
        "steps": [
            {
                "name": "Enumerate own IAM permissions",
                "technique_id": "T1087.004",
                "technique": "Account Discovery: Cloud Account",
                "tactic": "Discovery",
                "description": "Reads its own attached policies to find a path up.",
                "threat_class": 0,
                "event": {
                    "eventName": "GetAccountAuthorizationDetails",
                    "eventSource": "iam.amazonaws.com",
                },
                "localstack": {"service": "iam", "call": "list_users"},
            },
            {
                "name": "Enumerate assumable roles",
                "technique_id": "T1069.003",
                "technique": "Permission Groups Discovery: Cloud Groups",
                "tactic": "Discovery",
                "description": "Lists roles it might assume for lateral or vertical movement.",
                "threat_class": 0,
                "event": {
                    "eventName": "ListRoles",
                    "eventSource": "iam.amazonaws.com",
                },
                "localstack": {"service": "iam", "call": "list_roles"},
            },
            {
                "name": "Create a second access key (persistence)",
                "technique_id": "T1098.001",
                "technique": "Account Manipulation: Additional Cloud Credentials",
                "tactic": "Persistence",
                "description": "Mints a fresh access key so access survives a password reset.",
                "threat_class": 2,
                "event": {
                    "eventName": "CreateAccessKey",
                    "eventSource": "iam.amazonaws.com",
                },
                "localstack": {"service": "iam", "call": "create_access_key"},
            },
            {
                "name": "Attach AdministratorAccess to self",
                "technique_id": "T1548.005",
                "technique": "Abuse Elevation Control Mechanism: Cloud Policy",
                "tactic": "Privilege Escalation",
                "description": "Self-attaches the AdministratorAccess managed policy — full takeover.",
                "threat_class": 2,
                "event": {
                    "eventName": "AttachUserPolicy",
                    "eventSource": "iam.amazonaws.com",
                    "requestParameters": {
                        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "userName": "contractor-temp",
                    },
                },
                "localstack": {"service": "iam", "call": "attach_user_policy"},
            },
            {
                "name": "Assume a privileged role",
                "technique_id": "T1078.004",
                "technique": "Valid Accounts: Cloud Accounts",
                "tactic": "Privilege Escalation",
                "description": "Trades the new admin rights for a privileged role session.",
                "threat_class": 1,
                "event": {
                    "eventName": "AssumeRole",
                    "eventSource": "sts.amazonaws.com",
                },
                "localstack": {"service": "sts", "call": "get_caller_identity"},
            },
        ],
    },
    {
        "id": "credential-exfiltration",
        "name": "Compromised Credentials → Data Exfiltration",
        "tactic": "Exfiltration",
        "summary": (
            "Stolen credentials sign in from an unusual location, hunt for "
            "secrets, then bulk-download a sensitive S3 bucket."
        ),
        "attacker_principal": "arn:aws:iam::123456789012:user/analytics-svc",
        "source_ip": "45.155.205.233",
        "steps": [
            {
                "name": "Console login from unusual geo",
                "technique_id": "T1078.004",
                "technique": "Valid Accounts: Cloud Accounts",
                "tactic": "Initial Access",
                "description": "A valid-but-stolen credential signs in from a new country.",
                "threat_class": 1,
                "event": {
                    "eventName": "ConsoleLogin",
                    "eventSource": "signin.amazonaws.com",
                    "userIdentity": {"mfaAuthenticated": "false"},
                },
                "localstack": {"service": "sts", "call": "get_caller_identity"},
            },
            {
                "name": "Enumerate S3 buckets",
                "technique_id": "T1619",
                "technique": "Cloud Storage Object Discovery",
                "tactic": "Discovery",
                "description": "Lists buckets to locate sensitive datasets.",
                "threat_class": 0,
                "event": {
                    "eventName": "ListBuckets",
                    "eventSource": "s3.amazonaws.com",
                },
                "localstack": {"service": "s3", "call": "list_buckets"},
            },
            {
                "name": "Retrieve secrets from Secrets Manager",
                "technique_id": "T1552.001",
                "technique": "Unsecured Credentials: Credentials In Files",
                "tactic": "Credential Access",
                "description": "Pulls stored secrets to widen access.",
                "threat_class": 2,
                "event": {
                    "eventName": "GetSecretValue",
                    "eventSource": "secretsmanager.amazonaws.com",
                },
                "localstack": {"service": "secretsmanager", "call": "list_secrets"},
            },
            {
                "name": "Bulk-download sensitive bucket",
                "technique_id": "T1530",
                "technique": "Data from Cloud Storage",
                "tactic": "Exfiltration",
                "description": "Mass GetObject of a sensitive prefix — ~1.2 GB egress.",
                "threat_class": 3,
                "event": {
                    "eventName": "GetObject",
                    "eventSource": "s3.amazonaws.com",
                },
                "localstack": {"service": "s3", "call": "list_buckets"},
            },
        ],
    },
    {
        "id": "cross-account-lateral",
        "name": "Cross-Account Lateral Movement",
        "tactic": "Lateral Movement",
        "summary": (
            "An attacker with a foothold enumerates infrastructure, assumes a "
            "role into a second account, and sweeps hosts there."
        ),
        "attacker_principal": "arn:aws:iam::123456789012:user/ci-deployer",
        "source_ip": "91.219.236.19",
        "steps": [
            {
                "name": "Enumerate EC2 instances",
                "technique_id": "T1580",
                "technique": "Cloud Infrastructure Discovery",
                "tactic": "Discovery",
                "description": "Maps compute in the current account.",
                "threat_class": 0,
                "event": {
                    "eventName": "DescribeInstances",
                    "eventSource": "ec2.amazonaws.com",
                },
                "localstack": {"service": "ec2", "call": "describe_instances"},
            },
            {
                "name": "Assume role into a second account",
                "technique_id": "T1550.001",
                "technique": "Use Alternate Authentication Material: App Access Token",
                "tactic": "Lateral Movement",
                "description": "Crosses an account trust boundary via AssumeRole.",
                "threat_class": 1,
                "event": {
                    "eventName": "AssumeRole",
                    "eventSource": "sts.amazonaws.com",
                    "recipientAccountId": "987654321098",
                },
                "localstack": {"service": "sts", "call": "get_caller_identity"},
            },
            {
                "name": "Sweep hosts in the target account",
                "technique_id": "T1021.007",
                "technique": "Remote Services: Cloud Services",
                "tactic": "Lateral Movement",
                "description": "Cross-account DescribeInstances — the lateral pivot.",
                "threat_class": 4,
                "event": {
                    "eventName": "DescribeInstances",
                    "eventSource": "ec2.amazonaws.com",
                },
                "localstack": {"service": "ec2", "call": "describe_instances"},
            },
        ],
    },
]

_SCENARIO_INDEX = {s["id"]: s for s in SCENARIOS}


def list_scenarios() -> List[Dict]:
    """Return catalog metadata (no per-step events) for the picker UI."""
    out = []
    for s in SCENARIOS:
        out.append({
            "id": s["id"],
            "name": s["name"],
            "tactic": s["tactic"],
            "summary": s["summary"],
            "step_count": len(s["steps"]),
            "techniques": [st["technique_id"] for st in s["steps"]],
        })
    return out


def get_scenario(scenario_id: str) -> Optional[Dict]:
    """Return the full scenario definition, or None if the id is unknown."""
    return _SCENARIO_INDEX.get(scenario_id)


def maybe_execute_localstack(step: Dict) -> Optional[Dict]:
    """
    Best-effort real execution against LocalStack (localhost:4566) when
    USE_LOCALSTACK=1. Returns a small status dict, or None in mock mode.

    NEVER targets live AWS: endpoint is forced to LocalStack with dummy
    test/test creds. Any failure is caught and reported — a scenario must run
    end to end whether or not LocalStack is up.
    """
    if os.getenv("USE_LOCALSTACK") != "1":
        return None

    hint = step.get("localstack")
    if not hint:
        return {"mode": "localstack", "status": "skipped", "reason": "no call for this step"}

    service, call = hint.get("service"), hint.get("call")
    try:
        import boto3
        endpoint = os.getenv("LOCALSTACK_URL", "http://localhost:4566")
        client = boto3.client(
            service, endpoint_url=endpoint, region_name="us-east-1",
            aws_access_key_id="test", aws_secret_access_key="test",
        )
        fn = getattr(client, call, None)
        if fn is None:
            return {"mode": "localstack", "status": "skipped",
                    "reason": f"{service}.{call} not available"}
        fn()  # read-only enumeration calls; discard the (emulated) result
        return {"mode": "localstack", "status": "executed", "call": f"{service}.{call}"}
    except Exception as e:  # pragma: no cover - depends on LocalStack being up
        return {"mode": "localstack", "status": "error", "call": f"{service}.{call}",
                "error": str(e)}
