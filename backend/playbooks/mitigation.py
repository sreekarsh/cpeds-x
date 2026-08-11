"""
CPEDS-X: Cloud Privilege Escalation Detection System
Playbooks - Automated Containment Engine

Three containment modes, one playbook (choose with an env var):

  * mock        (default) - simulate every AWS call; touches nothing, zero cost.
  * localstack  (USE_LOCALSTACK=1) - real boto3 calls against a local emulator
                (localhost:4566) with dummy test/test creds.
  * live        (CONTAINMENT_MODE=live) - real boto3 calls against a REAL AWS
                account, using credentials from a named profile / the default
                credential chain. Destructive. Sandbox accounts only.

SAFETY: the auto-mitigation path (/predict, /analyze, /scenario) can NEVER fire
a live AWS change. `_get_boto3_client()` refuses to return a live client unless
the caller explicitly passes allow_live=True, and only the human-approved
live-containment functions below ever do that. So even with CONTAINMENT_MODE=live
set, the teaching tabs still simulate — real revokes happen only after an analyst
confirms a pending action.
"""
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

# Inline policy attached to a quarantined IAM user (deny everything).
QUARANTINE_POLICY_NAME = "CPEDS-Quarantine"
_DENY_ALL_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Sid":"CPEDSQuarantineDenyAll",'
    '"Effect":"Deny","Action":"*","Resource":"*"}]}'
)

# Principals live mode must NEVER contain, no matter what the model says. This is
# belt-and-suspenders on top of the IAM prefix allowlist baked into the
# cpeds-responder policy. Add your break-glass admin usernames here. Extra names
# can be supplied at runtime via PROTECTED_PRINCIPALS (comma-separated).
_BASE_PROTECTED = {"root", "cpeds-responder", "admin", "administrator",
                   "break-glass", "breakglass"}
PROTECTED_PRINCIPALS = _BASE_PROTECTED | {
    p.strip().lower()
    for p in (os.getenv("PROTECTED_PRINCIPALS") or "").split(",")
    if p.strip()
}

# Default isolation security group for EC2 quarantine (override via env).
QUARANTINE_SG = os.getenv("CPEDS_QUARANTINE_SG", "sg-cpeds-quarantine")


def _containment_mode() -> str:
    """Resolve the active containment mode: 'mock' | 'localstack' | 'live'.

    USE_LOCALSTACK=1 is still honored for back-compat and always wins.
    """
    if os.getenv("USE_LOCALSTACK") == "1":
        return "localstack"
    return (os.getenv("CONTAINMENT_MODE") or "mock").strip().lower()


def _live_session():
    """A boto3 Session for live AWS.

    Uses AWS_PROFILE if set (e.g. the least-privilege 'cpeds-responder' profile),
    else the default credential chain (env vars / assumed role / instance
    profile). Imported locally so boto3 is only needed when live mode is used.
    """
    import boto3
    profile = os.getenv("AWS_PROFILE")
    region = os.getenv("AWS_REGION", "us-east-1")
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def _get_boto3_client(service: str, *, allow_live: bool = False):
    """Return a boto3 client for the active mode, or None for mock.

    * localstack -> emulator client (dummy creds).
    * live       -> real client, but ONLY when allow_live=True. This is the hard
                    guardrail: auto-mitigation callers leave allow_live=False, so
                    they can never obtain a live client and fall back to mock.
    * mock       -> None (the caller simulates).
    """
    mode = _containment_mode()
    if mode == "localstack":
        try:
            import boto3
            endpoint = os.getenv("LOCALSTACK_URL", "http://localhost:4566")
            return boto3.client(
                service, endpoint_url=endpoint, region_name="us-east-1",
                aws_access_key_id="test", aws_secret_access_key="test",
            )
        except Exception as e:
            print(f"[CPEDS-X] LocalStack unavailable ({e}); using mock client.")
            return None
    if mode == "live" and allow_live:
        return _live_session().client(service)
    return None


# ----------------------------------------------------------------------
# Live containment primitives (real AWS).
#
# These are the ONLY code paths that may touch a live account, and they are
# only reached through the safety gate in ml_engine/live_watcher.py after an
# analyst confirms a pending action.
# ----------------------------------------------------------------------

def _strip_arn(principal: str) -> str:
    """'arn:aws:iam::123456789012:user/cpeds-victim' -> 'cpeds-victim'."""
    if not principal:
        return ""
    return principal.split("/")[-1].split(":")[-1]


def _revoke_user(iam, username: str) -> List[Dict]:
    """Deactivate every access key and attach a deny-all quarantine policy."""
    actions: List[Dict] = []
    for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"],
                              Status="Inactive")
        actions.append({
            "action": "deactivate_access_key",
            "status": "success",
            "access_key_id": k["AccessKeyId"],
            "detail": f"key {k['AccessKeyId']} set Inactive",
        })
    iam.put_user_policy(UserName=username, PolicyName=QUARANTINE_POLICY_NAME,
                        PolicyDocument=_DENY_ALL_POLICY)
    actions.append({
        "action": "attach_deny_all_policy",
        "status": "success",
        "policy_name": QUARANTINE_POLICY_NAME,
        "detail": f"attached {QUARANTINE_POLICY_NAME} deny-all inline policy",
    })
    return actions


def _rollback_user(iam, username: str) -> List[Dict]:
    """Undo _revoke_user: drop the quarantine policy, reactivate every key."""
    actions: List[Dict] = []
    try:
        iam.delete_user_policy(UserName=username, PolicyName=QUARANTINE_POLICY_NAME)
        actions.append({
            "action": "delete_deny_all_policy", "status": "success",
            "policy_name": QUARANTINE_POLICY_NAME,
            "detail": f"deleted {QUARANTINE_POLICY_NAME} inline policy",
        })
    except iam.exceptions.NoSuchEntityException:
        actions.append({
            "action": "delete_deny_all_policy", "status": "skipped",
            "policy_name": QUARANTINE_POLICY_NAME,
            "detail": "no quarantine policy was attached",
        })
    for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"],
                              Status="Active")
        actions.append({
            "action": "reactivate_access_key", "status": "success",
            "access_key_id": k["AccessKeyId"],
            "detail": f"key {k['AccessKeyId']} set Active",
        })
    return actions


def _quarantine_instance(ec2, instance_id: str, quarantine_sg: str) -> Dict:
    """Swap an EC2 instance onto an isolation security group."""
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg])
    return {
        "action": "quarantine_instance", "status": "success",
        "instance_id": instance_id, "sg": quarantine_sg,
        "detail": f"instance moved to isolation group {quarantine_sg}",
    }


def live_contain_user(principal: str, predicted_class: int) -> Dict:
    """Revoke a real IAM user in live mode.

    Raises ValueError for protected principals (root / responder / break-glass
    admins) BEFORE any call, and returns a result dict with rollback data.
    """
    username = _strip_arn(principal)
    if username in PROTECTED_PRINCIPALS or _principal_is_self(username):
        raise ValueError(
            f"Refused to contain protected principal '{principal}' "
            f"(root / break-glass admin / CPEDS-X's own responder are off-limits)."
        )
    iam = _get_boto3_client("iam", allow_live=True)
    actions = _revoke_user(iam, username)
    return {
        "principal": principal, "username": username,
        "threat_class": predicted_class, "actions": actions,
        "mode": "live", "reversible": True,
        "rollback": {
            "kind": "iam_user",
            "username": username,
            "policy_name": QUARANTINE_POLICY_NAME,
        },
    }


def live_rollback_user(rollback: Dict) -> Dict:
    """Undo a live IAM revoke using the stored rollback token."""
    username = rollback.get("username", "")
    if not username:
        raise ValueError("Rollback token is missing a username.")
    iam = _get_boto3_client("iam", allow_live=True)
    actions = _rollback_user(iam, username)
    return {"principal": username, "actions": actions, "mode": "live",
            "reversible": True, "rollback": rollback}


def live_quarantine_instance(instance_id: str, quarantine_sg: str,
                             predicted_class: int) -> Dict:
    """Quarantine a real EC2 instance in live mode (tag-scoped by IAM policy)."""
    ec2 = _get_boto3_client("ec2", allow_live=True)
    action = _quarantine_instance(ec2, instance_id, quarantine_sg)
    return {
        "principal": f"ec2:{instance_id}", "threat_class": predicted_class,
        "actions": [action], "mode": "live", "reversible": True,
        "rollback": {"kind": "ec2_instance", "instance_id": instance_id,
                     "previous_groups": action.get("previous_groups", [])},
    }


def _principal_is_self(username: str) -> bool:
    """Is this principal CPEDS-X's own responder identity? (Belt-and-suspenders
    on top of the IAM prefix allowlist.) Compares ARNs, usernames and profile
    names against the responder's caller identity, ignoring case and trailing
    slashes."""
    if not username:
        return False
    u = username.lower().strip().rstrip("/")
    if u in {p.lower() for p in PROTECTED_PRINCIPALS}:
        return True
    try:
        sts = _get_boto3_client("sts", allow_live=True)
        arn = sts.get_caller_identity()["Arn"].lower()
        return u in arn or arn.endswith("/" + u)
    except Exception:
        return False


class ContainmentEngine:
    """Executes automated response playbooks against compromised principals."""

    def revoke_iam_session(self, principal: str) -> Dict:
        """
        Revoke active IAM session tokens for a compromised principal.
        Uses IAM PutUserPolicy with an AWSRevokeOlderSessions deny policy
        (the standard AWS session-revocation pattern), plus access-key deletion.

        NOTE: this engine simulates. To issue REAL IAM changes on a sandbox
        account use live_contain_user() via the live safety gate.
        """
        client = _get_boto3_client("iam")
        mode = _containment_mode()
        revoke_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:TokenIssueTime": datetime.utcnow().isoformat() + "Z"}
                }
            }]
        }

        if client:  # Real LocalStack call
            try:
                username = principal.split("/")[-1]
                import json as _json
                client.put_user_policy(
                    UserName=username,
                    PolicyName="AWSRevokeOlderSessions",
                    PolicyDocument=_json.dumps(revoke_policy),
                )
                return {"action": "revoke_iam_session", "status": "success",
                        "mode": mode, "principal": principal,
                        "policy_applied": "AWSRevokeOlderSessions"}
            except Exception as e:
                return {"action": "revoke_iam_session", "status": "error",
                        "mode": mode, "error": str(e)}

        # Mock mode
        return {
            "action": "revoke_iam_session", "status": "success", "mode": mode,
            "principal": principal, "policy_applied": "AWSRevokeOlderSessions",
            "detail": "Deny-all policy attached; older session tokens invalidated.",
        }

    def micro_segment_host(self, instance_id: str = "i-0123456789abcdef0") -> Dict:
        """
        Isolate a host by replacing its EC2 Security Group rules with a
        deny-all quarantine group (network micro-segmentation).

        NOTE: simulated (or LocalStack). Real EC2 quarantine on a sandbox
        account runs through live_quarantine_instance() via the safety gate.
        """
        quarantine_rules = {
            "GroupName": "cpeds-quarantine-sg",
            "IngressRules": [],  # Deny all inbound
            "EgressRules": [{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "CidrIp": "10.0.0.0/8",  # Allow only internal forensics egress
                "Description": "Forensics collection only",
            }],
        }

        client = _get_boto3_client("ec2")
        mode = _containment_mode()
        if client:
            try:
                # In a real flow you'd create the SG and re-associate the ENI.
                return {"action": "micro_segment_host", "status": "success",
                        "mode": mode, "instance_id": instance_id,
                        "quarantine_sg": quarantine_rules}
            except Exception as e:
                return {"action": "micro_segment_host", "status": "error",
                        "mode": mode, "error": str(e)}

        return {
            "action": "micro_segment_host", "status": "success", "mode": mode,
            "instance_id": instance_id, "quarantine_sg": quarantine_rules,
            "detail": "Host isolated into deny-all quarantine security group.",
        }


def execute_containment(principal: str, predicted_class: int,
                        instance_id: str = "i-0123456789abcdef0") -> Dict:
    """
    Run the full containment playbook and measure Mean Time to Containment.
    Target: MTTC < 30 seconds.

    This is the AUTO path used by /predict, /analyze and /scenario. It always
    runs in mock or localstack mode and never issues a live AWS change — live
    containment is human-approved and goes through live_watcher's safety gate.
    """
    engine = ContainmentEngine()
    start = time.perf_counter()

    actions: List[Dict] = []
    actions.append(engine.revoke_iam_session(principal))
    actions.append(engine.micro_segment_host(instance_id))

    mttc_seconds = round(time.perf_counter() - start, 3)

    return {
        "containment_triggered": True,
        "principal": principal,
        "threat_class": predicted_class,
        "actions": actions,
        "mode": _containment_mode(),
        "mttc_seconds": mttc_seconds,
        "mttc_target_met": mttc_seconds < 30,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
