"""
CPEDS-X — sandbox fixtures for the live-AWS demo loop.

This module automates the *fixture* half of the Live AWS Runbook (Parts D, E, F):
creating a throwaway "attacker" IAM user, making it perform a CloudTrail-visible
action that CPEDS-X will flag, inspecting its state, and tearing it back down.

It is the CLI equivalent of the hand-typed `aws iam ...` commands in the runbook,
so the whole demo — setup -> attack -> poll -> contain -> undo -> teardown — can
run from `cpeds` instead of PowerShell.

WHAT THIS DOES NOT DO
---------------------
It never contains anything and never edits or imports the live-containment code
paths. Detection, the safety gate, and the real IAM revoke still live entirely in
`ml_engine/live_watcher.py` + `playbooks/mitigation.py`, untouched. This module
only *creates and deletes the target* those paths later act on. It talks to AWS
through its own boto3 session.

SAFETY (mirrors the guardrails around live containment)
-------------------------------------------------------
1. Sandbox-prefix guard — every mutating call refuses any username that does not
   start with SANDBOX_PREFIX ("cpeds-"), so it can only ever touch throwaway demo
   identities, never a real principal.
2. Protected-principals denylist — the exact set live containment refuses (root,
   cpeds-responder, admin, break-glass, ...) is refused here too, even though
   those aren't sandbox names, so `setup`/`teardown` can never be aimed at them.
3. Account preview — callers can print the STS caller identity (which real
   account they're about to write to) before committing, exactly like
   `cpeds live status`.
4. Secrets are returned once, in memory — a freshly minted secret access key is
   handed back to the caller (which prints it once) and is never written to disk.

These operations require IAM write permissions (CreateUser / CreateAccessKey /
DeleteUser). Point them at a SANDBOX account only, via a profile that actually
holds those permissions (the runbook's `cpeds-responder` with IAMFullAccess, or a
dedicated admin profile).
"""
from __future__ import annotations

import os
import time
from typing import Dict, List, Optional

# Only ever operate on throwaway demo identities whose name starts with this.
SANDBOX_PREFIX = os.getenv("CPEDS_SANDBOX_PREFIX", "cpeds-")

# The managed policy the runbook attaches so the victim can "escalate".
DEFAULT_VICTIM_POLICY_ARN = "arn:aws:iam::aws:policy/IAMFullAccess"

# The admin policy the victim self-attaches in a C2 (vertical) attack. The victim
# already holds IAMFullAccess (so iam:AttachUserPolicy is permitted), which is
# exactly the misconfiguration that lets it grant itself full admin.
DEFAULT_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# The secret id a C3 (exfil) attack tries to read. It does NOT need to exist and
# the victim is NOT granted access to it — the call is expected to be AccessDenied
# (or ResourceNotFound), which STILL records a GetSecretValue event in CloudTrail
# without anything actually being read. Override with CPEDS_EXFIL_SECRET_ID.
DEFAULT_EXFIL_SECRET_ID = os.getenv("CPEDS_EXFIL_SECRET_ID",
                                    "cpeds-sandbox-nonexistent-secret")

# Managed policies teardown will detach if present (best-effort).
_TEARDOWN_DETACH_ARNS = [
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess",
]

# The inline quarantine policy live containment may have attached. Teardown
# removes it too so a user contained mid-demo can still be deleted.
_QUARANTINE_POLICY_NAME = "CPEDS-Quarantine"


# ----------------------------------------------------------------------
# Attack kinds — the different CloudTrail-visible actions the victim can take.
# Each entry says which API call to make, what CPEDS-X should classify it as,
# and how confidently the *live* loop is expected to catch it (an honest note,
# because a real GetSecretValue lacks the synthetic exfil-volume signal).
# ----------------------------------------------------------------------
ATTACK_KINDS = {
    "horizontal": {
        "event_name": "CreateAccessKey",
        "expected_class": 1,
        "expected_label": "C1 Horizontal Escalation",
        "live_visible": True,
        "summary": "mint a second access key for the victim (persistence)",
        "note": "CloudTrail attributes CreateAccessKey to the victim; expect a "
                "confident C1 Pending verdict after ~5-15 min of CloudTrail lag.",
    },
    "vertical": {
        "event_name": "AttachUserPolicy",
        "expected_class": 2,
        "expected_label": "C2 Vertical Escalation",
        "live_visible": True,
        "summary": "self-attach AdministratorAccess (privilege escalation)",
        "note": "The victim uses its IAMFullAccess to grant itself "
                "AdministratorAccess — a textbook C2. Expect a confident C2 "
                "Pending verdict after CloudTrail lag. Teardown detaches it.",
    },
    "exfil": {
        "event_name": "GetSecretValue",
        "expected_class": 3,
        "expected_label": "C3 Data Exfiltration",
        "live_visible": True,
        "summary": "attempt to read a Secrets Manager secret (data access)",
        "note": "AccessDenied-safe: the victim has NO secrets permission, so this "
                "is expected to be denied — nothing is actually read, but the "
                "GetSecretValue attempt STILL appears in CloudTrail. Because real "
                "logs lack the synthetic exfil-volume signal, the live model may "
                "score this borderline (possibly below the 0.75 gate) — for a "
                "confident C3 demo use the Log Analysis tab on the real dataset.",
    },
}

# Aliases so a user can say the class code or a synonym.
_KIND_ALIASES = {
    "c1": "horizontal", "1": "horizontal", "horizontal": "horizontal",
    "persist": "horizontal", "persistence": "horizontal", "key": "horizontal",
    "c2": "vertical", "2": "vertical", "vertical": "vertical",
    "escalate": "vertical", "admin": "vertical", "privesc": "vertical",
    "c3": "exfil", "3": "exfil", "exfil": "exfil", "exfiltration": "exfil",
    "secret": "exfil", "secrets": "exfil", "read": "exfil",
}

DEFAULT_ATTACK_KIND = "horizontal"


def _resolve_attack_kind(kind: Optional[str]) -> str:
    """Normalize a user-supplied kind ('c2', 'vertical', '2', …) to a canonical
    key, or raise SandboxError listing the valid choices."""
    if not kind:
        return DEFAULT_ATTACK_KIND
    key = _KIND_ALIASES.get(str(kind).strip().lower())
    if not key:
        raise SandboxError(
            f"unknown attack kind '{kind}'. Choose one of: "
            f"{', '.join(ATTACK_KINDS)} (or C1/C2/C3).")
    return key


def describe_attack(kind: Optional[str] = None) -> Dict:
    """Return the metadata for an attack kind (for CLI previews), plus its
    canonical key. Raises SandboxError for an unknown kind."""
    key = _resolve_attack_kind(kind)
    spec = dict(ATTACK_KINDS[key])
    spec["kind"] = key
    return spec


class SandboxError(Exception):
    """Raised for any refused or failed sandbox-fixture operation."""


# ----------------------------------------------------------------------
# Protected-principals denylist — reuse live mode's single source of truth
# so the two can never drift. This is a read-only import of a constant; it
# does not modify or invoke the containment path.
# ----------------------------------------------------------------------
def _protected_principals() -> set:
    try:
        from playbooks.mitigation import PROTECTED_PRINCIPALS
        return set(PROTECTED_PRINCIPALS)
    except Exception:
        # Self-contained fallback if the import ever fails; keep in sync with
        # playbooks.mitigation._BASE_PROTECTED.
        base = {"root", "cpeds-responder", "admin", "administrator",
                "break-glass", "breakglass"}
        extra = {p.strip().lower()
                 for p in (os.getenv("PROTECTED_PRINCIPALS") or "").split(",")
                 if p.strip()}
        return base | extra


def _strip_arn(principal: str) -> str:
    """'arn:aws:iam::123:user/cpeds-victim' -> 'cpeds-victim'. Also tolerates a
    bare username."""
    if not principal:
        return ""
    return principal.split("/")[-1].split(":")[-1]


def assert_safe_name(username: str) -> str:
    """Validate a target username against BOTH guards, or raise SandboxError.

    Returns the normalized (ARN-stripped) username on success. Checks the
    protected denylist first so a protected name can never slip through even if
    it happens to match the sandbox prefix.
    """
    name = _strip_arn(username).strip()
    if not name:
        raise SandboxError("no username given.")
    if name.lower() in _protected_principals():
        raise SandboxError(
            f"'{name}' is a protected principal (root / responder / admin / "
            "break-glass) and is off-limits to the sandbox tool.")
    if not name.startswith(SANDBOX_PREFIX):
        raise SandboxError(
            f"refusing to operate on '{name}': sandbox fixtures only touch "
            f"throwaway users whose name starts with '{SANDBOX_PREFIX}'. "
            f"Use e.g. '{SANDBOX_PREFIX}victim'.")
    return name


# ----------------------------------------------------------------------
# boto3 session / client helpers (lazy import; boto3 only needed when used)
# ----------------------------------------------------------------------
def _session(profile: Optional[str] = None, region: Optional[str] = None):
    """A boto3 Session for real AWS.

    profile: explicit named profile (e.g. 'cpeds-responder'); falls back to
    AWS_PROFILE, then the default credential chain. region defaults to
    AWS_REGION or us-east-1 — matching playbooks.mitigation._live_session().
    """
    try:
        import boto3
    except Exception as e:  # pragma: no cover - env dependent
        raise SandboxError(
            f"boto3 is not installed in this environment ({e}). Install it in "
            "the project venv to use sandbox fixtures.")
    region = region or os.getenv("AWS_REGION", "us-east-1")
    profile = profile or os.getenv("AWS_PROFILE")
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def _session_from_keys(access_key_id: str, secret_access_key: str,
                       region: Optional[str] = None):
    """A boto3 Session bound to explicit credentials (the victim's own keys),
    so an action is attributed to that identity in CloudTrail."""
    try:
        import boto3
    except Exception as e:  # pragma: no cover - env dependent
        raise SandboxError(f"boto3 is not installed ({e}).")
    region = region or os.getenv("AWS_REGION", "us-east-1")
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region,
    )


def whoami(profile: Optional[str] = None, region: Optional[str] = None) -> Dict:
    """Return the caller identity for the profile — the real account about to be
    written to. Never raises for a bad profile; returns an error dict instead so
    callers can preview safely."""
    try:
        sts = _session(profile, region).client("sts")
        ident = sts.get_caller_identity()
        return {"ok": True,
                "account": ident.get("Account"),
                "arn": ident.get("Arn"),
                "region": region or os.getenv("AWS_REGION", "us-east-1"),
                "profile": profile or os.getenv("AWS_PROFILE")}
    except SandboxError as e:
        return {"ok": False, "reason": str(e)}
    except Exception as e:
        return {"ok": False,
                "reason": f"credentials not usable ({e}). Configure the profile "
                          "with `aws configure --profile <name>`."}


# ----------------------------------------------------------------------
# D1 — create the throwaway victim
# ----------------------------------------------------------------------
def setup_victim(username: str = "cpeds-victim",
                 profile: Optional[str] = None,
                 region: Optional[str] = None,
                 policy_arn: str = DEFAULT_VICTIM_POLICY_ARN,
                 attach_policy: bool = True) -> Dict:
    """Create the demo 'attacker' user, attach an escalation policy, mint a key.

    Idempotent-ish: if the user or attachment already exists, that step is
    reported as 'exists' rather than failing. Returns the user's fresh access
    key (id + secret) so the caller can drive the attack step; the secret is in
    memory only.
    """
    name = assert_safe_name(username)
    iam = _session(profile, region).client("iam")
    actions: List[Dict] = []

    # 1. create the user
    try:
        iam.create_user(UserName=name)
        actions.append({"action": "create_user", "status": "success",
                        "detail": f"created IAM user {name}"})
    except iam.exceptions.EntityAlreadyExistsException:
        actions.append({"action": "create_user", "status": "exists",
                        "detail": f"user {name} already existed; reused"})

    # 2. attach the escalation policy (so it can later "escalate")
    if attach_policy:
        try:
            iam.attach_user_policy(UserName=name, PolicyArn=policy_arn)
            actions.append({"action": "attach_user_policy", "status": "success",
                            "detail": f"attached {policy_arn}"})
        except Exception as e:
            actions.append({"action": "attach_user_policy", "status": "error",
                            "detail": f"could not attach {policy_arn}: {e}"})

    # 3. mint an access key for the user (this is its "password")
    key = iam.create_access_key(UserName=name)["AccessKey"]
    actions.append({"action": "create_access_key", "status": "success",
                    "detail": f"created access key {key['AccessKeyId']}"})

    return {
        "username": name,
        "access_key_id": key["AccessKeyId"],
        "secret_access_key": key["SecretAccessKey"],
        "policy_arn": policy_arn if attach_policy else None,
        "actions": actions,
    }


# ----------------------------------------------------------------------
# D2 — make the attack happen (as the victim, so CloudTrail blames it)
# ----------------------------------------------------------------------
def _err_code(exc: Exception) -> str:
    """Best-effort AWS error code (botocore ClientError), else the class name —
    lowercased, for classifying an exception as transient / expected / fatal."""
    try:
        code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
        if code:
            return str(code).lower()
    except Exception:
        pass
    return exc.__class__.__name__.lower()


def _do_horizontal(session, name: str) -> Dict:
    """C1: mint a second access key for the victim (persistence)."""
    made = session.client("iam").create_access_key(UserName=name)["AccessKey"]
    return {"made_access_key_id": made["AccessKeyId"]}


def _do_vertical(session, name: str, admin_policy_arn: str) -> Dict:
    """C2: the victim self-attaches AdministratorAccess (privilege escalation).
    attach_user_policy is idempotent, so a retry after a transient error is safe."""
    session.client("iam").attach_user_policy(
        UserName=name, PolicyArn=admin_policy_arn)
    return {"attached_policy_arn": admin_policy_arn}


def _do_exfil(session, name: str, secret_id: str) -> Dict:
    """C3: attempt GetSecretValue AS the victim. AccessDenied-safe — the victim
    has no secrets permission, so this is expected to be denied and reads nothing,
    but the attempt is still recorded in CloudTrail. A credential-propagation
    error (fresh key) is re-raised so the caller can retry it."""
    sm = session.client("secretsmanager")
    try:
        sm.get_secret_value(SecretId=secret_id)
        # Unexpected: perms + secret both present. Do NOT return the material.
        return {"secret_id": secret_id, "denied": False,
                "detail": "GetSecretValue unexpectedly succeeded; the sandbox "
                          "withholds the secret value and reads nothing further."}
    except Exception as e:
        code = _err_code(e)
        if "accessdenied" in code or "resourcenotfound" in code:
            # Expected, terminal, and CloudTrail-visible — this IS the attack.
            return {"secret_id": secret_id, "denied": True, "error_code": code,
                    "detail": f"GetSecretValue was {code} (expected) — the attempt "
                              "is still recorded in CloudTrail as victim data access."}
        raise  # propagation / throttle / other → let the retry loop decide


def run_attack(username: str = "cpeds-victim",
               *,
               kind: str = DEFAULT_ATTACK_KIND,
               victim_profile: Optional[str] = None,
               access_key_id: Optional[str] = None,
               secret_access_key: Optional[str] = None,
               region: Optional[str] = None,
               secret_id: Optional[str] = None,
               admin_policy_arn: str = DEFAULT_ADMIN_POLICY_ARN,
               retries: int = 6,
               retry_wait: float = 5.0) -> Dict:
    """Perform a CloudTrail-visible attack action AS the victim.

    `kind` selects which action (all attributed to the victim in CloudTrail):
      • horizontal (C1) — CreateAccessKey: mint a second key (persistence).
      • vertical   (C2) — AttachUserPolicy: self-attach AdministratorAccess.
      • exfil      (C3) — GetSecretValue: attempt a data read (AccessDenied-safe;
        reads nothing, but the attempt is logged). See ATTACK_KINDS[...]["note"].

    horizontal and vertical are actions the victim is *authorized* to do (it holds
    IAMFullAccess), so they generate clean, high-signal events. exfil is deliberately
    *unauthorized* — it proves a data-access attempt reaches the live loop even
    though the model may score it below the containment gate.

    The call must be attributed to the victim, so it runs with the victim's own
    identity — either a configured profile (victim_profile) or explicit keys
    (access_key_id/secret_access_key, e.g. the ones setup_victim just returned).

    A just-minted key can take a few seconds to become valid, so an auth failure
    is retried with a short backoff. Any extra key/attachment this creates is left
    for teardown to clean up (teardown deletes ALL keys and detaches all managed
    policies, including AdministratorAccess).
    """
    name = assert_safe_name(username)
    key = _resolve_attack_kind(kind)
    spec = ATTACK_KINDS[key]

    if victim_profile:
        session = _session(victim_profile, region)
    elif access_key_id and secret_access_key:
        session = _session_from_keys(access_key_id, secret_access_key, region)
    else:
        raise SandboxError(
            "run_attack needs the victim's identity: pass victim_profile or "
            "access_key_id + secret_access_key.")

    sid = secret_id or DEFAULT_EXFIL_SECRET_ID

    def _perform() -> Dict:
        if key == "horizontal":
            return _do_horizontal(session, name)
        if key == "vertical":
            return _do_vertical(session, name, admin_policy_arn)
        return _do_exfil(session, name, sid)

    last_err: Optional[Exception] = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            extra = _perform()
            result = {
                "username": name,
                "kind": key,
                "event_name": spec["event_name"],
                "expected_class": spec["expected_class"],
                "expected_label": spec["expected_label"],
                "attempts": attempt,
                "note": spec["note"],
            }
            result.update(extra)
            return result
        except Exception as e:  # new-key propagation delay, throttling, etc.
            last_err = e
            code = _err_code(e)
            transient = any(t in code for t in
                            ("invalidclienttoken", "accessdenied",
                             "signaturedoesnotmatch", "throttl",
                             "unrecognizedclient"))
            if attempt < retries and transient:
                time.sleep(retry_wait)
                continue
            break
    raise SandboxError(
        f"attack action ({key}) failed after {retries} attempt(s): {last_err}. "
        "If this was a fresh key, it may not have propagated yet — retry, or run "
        "the attack with --victim-profile pointing at a configured profile.")


# ----------------------------------------------------------------------
# E — verify (prove the real change before/after containment)
# ----------------------------------------------------------------------
def verify(username: str = "cpeds-victim",
           profile: Optional[str] = None,
           region: Optional[str] = None) -> Dict:
    """Report the victim's access-key statuses and attached policies.

    Read-only. Run it before/after `live contain` to watch keys flip
    Active -> Inactive and the CPEDS-Quarantine policy appear/disappear. The
    prefix guard is applied even though this reads nothing destructive, for
    consistency.
    """
    name = assert_safe_name(username)
    iam = _session(profile, region).client("iam")
    try:
        keys = [{"access_key_id": k["AccessKeyId"], "status": k["Status"]}
                for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]]
        inline = iam.list_user_policies(UserName=name)["PolicyNames"]
        managed = [p["PolicyName"] for p in
                   iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]]
    except iam.exceptions.NoSuchEntityException:
        raise SandboxError(f"user {name} does not exist (nothing to verify).")
    return {
        "username": name,
        "access_keys": keys,
        "inline_policies": inline,
        "managed_policies": managed,
        "contained": _QUARANTINE_POLICY_NAME in inline,
    }


# ----------------------------------------------------------------------
# F — teardown (fully delete the throwaway user)
# ----------------------------------------------------------------------
def teardown(username: str = "cpeds-victim",
             profile: Optional[str] = None,
             region: Optional[str] = None) -> Dict:
    """Delete every access key, inline policy and managed attachment, then the
    user. Idempotent: missing pieces are reported 'skipped', not errors, so it's
    safe to re-run or to run on a half-created user."""
    name = assert_safe_name(username)
    iam = _session(profile, region).client("iam")
    actions: List[Dict] = []

    # user gone already?
    try:
        iam.get_user(UserName=name)
    except iam.exceptions.NoSuchEntityException:
        return {"username": name, "actions": [
            {"action": "delete_user", "status": "skipped",
             "detail": f"user {name} did not exist"}]}

    # 1. access keys
    try:
        for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=name, AccessKeyId=k["AccessKeyId"])
            actions.append({"action": "delete_access_key", "status": "success",
                            "detail": f"deleted key {k['AccessKeyId']}"})
    except Exception as e:
        actions.append({"action": "delete_access_key", "status": "error",
                        "detail": str(e)})

    # 2. inline policies (incl. the quarantine policy if contained mid-demo)
    try:
        for pol in iam.list_user_policies(UserName=name)["PolicyNames"]:
            iam.delete_user_policy(UserName=name, PolicyName=pol)
            actions.append({"action": "delete_user_policy", "status": "success",
                            "detail": f"deleted inline policy {pol}"})
    except Exception as e:
        actions.append({"action": "delete_user_policy", "status": "error",
                        "detail": str(e)})

    # 3. detach managed policies (best-effort over the known set + anything left)
    try:
        attached = [p["PolicyArn"] for p in
                    iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]]
    except Exception:
        attached = list(_TEARDOWN_DETACH_ARNS)
    for arn in attached:
        try:
            iam.detach_user_policy(UserName=name, PolicyArn=arn)
            actions.append({"action": "detach_user_policy", "status": "success",
                            "detail": f"detached {arn}"})
        except Exception as e:
            name_l = e.__class__.__name__.lower()
            status = "skipped" if "nosuchentity" in name_l else "error"
            actions.append({"action": "detach_user_policy", "status": status,
                            "detail": f"{arn}: {e}"})

    # 4. delete the user
    try:
        iam.delete_user(UserName=name)
        actions.append({"action": "delete_user", "status": "success",
                        "detail": f"deleted user {name}"})
    except Exception as e:
        actions.append({"action": "delete_user", "status": "error",
                        "detail": str(e)})

    return {"username": name, "actions": actions}
