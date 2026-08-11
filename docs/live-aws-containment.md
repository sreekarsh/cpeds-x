# 🛰️ CPEDS-X — Live AWS Containment: Real-World Implementation Guide

This guide takes CPEDS-X from *simulated* containment to a **real, working live loop**
against a genuine AWS account: an attacker performs real privilege-escalation API
calls → AWS CloudTrail records them → CPEDS-X ingests those logs → the model
classifies the threat → CPEDS-X issues a **real IAM revoke** to contain it.

It is written as a step-by-step build guide that plugs into your existing code
(`playbooks/mitigation.py`, `ml_engine/log_ingest.py`, the `clf.predict()` pipeline,
and the incident-history store). Mock and LocalStack modes stay exactly as they are —
this adds a third mode alongside them.

---

## 🚨 The one rule (read this first)

> **Use a dedicated, throwaway AWS "sandbox" account for live mode — never a
> production account, never an account with anything real in it.**

Live containment issues genuinely destructive IAM/EC2 changes. Your model overlaps
classes *by design* and **will** misfire on some benign events. Every guardrail in
this guide exists so a false positive costs you nothing but a click to undo. If you
skip the guardrails, skip live mode.

Before you start, on the sandbox account: enable MFA on the root user, set a
**billing alarm at $1**, and put everything in one region (e.g. `us-east-1`).

---

## 🗺️ Architecture of the live loop

```
┌─────────────┐   real API calls   ┌────────────┐   records    ┌──────────────┐
│  Attacker   │ ─────────────────▶ │  AWS APIs  │ ───────────▶ │  CloudTrail  │
│ (test user) │  iam:AttachUser…   │ IAM / EC2  │              │   (sensor)   │
└─────────────┘                    └────────────┘              └──────┬───────┘
                                                                      │ poll
                                                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  CPEDS-X backend (live_watcher)                                              │
│   1. LookupEvents  ─▶  2. parse_logs()  ─▶  3. clf.predict()  ─▶  threat?    │
│                                                          │                   │
│   4. SAFETY GATE (confidence ≥ 0.75 · class ≠ C0 · analyst approves)         │
│                                                          │                   │
│   5. execute_containment(mode="live")  ─▶  real boto3  ─▶ IAM revoke /       │
│                                                            EC2 quarantine    │
│   6. record incident + rollback token                                       │
└────────────────────────────────────────────────────────────────────────────┘
```

The only new moving parts are a **credential/role setup**, a **live branch inside
`mitigation.py`**, a **`live_watcher` poller**, and a **safety gate**. Everything else
(parser, classifier, SHAP, incident history) is code you already have.

---

## ✅ Prerequisites

- A **separate** AWS sandbox account (not your main one).
- AWS CLI v2 installed locally (`aws --version`).
- Your CPEDS-X backend running via `.venv\Scripts\python.exe -m uvicorn main:app --port 8000`.
- `boto3` (already in `requirements.txt`).

---

## Step 1 — Enable CloudTrail (the sensor / "the eyes")

CloudTrail is what turns real attacker API calls into logs your model can read.

1. AWS Console → **CloudTrail → Create trail**.
2. Name it `cpeds-trail`, apply to the current region, log **Management events**
   (Read + Write). This is enough to catch IAM/EC2 privilege-escalation calls.
3. Let it create an S3 bucket for storage (fine for a sandbox).

**How you'll read it — pick one:**

| Path | Latency | Setup | Use for |
|------|---------|-------|---------|
| **`cloudtrail:LookupEvents` API polling** *(recommended v1)* | ~5–15 min | Zero extra infra | First working version |
| CloudTrail → **CloudWatch Logs** + `logs:FilterLogEvents` | ~1–5 min | Enable log delivery | Faster loop |
| **EventBridge** rule → HTTP webhook to your backend | near-real-time | Most setup | A polished live demo |

Start with **LookupEvents polling** — it's a single API call, no extra infrastructure,
and it's honest about the latency AWS actually gives you.

---

## Step 2 — Create two IAM identities (the app's hands + the victim)

### 2a. The containment role/user (CPEDS-X's own least-privilege identity)

Create an IAM user `cpeds-responder` with **only** the actions the loop needs, scoped
by name-prefix and resource tag so it *physically cannot* touch anything outside the
sandbox's test resources. This tag/prefix scoping is your allowlist guardrail baked
into AWS itself — defense in depth, so even a bug can't run wild.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTelemetry",
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents", "sts:GetCallerIdentity"],
      "Resource": "*"
    },
    {
      "Sid": "ContainOnlyCpedsTestUsers",
      "Effect": "Allow",
      "Action": ["iam:UpdateAccessKey", "iam:PutUserPolicy", "iam:ListAccessKeys"],
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:user/cpeds-*"
    },
    {
      "Sid": "QuarantineOnlyTaggedInstances",
      "Effect": "Allow",
      "Action": ["ec2:ModifyInstanceAttribute", "ec2:DescribeInstances"],
      "Resource": "*",
      "Condition": { "StringEquals": { "aws:ResourceTag/cpeds-managed": "true" } }
    }
  ]
}
```

Generate an access key for `cpeds-responder`. **Do not paste it into code.** Put it in
your local environment or `~/.aws/credentials` under a named profile:

```ini
# ~/.aws/credentials     (Windows: C:\Users\admin\.aws\credentials)
[cpeds-responder]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-east-1
```

> 🔒 Better still: give the app an *assumed role* via `sts:AssumeRole` so it runs on
> short-lived temporary credentials instead of a long-lived key. Do this once the
> key-based version works.

### 2b. The victim user (what the attacker "compromises")

Create `cpeds-victim` with modest starting permissions (e.g. read-only). This is the
identity you'll drive the simulated attack from, and the one CPEDS-X will revoke.

---

## Step 3 — Add a `live` branch to `playbooks/mitigation.py`

Your `_get_boto3_client()` already returns a real client for LocalStack and `None`
for mock. Extend the **mode switch** (not the playbook logic) to a third value.

```python
# playbooks/mitigation.py
import os, boto3

def _containment_mode() -> str:
    # Back-compat: USE_LOCALSTACK=1 still means "localstack".
    if os.getenv("USE_LOCALSTACK") == "1":
        return "localstack"
    return os.getenv("CONTAINMENT_MODE", "mock").lower()   # mock | localstack | live

def _get_boto3_client(service: str):
    mode = _containment_mode()
    if mode == "localstack":
        return boto3.client(service, endpoint_url="http://localhost:4566",
                            aws_access_key_id="test", aws_secret_access_key="test",
                            region_name="us-east-1")
    if mode == "live":
        session = boto3.Session(profile_name=os.getenv("AWS_PROFILE", "cpeds-responder"))
        return session.client(service)           # real AWS, real creds from the chain
    return None                                   # mock — simulate, touch nothing
```

The actual revoke code is the **same** for LocalStack and live — only the client's
target differs. That's the whole point of the hybrid design: one playbook, three dials.

**The real IAM revoke** (deactivate keys + attach a deny-all inline policy):

```python
def _revoke_user(iam, username: str) -> dict:
    actions = []
    for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"],
                              Status="Inactive")
        actions.append(f"deactivated key {k['AccessKeyId']}")
    iam.put_user_policy(UserName=username, PolicyName="CPEDS-Quarantine",
        PolicyDocument='{"Version":"2012-10-17","Statement":'
                       '[{"Effect":"Deny","Action":"*","Resource":"*"}]}')
    actions.append("attached deny-all quarantine policy")
    return {"principal": username, "actions": actions, "mode": "live"}
```

**The real EC2 quarantine** (swap the instance onto an isolation security group):

```python
def _quarantine_instance(ec2, instance_id: str, quarantine_sg: str) -> dict:
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg])
    return {"instance_id": instance_id, "sg": quarantine_sg, "mode": "live"}
```

---

## Step 4 — Build the live ingestion loop (`ml_engine/live_watcher.py`)

Poll CloudTrail, convert each record into the CloudTrail-shaped dict your parser
already understands, and run it through the *same* classifier as every other tab.

```python
# ml_engine/live_watcher.py  (skeleton)
import json, boto3
from ml_engine.log_ingest import parse_logs   # you already have this

def poll_events(profile="cpeds-responder", minutes=15):
    ct = boto3.Session(profile_name=profile).client("cloudtrail")
    resp = ct.lookup_events(MaxResults=50)     # add StartTime for a sliding window
    events = []
    for e in resp["Events"]:
        record = json.loads(e["CloudTrailEvent"])   # full userIdentity/eventName/...
        events.append(record)
    return parse_logs(json.dumps({"Records": events}), fmt="json")

def run_once(clf, threshold=0.75):
    verdicts = []
    for event in poll_events():
        pred = clf.predict(event)
        if pred["predicted_class"] != 0 and pred["confidence"] >= threshold:
            verdicts.append((event, pred))     # hand to the safety gate, not straight to revoke
    return verdicts
```

Wire this to a manual **"Poll live account"** button on the Scenario Runner (or a new
Live tab) for v1 — a button is safer and more demo-able than a background thread. Move
to a scheduled poll later if you want it hands-off.

---

## Step 5 — The safety gate (this is what makes live mode responsible)

In **mock/localstack**, auto-firing on the confidence gate is fine. In **live**, put a
human in the loop and enforce hard guardrails before any boto3 call:

1. **Human approval** — a threat in live mode shows as *"Pending approval"*; the
   analyst clicks **Confirm containment** before anything executes. Model confidence
   alone never fires a real revoke.
2. **Dry-run preview** — EC2 supports `DryRun=True`; IAM has
   `SimulatePrincipalPolicy`. Preview first, execute on the second explicit click.
3. **Protected-principals denylist** — never revoke `root`, your break-glass admin,
   or `cpeds-responder` itself (belt-and-suspenders on top of the IAM prefix scope).
4. **Blast-radius cap** — refuse more than N containments per 10 min so a burst of
   false positives can't cascade.
5. **Always reversible** — every action writes a **rollback token** (see Step 8).

---

## Step 6 — Simulate a real attack

Point the AWS CLI at the victim's credentials and perform a real privilege-escalation
sequence. These are genuine API calls; CloudTrail will record every one.

```bash
# one-time: store the victim's creds as a CLI profile
aws configure --profile cpeds-victim        # paste cpeds-victim's key + secret

# --- Recon (benign by design — should read C0) ---
aws --profile cpeds-victim iam list-users
aws --profile cpeds-victim iam list-roles

# --- Privilege escalation (should trip the detector: C1/C2) ---
aws --profile cpeds-victim iam attach-user-policy \
    --user-name cpeds-victim \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws --profile cpeds-victim iam create-access-key --user-name cpeds-victim
```

> **Purpose-built alternative:** [Stratus Red Team](https://github.com/DataDog/stratus-red-team)
> (Datadog) is an open-source, "Atomic Red Team for the cloud" tool that detonates
> realistic, self-contained AWS attack techniques and cleans up after itself — ideal
> for generating honest CloudTrail telemetry. Use it against the sandbox only.

---

## Step 7 — Watch the loop close

1. Run the attack (Step 6).
2. Wait for CloudTrail latency (~5–15 min on LookupEvents), then hit **Poll live account**.
3. The escalation event flows through `parse_logs → clf.predict` → classifies as a
   non-benign threat with SHAP attributions (your existing XAI view).
4. Live mode shows **"Pending approval."** Click **Confirm containment**.
5. CPEDS-X calls real IAM: `cpeds-victim`'s access keys go **Inactive** and a deny-all
   quarantine policy is attached. Verify in the console — the victim is locked out.
6. The incident lands in your history with `mode: "live"` and a rollback token.

You now have a real detection-to-containment loop on a real cloud account.

---

## Step 8 — Rollback & cleanup

Every live action must be undoable. Store what changed and expose an **Undo** button.

```python
def _rollback_user(iam, username: str):
    iam.delete_user_policy(UserName=username, PolicyName="CPEDS-Quarantine")
    for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"],
                              Status="Active")
```

Extend the `incidents` table with a `rollback` JSON column so the case log doubles as
an audit + undo trail.

---

## 🧪 Testing tiers (cheapest first)

| Tier | Tool | Cost | Proves |
|------|------|------|--------|
| 1. Unit | [`moto`](https://github.com/getmoto/moto) (mocks boto3 in-memory) | $0 | Playbook logic is correct |
| 2. Integration | LocalStack (`USE_LOCALSTACK=1`) | $0 | boto3 calls are well-formed |
| 3. Live | Sandbox AWS account + `cpeds-*` test identities | ~$0 | End-to-end real containment |

Validate live mode **only** against the sandbox, never anything else.

---

## 🚀 Deployment separation (what actually keeps demos safe)

Safety comes from the *environment*, not from remembering to flip a flag:

- **Demo deployment** (Render/Vercel): `cpeds-responder` credentials are simply **not
  present**, so `CONTAINMENT_MODE=live` can't do anything. Leave it on `mock`.
- **Operational deployment** (local or your own box, behind your network): the only
  place the sandbox profile/role exists. This is where live mode runs.

Keep the **Attack Simulator** and **Scenario Runner** tabs pinned to mock even when the
backend is live — they're teaching tools, not real incidents.

---

## 🔐 Security checklist (tick before enabling live)

- [ ] Separate sandbox AWS account; MFA on root; $1 billing alarm set.
- [ ] `cpeds-responder` policy scoped to `user/cpeds-*` + `cpeds-managed=true` tag only.
- [ ] No access keys in code or git — creds come from a profile / env / assumed role.
- [ ] Protected-principals denylist (root, admins, the responder itself).
- [ ] Human-approval gate + dry-run preview enforced in live mode.
- [ ] Blast-radius cap active.
- [ ] Every action has a stored rollback token and an Undo button.
- [ ] Demo deployment has **no** live credentials.
- [ ] Sandbox torn down (`terraform destroy` / delete test users + instances) when done.

---

## 🧭 Suggested build order

1. **Milestone A (zero real-AWS risk):** Steps 3–5 with Tier-1/2 testing. Full hybrid
   skeleton, still safe to demo anywhere.
2. **Milestone B (real but sandboxed):** Steps 1–2, 6–8 against the throwaway account.
   Treat this as *"real, sandboxed containment,"* not production auto-remediation —
   auto-firing destructive IAM/EC2 changes on a model verdict is risky even in
   industry, which is exactly why the approval gate and tag allowlist are mandatory,
   not optional.

---

*CPEDS-X is trained on synthetic cloud-audit data; live mode runs the same model
against real telemetry. Keep the academic-honesty note intact — cite `measured`
metrics, and disclose that live containment was validated on a sandbox account.*
