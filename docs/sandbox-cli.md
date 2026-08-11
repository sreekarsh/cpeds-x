# 🧪 CPEDS-X — Sandbox Fixture CLI (`cpeds sandbox`)

The `cpeds live` commands drive the **containment** half of the live-AWS demo
(status → poll → contain → undo). This is the other half: `cpeds sandbox` creates,
attacks, inspects, and deletes the **throwaway victim** those commands act on — so the
whole demo runs from `cpeds` instead of hand-typed `aws iam …`.

```
setup ─▶ attack ─▶ (wait ~5–15 min) ─▶ live poll ─▶ live contain ─▶ verify ─▶ live undo ─▶ teardown
└──────── cpeds sandbox ───────┘        └──────────────── cpeds live ───────────────┘        └ sandbox ┘
```

It automates Parts **D1 / D2 / E / F** of the [Live AWS Runbook](../LIVE_AWS_RUNBOOK.md).
It is a net-new, self-contained module (`backend/sandbox_fixtures.py`) that talks to AWS
through its own boto3 session. **It never contains anything and never touches the
live-containment code** (`ml_engine/live_watcher.py`, `playbooks/mitigation.py`) — it only
creates and deletes the target those paths later act on.

---

## 🚨 The one rule (read this first)

> **Point `cpeds sandbox` at a dedicated, throwaway AWS "sandbox" account only — never
> production, never an account with anything real in it.**

These are the **only** `cpeds` commands that make *creative* IAM writes (`CreateUser`,
`CreateAccessKey`). Everything else in the CLI reads or scores. Treat this group with the
same care as `cpeds live contain`.

---

## ✅ Prerequisites

- A **separate** AWS sandbox account (the same one live mode uses; account and region
  come from your profile).
- The project venv, with `boto3` installed (already in `backend/requirements.txt`).
- An AWS profile with **IAM write** permissions — `CreateUser` / `CreateAccessKey` /
  `DeleteUser`. Least-privilege `cpeds-responder` needs `IAMFullAccess` for this, or use a
  dedicated admin profile. Pass it with `--profile` (default `cpeds-responder`).
- Credentials come from the profile / environment / assumed role — **never pasted into
  code**.

Run everything from the `backend` folder so the `cpeds` launcher and venv are found.

---

## 🔐 Guardrails (baked into every mutating command)

| Guardrail | What it does |
|-----------|--------------|
| **`cpeds-` name prefix** | Refuses any username that doesn't start with `cpeds-`, so it can only ever create or delete throwaway demo identities. |
| **Protected-principals denylist** | Refuses `root`, `cpeds-responder`, `admin`, `administrator`, `break-glass`, `breakglass` — the exact set `live contain` refuses, reused from `playbooks.mitigation`, not re-declared. |
| **Guard runs first** | The name check fires *before* any account preview, confirmation prompt, or AWS call — a bad target never reaches AWS. |
| **STS account preview** | `setup` / `teardown` / `run` print the real account + identity (`sts:GetCallerIdentity`) they're about to write to, before you confirm. |
| **Typed confirmation** | Every mutating action needs an explicit `yes` (or `--yes` for non-interactive use). |
| **Secret shown once** | A freshly minted secret access key is printed to stdout **once** and is **never written to any file**. |

---

## 🎛️ Commands

| Command | Runbook | What it does |
|---------|:-------:|--------------|
| `cpeds sandbox setup` | D1 | Create the throwaway user, attach `IAMFullAccess`, mint an access key (returns the secret once). |
| `cpeds sandbox attack` | D2 | Run an attack action **as the victim**, so CloudTrail attributes it to the victim. `--kind` picks which: **horizontal** (C1, default), **vertical** (C2), or **exfil** (C3). See [Attack kinds](#-attack-kinds). |
| `cpeds sandbox verify` | E | Read-only: show the victim's access-key statuses + attached policies (watch keys flip `Active → Inactive` around a contain). |
| `cpeds sandbox teardown` | F | Fully delete the user — keys, inline policies, managed attachments, then the user. Idempotent. |
| `cpeds sandbox run` | D1+D2 | `setup` + `attack` in one step, using the fresh key in-memory (no profile juggling), then hands you off to `live poll`. |

Bare `cpeds sandbox` prints this help.

---

## 🎯 Attack kinds

`cpeds sandbox attack` (and `run`) take **`--kind`** to choose *which* CloudTrail-visible
action the victim performs. Each maps to one CPEDS-X class:

| `--kind` | Class | AWS call | Authorized? | Live-demo strength |
|----------|:-----:|----------|:-----------:|--------------------|
| `horizontal` *(default)* | **C1** | `CreateAccessKey` — mint the victim a second key (persistence) | ✅ yes (victim holds `IAMFullAccess`) | **Strong** — clean, high-confidence contain. |
| `vertical` | **C2** | `AttachUserPolicy` — victim self-attaches `AdministratorAccess` | ✅ yes | **Strong** — clean, high-confidence contain. Teardown detaches it. |
| `exfil` | **C3** | `GetSecretValue` — victim tries to read a Secrets Manager secret | ❌ no (AccessDenied-safe) | **Weak (see caveat)** — proves the attempt reaches the loop; may score below the gate. |

Aliases are accepted, so `--kind c2`, `--kind vertical`, `--kind 2`, and `--kind escalate`
are all the same. `C1`/`C2`/`C3` work too.

**Why C1 and C2 are the headline demos.** Both are *IAM changes* — management events that
`cloudtrail:LookupEvents` returns, carrying the exact signatures the model keys on
(`CreateAccessKey` → C1, `AttachUserPolicy` → C2). The live loop sees them within CloudTrail
latency and contains them confidently.

> ### ⚠️ The `exfil` (C3) caveat — read before demoing it
>
> `--kind exfil` is deliberately **AccessDenied-safe**: the victim has **no** Secrets
> Manager permission and the target secret (`cpeds-sandbox-nonexistent-secret` by default)
> need not exist, so the call is **expected to be denied and reads nothing** — but the
> `GetSecretValue` *attempt* is still recorded in CloudTrail. Two honest limitations:
>
> 1. **Data reads mostly aren't in `LookupEvents`.** The canonical C3 action, S3
>    `GetObject`, is a *data event* and never appears in the management-event feed the live
>    loop polls. `GetSecretValue` is one of the few C3-flavored *management* events that
>    does — which is why it's used here.
> 2. **Real logs lack the exfil-volume signal.** The model's strongest C3 driver
>    (`data_exfil_volume_mb`) is `0` in real CloudTrail, so a real `GetSecretValue` may
>    score **borderline — possibly below the 0.75 containment gate** — landing as
>    *monitored* rather than a confident *contain*. The CLI preview says so.
>
> **For a confident C3 story, use the Log Analysis tab / `cpeds analyze` on the real
> Stratus dataset** (393 real C3 events) instead of the live loop. Treat `--kind exfil` as
> an honest demonstration of the *data-event visibility limit*, not a reliable live contain.
> Override the target secret with `--secret-id` / `CPEDS_EXFIL_SECRET_ID` if you want.

---

## 🔁 The full demo loop

```powershell
# 1. Create + attack a throwaway victim in one step (fixture side)
cpeds sandbox run
#   → creates cpeds-victim, performs CreateAccessKey as it,
#     prints the next commands to run.

# 2. Wait ~5–15 min for CloudTrail latency, then score real telemetry
cpeds live poll --minutes 60
#   → the escalation surfaces as a C1 "Pending" verdict.

# 3. Contain it (real, reversible IAM revoke — asks you to type 'yes')
cpeds live contain --principal cpeds-victim --class 1

# 4. Prove the change landed
cpeds sandbox verify
#   → keys show Inactive, CPEDS-Quarantine policy present → CONTAINED.

# 5. Roll it back
cpeds live undo --username cpeds-victim
cpeds sandbox verify        # keys Active again → ACTIVE

# 6. Delete the throwaway user when you're done
cpeds sandbox teardown
```

Prefer running the two fixture halves separately? Use `setup` then `attack`:

```powershell
cpeds sandbox setup
#   → prints username, access_key_id, secret_access_key (shown ONCE).

# attack with the keys it just printed …
cpeds sandbox attack --username cpeds-victim `
    --access-key-id AKIA... --secret-access-key <secret>

# … or, if you saved the victim as its own profile, attribute by profile instead:
cpeds sandbox attack --username cpeds-victim --victim-profile cpeds-victim
```

Want a different attack? Add `--kind` (and match the `--class` on contain):

```powershell
# C2 vertical escalation — victim self-attaches AdministratorAccess (clean live contain)
cpeds sandbox run --kind vertical
cpeds live contain --principal cpeds-victim --class 2

# C3 exfil attempt — GetSecretValue (AccessDenied-safe; may score below the gate)
cpeds sandbox run --kind exfil
#   → see the exfil caveat above; for a confident C3, use `cpeds analyze` on real data.
```

> `cpeds sandbox run` prints the exact follow-up `live contain … --class N` line for the
> kind you chose, so you don't have to remember the class number.

> On macOS/Linux use `./cpeds sandbox run` and swap the PowerShell backtick line
> continuations for `\`.

---

## 🚩 Flags

Common to `setup` / `attack` / `teardown` / `run`:

| Flag | Default | Meaning |
|------|---------|---------|
| `--username` | `cpeds-victim` | Victim name. **Must** start with `cpeds-`. |
| `--region` | `AWS_REGION`, else `us-east-1` | AWS region. |
| `--yes` | off | Skip the interactive `yes` prompt (non-interactive / scripted use). |

Command-specific:

| Flag | Command(s) | Meaning |
|------|------------|---------|
| `--kind` | `attack` `run` | Which attack: `horizontal` (C1, default), `vertical` (C2), `exfil` (C3). Aliases/`C1`–`C3` accepted. See [Attack kinds](#-attack-kinds). |
| `--profile` | `setup` `verify` `teardown` `run` | AWS profile with IAM write perms (default `cpeds-responder`). `attack` uses `--victim-profile` instead. |
| `--no-policy` | `setup` | Create the user **without** attaching `IAMFullAccess`. |
| `--victim-profile` | `attack` | A configured profile for the victim's own identity. |
| `--access-key-id` / `--secret-access-key` | `attack` | The victim's keys (from `setup`) to attribute the attack. |
| `--secret-id` | `attack` `run` | *(exfil kind only)* Secrets Manager secret the victim attempts to read. Default is a nonexistent name so the call is AccessDenied-safe. |

`verify` takes `--username`, `--profile`, `--region` only (it's read-only — no `--yes`).

### JSON & exit codes

Add `--json` to any command for machine-readable output on **stdout**; all human status
text goes to **stderr**, so pipes stay clean.

| Exit code | Meaning |
|:---------:|---------|
| `0` | Success. |
| `1` | Refused or aborted — guard rejected the target, the profile couldn't reach AWS, bad arguments, or you didn't type `yes`. |
| `2` | The mutating AWS operation failed (e.g. the profile lacked a required IAM permission). |

---

## 🧹 When you're done

Always tear down so nothing lingers in the account:

```powershell
cpeds sandbox teardown          # deletes cpeds-victim entirely (idempotent)
```

`teardown` is safe to re-run — a missing user or already-deleted piece is reported
`skipped`, not an error.

**Security checklist**

- [ ] Ran only against the **sandbox** account (checked the STS account preview).
- [ ] Only `cpeds-*` users were created (the guard enforces this).
- [ ] The printed secret access key was **not** saved to any file or committed.
- [ ] `cpeds sandbox teardown` run for every victim you created.
- [ ] Any previously-exposed responder access key rotated/deleted in the AWS Console.

---

## 🔧 Under the hood

`backend/sandbox_fixtures.py` exposes:

| Function | Purpose |
|----------|---------|
| `assert_safe_name(username)` | The guard — accepts a bare name or full ARN, applies the denylist + `cpeds-` prefix check, returns the cleaned username or raises `SandboxError`. |
| `whoami(profile, region)` | STS account preview; never raises (returns an error dict) so previews are safe. |
| `setup_victim(...)` | D1 — create user, attach policy, mint key. |
| `run_attack(...)` | D2 — perform the chosen `kind` as the victim (by keys or profile): horizontal `CreateAccessKey` (C1), vertical `AttachUserPolicy`→`AdministratorAccess` (C2), or exfil `GetSecretValue` (C3, AccessDenied-safe). Retries fresh-key propagation. `describe_attack(kind)` / `ATTACK_KINDS` expose the metadata used by the CLI preview. |
| `verify(...)` | E — read key statuses + policies; reports `contained`. |
| `teardown(...)` | F — delete keys → inline policies → managed attachments → user; idempotent. |

The CLI wrappers live in `backend/cli.py` (`cmd_sandbox_*`). The name guard is applied
up-front in the four mutating wrappers (`setup` / `attack` / `teardown` / `run`) via
`_guard_or_die()` — before any preview or AWS call; the read-only `verify` applies the
same check inside `verify()` itself.

> **Note on testing:** module logic is unit-tested against a mocked boto3 client, but the
> **real** setup → attack → teardown must run on a machine with `boto3`, internet, and the
> AWS profile configured (i.e. your Windows box) — not inside a sandboxed CI/VM without AWS.

---

*Synthetic-training / academic-honesty note is unchanged: CPEDS-X is trained on synthetic
cloud-audit data and the live loop runs that same model against real telemetry. Live
containment — and these fixtures — are validated on a sandbox account only.*

