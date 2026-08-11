# 🛰️ CPEDS-X — Live AWS Containment Runbook

A complete, copy-paste record of how to run CPEDS-X against a **real AWS sandbox
account** — from first-time setup, to arming live mode, to a full demo, to
cleanup. Follow the parts in order. Everything here was tested end-to-end.

---

## ⚠️ Read this first — safety rules

1. **Sandbox account ONLY.** Live mode issues real, destructive IAM changes
   (deactivates access keys, attaches a deny-all policy). Never point it at a
   production or important account.
2. **Never put credentials in code or chat.** Keys live only in your local AWS
   profile (via `aws configure`). If a secret key is ever exposed, **rotate it**
   (delete + recreate) immediately.
3. **The model will misfire** — it overlaps threat classes by design. That's why
   a human must click **Confirm** before any real change, and why every action
   is reversible (**Undo**).
4. **Guardrails are always on:** protected principals (`root`, `cpeds-responder`,
   admin, break-glass) are never contained; a blast cap limits how many
   containments can fire in a window; every action stores a rollback token.

### This account (fill in your own)
| Thing | Value |
|---|---|
| AWS account ID | `930525999048` |
| Region | `us-east-1` |
| Responder IAM user (app's login) | `cpeds-responder` |
| CLI profile name | `cpeds-responder` |
| CloudTrail trail name | `cpeds-trail` |
| Test "attacker" users (created + deleted per demo) | `cpeds-victim`, `cpeds-intruder` |

> 🔑 **Outstanding action:** the responder key `<REDACTED-responder-key-id>` was pasted
> into chat during setup — delete it in the Console and keep only the key you
> configured afterward. (IAM → Users → cpeds-responder → Security credentials.)

---

## PART A — One-time AWS setup (do once)

Done on the **AWS website** (console.aws.amazon.com), signed in to the sandbox
account. Use the **Search bar** at the top to jump to each service.

### A1. Turn on CloudTrail (the activity recorder)
1. Search **CloudTrail** → open it.
2. **Create trail**.
3. Trail name: `cpeds-trail`.
4. Leave defaults → **Next** → **Create trail**.

This records "who did what" so the app has events to read.

### A2. Create the responder IAM user (the app's login to AWS)
1. Search **IAM** → **Users** → **Create user**.
2. User name: `cpeds-responder`.
3. Do **not** tick "Provide user access to the Console." → **Next**.

### A3. Give it permission
On the permissions page → **Attach policies directly** → search and tick each:
- `IAMFullAccess`
- `AmazonEC2FullAccess`
- `AWSCloudTrail_ReadOnlyAccess`

Then **Next** → **Create user**.

> These are broad on purpose for a sandbox. To lock it down later, replace them
> with a custom policy that only allows `iam:UpdateAccessKey`, `iam:PutUserPolicy`,
> `iam:DeleteUserPolicy`, `cloudtrail:LookupEvents`, `sts:GetCallerIdentity` on
> `cpeds-*` users.

### A4. Create the access key (the app's password)
1. Open the **cpeds-responder** user → **Security credentials** tab.
2. **Access keys** → **Create access key** → **Command Line Interface (CLI)** →
   tick the box → **Create access key**.
3. Copy **both** values (or Download .csv):
   - **Access key ID**
   - **Secret access key** ← shown only ONCE.

---

## PART B — One-time computer setup (do once)

Done on your **Windows PC** in **PowerShell**.

### B1. Install the AWS CLI
```powershell
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```
Click through the installer window: **Next → Next → Install → Finish**.

> Silent alternative:
> ```powershell
> Start-Process msiexec.exe -ArgumentList '/i https://awscli.amazonaws.com/AWSCLIV2.msi /qn' -Wait
> ```

### B2. Verify it installed
**Close PowerShell and open a NEW window first** (the `aws` command only appears
in a fresh window). Then:
```powershell
aws --version
```
Expected: `aws-cli/2.x.x Python/3.x Windows/11 exe/AMD64`

> If plain `aws` still isn't recognized, use the full path anytime:
> ```powershell
> & "C:\Program Files\Amazon\AWSCLIV2\aws.exe" --version
> ```

### B3. Save the responder keys as a profile
```powershell
aws configure --profile cpeds-responder
```
Answer the four prompts:
- **AWS Access Key ID** → paste the Access key ID
- **AWS Secret Access Key** → paste the Secret access key
- **Default region name** → `us-east-1`
- **Default output format** → press Enter (leave blank)

### B4. Test the keys work
```powershell
aws sts get-caller-identity --profile cpeds-responder
```
Expected: your account `930525999048` and `arn:...user/cpeds-responder`.

> Tip: if a window doesn't recognize `aws`, set a shortcut and use `& $aws ...`:
> ```powershell
> $aws = "C:\Program Files\Amazon\AWSCLIV2\aws.exe"
> ```

---

## PART C — Arm live mode

### C1. Start the backend in LIVE mode
In the **backend** folder:
```powershell
cd C:\Users\admin\Desktop\projects\cpeds-x\backend
$env:CONTAINMENT_MODE="live"
$env:AWS_PROFILE="cpeds-responder"
.venv\Scripts\python.exe -m uvicorn main:app --port 8000
```
Leave this window running (it's the app's brain).

### C2. Start the frontend
In the **frontend** folder (new window):
```powershell
cd C:\Users\admin\Desktop\projects\cpeds-x\frontend
npm run dev
```

### C3. Confirm it's armed
Open the app → log in → **Live Containment** tab → click **Re-check**.
The chip flips **MOCK → LIVE ARMED**, showing account `930525999048` and the
`cpeds-responder` identity. Blast room shows `5/5`.

---

## PART D — Run a live demo (create → attack → catch → contain → undo)

### D1. Create a fake "attacker" user
```powershell
$aws = "C:\Program Files\Amazon\AWSCLIV2\aws.exe"

# 1. create the test user
& $aws iam create-user --user-name cpeds-victim --profile cpeds-responder

# 2. let it manage IAM (so it can "escalate")
& $aws iam attach-user-policy --user-name cpeds-victim `
    --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --profile cpeds-responder

# 3. give it its own keys
& $aws iam create-access-key --user-name cpeds-victim --profile cpeds-responder
```
Copy the printed AccessKeyId + SecretAccessKey from step 3, then save them as a
second profile:
```powershell
& $aws configure --profile cpeds-victim
# paste victim key id, victim secret, us-east-1, Enter
```

### D2. Make the "attack" happen (act AS the victim)
CloudTrail blames the caller, so the attack must be run with `--profile cpeds-victim`.

**Which actions trip the model** (learned from testing):
| Action | Model verdict |
|---|---|
| `create-access-key` | **C1 threat → Pending** ✅ |
| `create-user` | **C1 threat → Pending** ✅ |
| `attach-user-policy` | C0 Benign (won't flag) |

So run a triggering action as the victim:
```powershell
& $aws iam create-access-key --user-name cpeds-victim --profile cpeds-victim
```
(You can ignore the key it prints — we only want CloudTrail to record the action.)

### D3. Wait, then poll
- **Wait ~5–15 minutes.** This delay is CloudTrail's, not the app's — you can't
  skip it. Polling sooner just won't show the event yet.
- In the app: set **Look-back = 1 hour** → **Poll live account**.
- The victim's `CreateAccessKey` appears as **C1 Horizontal · Pending** with a
  **Review & contain** button. (Events from `cpeds-responder`/`root` show as
  **Guarded** — that's the protected-principals guardrail working.)

### D4. Contain it (two-click human approval)
1. On the **cpeds-victim · Pending** row → **Review & contain**.
2. Read the red preview (Set every access key to Inactive + attach deny-all
   `CPEDS-Quarantine` policy). *Nothing has touched AWS yet.*
3. **Confirm real revoke** → row flips to **Contained**, an **Undo** appears.
   ← This is the real IAM change.

### D5. Undo it
Click **Undo** on the row → keys reactivated, quarantine policy removed → row
flips to **Reversed**.

---

## PART E — Verify commands (prove the real change)

Run **before** and **after** containing to see the change:
```powershell
$aws = "C:\Program Files\Amazon\AWSCLIV2\aws.exe"

# access key status: Active  ->  Inactive (after contain)  ->  Active (after undo)
& $aws iam list-access-keys --user-name cpeds-victim --profile cpeds-responder

# inline policies: []  ->  ["CPEDS-Quarantine"] (after contain)  ->  [] (after undo)
& $aws iam list-user-policies --user-name cpeds-victim --profile cpeds-responder
```

---

## PART F — Cleanup / teardown

### F1. See which test users remain
```powershell
& $aws iam list-users --profile cpeds-responder --query "Users[].UserName"
```
You want only `cpeds-responder` left. Delete any `cpeds-victim` / `cpeds-intruder`.

### F2. Fully delete a test user
A user can't be deleted until its keys and policies are gone. For `cpeds-victim`:
```powershell
# list its key IDs
& $aws iam list-access-keys --user-name cpeds-victim --profile cpeds-responder `
    --query "AccessKeyMetadata[].AccessKeyId"

# delete EACH key id it printed (repeat per key)
& $aws iam delete-access-key --user-name cpeds-victim --access-key-id KEYID --profile cpeds-responder

# remove any inline quarantine policy left over (safe to ignore NoSuchEntity)
& $aws iam delete-user-policy --user-name cpeds-victim --policy-name CPEDS-Quarantine --profile cpeds-responder

# detach managed policies
& $aws iam detach-user-policy --user-name cpeds-victim --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --profile cpeds-responder
& $aws iam detach-user-policy --user-name cpeds-victim --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile cpeds-responder

# finally delete the user
& $aws iam delete-user --user-name cpeds-victim --profile cpeds-responder
```
Repeat for `cpeds-intruder` if it exists (usually just the `delete-user` line).

> Errors like `NoSuchEntity` just mean it was already gone — safe to ignore.

### F3. Remove the victim CLI profile (optional tidy-up)
Edit `C:\Users\<you>\.aws\credentials` and `C:\Users\<you>\.aws\config` and
delete the `[cpeds-victim]` blocks.

### F4. 🔑 Rotate any exposed responder key
If a `cpeds-responder` secret was ever pasted somewhere (chat, screenshot, file):
1. Console → IAM → Users → `cpeds-responder` → Security credentials.
2. Delete the exposed key (e.g. `<REDACTED-responder-key-id>`).
3. Create a fresh key → `aws configure --profile cpeds-responder` again with it.

---

## PART G — Back to safe mock mode

1. In the backend window, press **Ctrl+C** to stop the server.
2. Next launch **without** the `$env:CONTAINMENT_MODE="live"` line runs in safe
   **mock** mode (blocks are simulated, nothing touches AWS). The app shows the
   **MOCK** chip again.

To keep it permanently safe, just start the backend normally:
```powershell
cd C:\Users\admin\Desktop\projects\cpeds-x\backend
.venv\Scripts\python.exe -m uvicorn main:app --port 8000
```

---

## Appendix — quick command reference

```powershell
# shortcut for the aws binary (use in any window)
$aws = "C:\Program Files\Amazon\AWSCLIV2\aws.exe"

# who am I / does the profile work
& $aws sts get-caller-identity --profile cpeds-responder

# list users
& $aws iam list-users --profile cpeds-responder --query "Users[].UserName"

# create / attack (as victim)
& $aws iam create-user --user-name cpeds-victim --profile cpeds-responder
& $aws iam create-access-key --user-name cpeds-victim --profile cpeds-victim

# verify a containment
& $aws iam list-access-keys  --user-name cpeds-victim --profile cpeds-responder
& $aws iam list-user-policies --user-name cpeds-victim --profile cpeds-responder

# cleanup
& $aws iam delete-access-key --user-name cpeds-victim --access-key-id KEYID --profile cpeds-responder
& $aws iam delete-user       --user-name cpeds-victim --profile cpeds-responder
```

### Environment variables the backend reads
| Variable | Purpose | Value used |
|---|---|---|
| `CONTAINMENT_MODE` | `live` turns on real AWS; unset/`mock` is safe | `live` |
| `AWS_PROFILE` | which local profile to use | `cpeds-responder` |
| `AWS_REGION` | region (defaults to us-east-1) | `us-east-1` |
| `PROTECTED_PRINCIPALS` | extra never-contain usernames (comma-sep) | *(optional)* |
| `CPEDS_BLAST_CAP` | max containments per window (default 5) | *(optional)* |
| `CPEDS_BLAST_WINDOW` | window seconds (default 600) | *(optional)* |

### Troubleshooting
| Symptom | Fix |
|---|---|
| `aws not recognized` | Open a new window, or use the full path `& "C:\Program Files\Amazon\AWSCLIV2\aws.exe"` |
| App still says MOCK | The backend wasn't started with `CONTAINMENT_MODE=live`; restart with the env line, then **Re-check** |
| No Pending rows | Attack ran as a protected user (shows Guarded), or action was `attach-user-policy` (benign). Use `create-access-key`/`create-user` **as cpeds-victim**, and wait 5–15 min |
| Confirm errors out | The target user was deleted before Confirm — recreate it, or just clean up |
| Nothing in poll | CloudTrail latency — wait 5–15 min and poll again with Look-back = 1 hour |
