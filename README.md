# 🛡️ CPEDS-X: Cloud Privilege Escalation Detection System

An end-to-end, ML-powered cloud security platform that ingests **real CloudTrail
log exports** (drag-and-drop upload) or a live threat simulator, classifies
privilege-escalation threats in real time, explains every decision with SHAP + a
GenAI co-pilot, and executes automated containment playbooks — all deployable on
**100% free tiers**.

> ⚠️ **Academic honesty note:** The dataset is **synthetically generated** in a
> CloudTrail-compatible shape (not real CERT r6.2 logs). The `/metrics` endpoint
> returns two blocks: `benchmark` (reference numbers from the CPEDS paper
> baseline) and `measured` (the **real** accuracy from the model actually trained
> at server startup). Cite the `measured` values as your results.

---

## 🏗️ Architecture

```
Layer 1  Data Ingestion        Real CloudTrail/JSON/JSONL/CSV upload + synthetic generator
Layer 2  Preprocessing + SMOTE 28-feature extractor, StandardScaler, 5-NN SMOTE
Layer 3  ML Classification     LightGBM (primary) + XGBoost/RF/AdaBoost ensemble
Layer 4  Explainable AI        SHAP TreeExplainer top-5 + GenAI SOC summary
Layer 5  Automated Mitigation  boto3/LocalStack IAM revoke + micro-segmentation
Layer 6  Frontend SOC UI       React + Vite + Tailwind + Recharts dashboard
Layer 7  Case Management       Per-user incident history + printable SOC report
```

**Threat classes:** `C0` Benign · `C1` Horizontal Escalation ·
`C2` Vertical Escalation · `C3` Data Exfiltration · `C4` Lateral Movement

---

## 🔍 Two ways to feed the detector

The same trained model backs both entry points, so results are identical
whichever you use.

**1. Attack Simulator** *(Tab 1)* — generate a synthetic CloudTrail event for any
threat class and watch it flow through classify → SHAP → GenAI → auto-containment
in real time. Best for a scripted, reliable live demo.

**2. Log Analysis** *(Tab 3)* — **upload a real log file** and batch-triage it.
Drag-and-drop (or browse to) an AWS CloudTrail export or any JSON / JSON&nbsp;Lines
/ CSV log, or click **Load sample export** to pull a realistic mixed CloudTrail
file from the backend. Every event is scored, high-confidence threats are
auto-contained (≥ 75% confidence, non-benign), and you get:

- summary cards (events analyzed, threats detected, auto-contained, processing time),
- a threat-class distribution bar,
- a per-row results table (click any row to open its full SHAP/XAI breakdown), and
- a one-click **CSV export** of the triage results.

Accepted upload formats: `{"Records":[…]}` CloudTrail exports, JSON arrays,
single JSON events, `.jsonl` / `.ndjson`, and CSV (dotted headers like
`userIdentity.arn` are un-flattened into nested objects). Uploads are capped at
8&nbsp;MB and 1,000 events per file to keep the demo responsive.

---

## 🟣 Purple-team Scenario Runner *(Tab 2)*

Beyond scoring single events, the **Scenario Runner** replays whole **multi-step
attack chains** — a realistic kill-chain (e.g. credential compromise → privilege
escalation → data exfiltration) fired step-by-step through the same
classify → SHAP → GenAI → auto-containment pipeline. Pick a scenario from the
catalog, run it, and watch each stage light up with its predicted class,
confidence, and containment action. Great for demonstrating detection across a
sequence rather than one isolated call. Backed by `GET /api/v1/scenarios`
(catalog) and `POST /api/v1/scenario/run` (execute a step). Every step is also
written to your incident history, so a full chain produces a complete case trail.

---

## 🗂️ Incident History + SOC report *(Tab 4)*

Every detection — from the simulator, a scenario step, or an uploaded-log
triage — is **persisted to a private, per-user case file** (SQLite `incidents`
table, isolated by account; auto-migrated on startup). The **Incident History**
tab is your SOC case log:

- summary cards (total incidents, threats, auto-contained, last seen),
- a full incident table (time, source, event, principal, threat class,
  confidence, action), where each drillable row **re-runs the stored raw log**
  to regenerate its SHAP/XAI breakdown and opens it in the XAI tab, and
- a one-click **Download SOC report** — a self-contained, print-ready incident
  report (masthead, confidential banner, executive-summary cards, threat
  distribution, and the full incident log) rendered client-side and handed to the
  browser's **Save-as-PDF**. No dependencies, no server round-trip. Analyst
  attribution is pulled from your signed-in account.

Backed by `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, and
`DELETE /api/v1/incidents` (scoped to the calling user).

---

## 🖥️ Command-line interface (`cpeds`)

The same trained model that powers the API and the dashboard is also a terminal
tool. `backend/cli.py` imports the engine **in-process** — no server to start and
no login required — so you get one detection brain across **three surfaces**
(REST API · web dashboard · CLI). It adds **zero new dependencies** (standard-library
`argparse` only) and colour auto-disables when output isn't a terminal.

### Setup

The CLI trains the model on first use, so run it with the project venv (which has
LightGBM etc.). Use the bundled launcher so you can just type `cpeds …`:

```powershell
# Windows — from the backend folder
cd backend
cpeds simulate 2

# ...or run it from anywhere by adding the backend folder to your PATH,
# then `cpeds <command>` works in any directory.
```
```bash
# macOS / Linux — from the backend folder
cd backend
./cpeds simulate 2
```

> The launcher calls the venv Python by absolute path (`.venv\Scripts\python.exe`
> on Windows), because the Microsoft Store Python build has no `activate` script.
> It never changes your working directory, so relative log paths like
> `cpeds analyze trail.json` resolve against wherever you run the command. If you
> prefer, invoke it directly: `.venv\Scripts\python.exe cli.py <command>`.

### Commands

| Command | What it does |
|---------|--------------|
| `cpeds simulate CLASS` | Generate a synthetic attack (`CLASS` 0–4) and score it. `--randomize`, `--show-log`. |
| `cpeds predict FILE` | Score a single CloudTrail event from a file (or `-` for stdin). |
| `cpeds analyze FILE` | Batch-score a whole log file (CloudTrail/JSON/JSONL/CSV) with a summary. `--limit N`. |
| `cpeds metrics` | Show this session's **measured** model metrics (real training run). |
| `cpeds live status` | Is live AWS mode armed? Which account/identity? *(works without boto3)* |
| `cpeds live poll` | Score real CloudTrail and stage pending threats. `--minutes N` look-back (default 60). |
| `cpeds live contain` | Execute a real, reversible IAM revoke. `--principal ARN --class N` (asks to confirm). |
| `cpeds live undo` | Reverse a containment. `--username U` (`--policy` defaults to `CPEDS-Quarantine`). |

### Global flags & scripting

- `--json` — machine-readable JSON on **stdout**; all human status text goes to
  **stderr**, so pipes stay clean (`cpeds analyze trail.json --json | jq .summary`).
- `--no-color` — disable ANSI colour (also honours the `NO_COLOR` env var).
- `--fail-on-threat` — exit code **2** if a threat is detected, for CI gates.
  Both flags may appear before *or* after the subcommand.

**Exit codes:** `0` success · `1` error (bad input, file not found, guardrail
refused) · `2` threat detected with `--fail-on-threat`, or a live action failed.

```bash
# score a file, fail the build if anything non-benign is found
cpeds analyze cloudtrail-export.json --fail-on-threat

# pipe an event in from another tool and get JSON out
cat event.json | cpeds predict - --json | jq '.prediction.class_label'
```

### Live containment from the CLI (safe by default)

`cpeds live contain` is the CLI equivalent of the dashboard's **two-click
approval**: it prints a red preview of exactly what will change (deactivate the
principal's access keys + attach a deny-all `CPEDS-Quarantine` policy) and does
**nothing** until you type `yes` (or pass `--yes` for non-interactive use). It
runs through the **same safety gate** as everything else — protected-principals
denylist, blast-radius cap, and threshold — and raises a guardrail error (exit 1)
rather than touching a protected identity. Every action is reversible with
`cpeds live undo`. Live mode only activates when the backend host is armed with
`CONTAINMENT_MODE=live` and sandbox credentials; otherwise `live` commands report
`MOCK` and refuse to act. See [`LIVE_AWS_RUNBOOK.md`](LIVE_AWS_RUNBOOK.md) for the
full live-AWS workflow.

---

## 📁 Project Structure

```
cpeds-x/
├── backend/
│   ├── main.py                    FastAPI app + REST endpoints (ML routes gated by auth)
│   ├── cli.py                     In-process command-line interface (same engine, no server)
│   ├── cpeds / cpeds.bat          `cpeds …` launchers (macOS/Linux · Windows)
│   ├── auth/
│   │   ├── routes.py              signup / login / me / forgot- & reset-password
│   │   ├── security.py            password hashing (bcrypt→PBKDF2) + JWT (PyJWT→stdlib)
│   │   ├── database.py            storage dispatcher (picks SQLite or Supabase)
│   │   ├── _store_sqlite.py       local SQLite store (dev default)
│   │   ├── _store_supabase.py     Supabase/Postgres store (production)
│   │   └── _store_base.py         shared DuplicateEmailError + helpers
│   ├── supabase_schema.sql        run once in Supabase SQL editor
│   ├── .env.example               JWT_SECRET_KEY + SUPABASE_URL/KEY template
│   ├── ml_engine/
│   │   ├── model.py               LightGBM + ensemble train/inference
│   │   ├── preprocessor.py        28-feature extractor + SMOTE + synth generator
│   │   ├── log_ingest.py          upload parser (CloudTrail/JSON/JSONL/CSV → events)
│   │   ├── shap_explainer.py      SHAP top-5 local attributions
│   │   └── genai_copilot.py       OpenAI/Ollama + template SOC summaries
│   ├── attack_scenarios.py        purple-team multi-step attack-chain catalog
│   ├── playbooks/
│   │   └── mitigation.py          Containment playbooks (mock boto3 / LocalStack)
│   ├── Dockerfile                 Render / HF Spaces container
│   ├── Procfile                   Render native-runtime alternative
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx                Auth gate → tab shell
│   │   ├── api.js                 Axios client + JWT interceptor (VITE_API_BASE_URL)
│   │   ├── context/
│   │   │   └── AuthContext.jsx    Session state (token persistence + restore)
│   │   ├── utils/
│   │   │   └── socReport.js       Client-side printable SOC report (Save-as-PDF)
│   │   └── components/
│   │       ├── Header.jsx         Title + status badge + user menu / sign-out
│   │       ├── auth/              Secure-access screen (login/signup/forgot/reset)
│   │       ├── AttackSimulator.jsx  Tab 1: simulate + live log stream
│   │       ├── ScenarioRunner.jsx   Tab 2: purple-team multi-step attack chains
│   │       ├── LogAnalysis.jsx    Tab 3: upload real logs → batch triage + export
│   │       ├── IncidentHistory.jsx  Tab 4: per-user case log + SOC report download
│   │       ├── XAIView.jsx        Tab 5: SHAP chart + GenAI + mitigation
│   │       ├── AttackMap.jsx      Tab 6: kill-chain node graph
│   │       └── MetricsView.jsx    Tab 7: benchmarks + confusion matrix
│   ├── vercel.json
│   └── package.json
└── render.yaml                    One-click Render blueprint
```

---

## 🚀 Local Development

### Backend

```bash
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The server trains the models on startup (a few seconds), then:
- API docs: http://localhost:8000/docs
- Health:   http://localhost:8000/api/v1/health

### Frontend

```bash
cd frontend
npm install
cp .env.example .env      # points to http://localhost:8000
npm run dev
```

Open http://localhost:5173

### Automated containment — safe by default (never touches live AWS)

The containment playbook (`playbooks/mitigation.py`) runs when a threat clears the
gate (confidence ≥ 0.75 and class ≠ C0). It has two modes, and **the default is
completely safe for a live demo in front of externals**:

| Mode | How to enable | What it does |
|------|---------------|--------------|
| **Mock** *(default)* | nothing — this is the default | Simulates the real AWS API calls (IAM session revoke + EC2 quarantine SG) and returns a realistic `"mode": "mock"` result. Zero cost, zero risk, can't fail live. |
| **LocalStack** | `USE_LOCALSTACK=1` + LocalStack running | Issues **real boto3 calls** against a **local** AWS emulator (`localhost:4566`, dummy `test`/`test` creds). Proves the code makes genuine cloud-API calls — still free, still isolated. |

> ⚠️ **Do not point this at a real AWS account for a demo.** A live account risks
> real credentials, real cost, and genuinely destructive IAM/EC2 changes if the
> model fires on a benign event — and any live-API hiccup breaks your
> presentation. Mock mode (or LocalStack) shows the exact same playbook logic and
> output without any of that exposure. If LocalStack is enabled but unreachable,
> the engine automatically and silently falls back to mock mode.

**Optional — exercise real boto3 calls via LocalStack (still free):**

```bash
pip install localstack
localstack start          # emulates AWS on :4566
```

Then start the backend with `USE_LOCALSTACK=1` set in the environment:

```bash
# macOS/Linux:
USE_LOCALSTACK=1 uvicorn main:app --port 8000
```
```powershell
# Windows PowerShell (set the var first, then run on the next line):
$env:USE_LOCALSTACK = "1"
uvicorn main:app --port 8000
```

### Optional: GenAI co-pilot

```bash
# OpenAI:
export OPENAI_API_KEY=sk-...
# or local Ollama (free):
ollama run llama3
export OLLAMA_URL=http://localhost:11434
```
Without either, a deterministic template summary is used.

---

## 🔌 API Endpoints

**Authentication** (public):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/signup`          | Create an account → returns JWT |
| `POST` | `/api/v1/auth/login`           | Sign in → returns JWT |
| `GET`  | `/api/v1/auth/me`              | Current user (send `Authorization: Bearer <token>`) |
| `POST` | `/api/v1/auth/forgot-password` | Issue a single-use reset token |
| `POST` | `/api/v1/auth/reset-password`  | Set a new password with that token |

**Detection** (require `Authorization: Bearer <token>`):

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/v1/health`         | Service + model status *(public)* |
| `POST` | `/api/v1/simulate`       | Generate synthetic log `{threat_class: 0-4}` |
| `POST` | `/api/v1/predict`        | Classify log → prediction + SHAP + summary + auto-mitigate |
| `POST` | `/api/v1/analyze`        | **Batch-classify an uploaded log file** (CloudTrail/JSON/JSONL/CSV) |
| `GET`  | `/api/v1/analyze/sample` | Realistic mixed CloudTrail export for the upload demo |
| `GET`  | `/api/v1/scenarios`      | Purple-team attack-chain catalog |
| `POST` | `/api/v1/scenario/run`   | Run one step of a multi-step attack scenario |
| `POST` | `/api/v1/explain`        | SHAP top-5 for a scaled vector |
| `POST` | `/api/v1/mitigate`       | Trigger containment (gated ≥ 0.75, class ≠ C0) |
| `GET`  | `/api/v1/incidents`      | List the caller's saved incident history |
| `GET`  | `/api/v1/incidents/{id}` | Fetch one saved incident (owner-scoped) |
| `DELETE` | `/api/v1/incidents`    | Clear the caller's incident history |
| `GET`  | `/api/v1/metrics`        | Benchmark + measured metrics |

---

## 🔐 Authentication

The dashboard sits behind a real account system, so the app opens on a
professional secure-access screen (sign in · create account · forgot password)
and only reveals the SOC console after login.

- **Passwords** are hashed with **bcrypt** (falls back to stdlib PBKDF2-SHA256
  with 260k iterations if the `bcrypt` wheel isn't installed).
- **Sessions** use **JWT** (HS256, 12-hour expiry) via **PyJWT** (falls back to a
  stdlib HS256 implementation — tokens are interchangeable either way).
- **Storage is pluggable:** local development uses a **SQLite** file
  (`backend/cpeds_users.db`, auto-created, git-ignored) with zero setup. When
  `SUPABASE_URL` + `SUPABASE_KEY` are set, the same code path switches to a
  **Supabase (Postgres)** database — required for Render/Vercel hosting, whose
  filesystems are ephemeral and would otherwise wipe every account. The backend
  uses the **service_role** key (never exposed to the frontend) and Row Level
  Security locks the tables down against the anon key.
- The whole auth layer runs with **zero extra installs** locally thanks to the
  stdlib fallbacks, and transparently upgrades to bcrypt/PyJWT/Supabase when
  they're present.

> ⚠️ **Demo password reset:** with no mail server in this build, the
> `forgot-password` endpoint returns a single-use, time-limited (30 min) reset
> token directly in the response so the UI can complete the flow. In production
> you'd email a reset link instead. The token security (single-use, expiring,
> no account enumeration) is real either way.

**Production hardening:** set a strong `JWT_SECRET_KEY` in the backend
environment (a random default is used for local dev), and replace
`allow_origins=["*"]` with your Vercel domain.

### Switching storage to Supabase (one-time setup)

1. Create a free project at [supabase.com](https://supabase.com).
2. Open **SQL Editor** → run [`backend/supabase_schema.sql`](backend/supabase_schema.sql)
   (creates `users` + `password_resets` and enables Row Level Security).
3. **Project Settings → API**: copy the Project URL and the **service_role**
   key (secret — server-side only, never in the frontend).
4. Set `SUPABASE_URL` and `SUPABASE_KEY` in the backend environment
   (Render → Environment, or locally in `backend/.env` — see
   [`backend/.env.example`](backend/.env.example)).
5. Restart the backend. `GET /api/v1/health` now reports
   `"auth_backend": "supabase"`; leave the vars unset and it reports `"sqlite"`.

---

## ☁️ Free Deployment

### Backend → Render.com (free)

1. Push this repo to GitHub.
2. Render Dashboard → **New → Blueprint** → select the repo (uses `render.yaml`),
   **or** New → Web Service → Docker → root `backend/`.
3. In Render, add the environment variables: `JWT_SECRET_KEY` (required),
   `SUPABASE_URL`, `SUPABASE_KEY` (see above).
4. Deploy. Note your URL, e.g. `https://cpeds-x-backend.onrender.com`.
   > Free instances sleep after 15 min idle (~50s cold start on first hit).
   > User accounts live in Supabase now, so sleeping/cold-starting never
   > loses data.

**CORS:** already enabled in `main.py`. For production, replace
`allow_origins=["*"]` with your Vercel domain.

### Frontend → Vercel (free)

```bash
cd frontend
npm i -g vercel
vercel            # follow prompts (framework auto-detected as Vite)
```

In **Vercel → Project → Settings → Environment Variables**, add:

```
VITE_API_BASE_URL = https://cpeds-x-backend.onrender.com
```

Redeploy so the frontend targets your live backend.

---

## 📊 Paper Baseline (reference)

| Model | Accuracy | Notes |
|-------|----------|-------|
| **LightGBM** | **97.0%** | Primary, leaf-wise |
| XGBoost | 93.1% | Ensemble |
| AdaBoost | 88.4% | Ensemble |
| Random Forest | 86.2% | Ensemble |
| ROC-AUC | 0.990 | — |
| Macro F1 | 96.2% | — |
| MTTC | < 30s | Mean Time to Containment |

---

## 🧰 Tech Stack

**Backend:** FastAPI · Uvicorn · LightGBM · XGBoost · scikit-learn ·
imbalanced-learn · SHAP · boto3 · Pydantic
**Frontend:** React · Vite · Tailwind CSS · Recharts · Lucide · Axios
**Infra (free):** Render / Hugging Face Spaces · Vercel · LocalStack

## 💰 Cost: **$0.00** on hobby/academic free tiers.
