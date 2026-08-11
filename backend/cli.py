#!/usr/bin/env python3
"""
CPEDS-X — command-line interface (in-process).

Same engine as the API and the web dashboard, driven from your terminal. No
server and no login required: this imports the trained classifier, the log
parser, and the live-containment safety gate directly and runs them locally.

    cpeds simulate 2                 # generate a C2 attack and score it
    cpeds predict event.json         # score one CloudTrail event
    cpeds analyze trail.json         # batch-score a whole log file
    cpeds metrics                    # this session's real model accuracy
    cpeds live status                # is live AWS mode armed?
    cpeds live poll --minutes 60     # score real CloudTrail, stage threats
    cpeds live contain --principal arn:...:user/cpeds-victim --class 1
    cpeds live undo --username cpeds-victim
    cpeds sandbox run                # create+attack a throwaway victim for a demo
    cpeds sandbox teardown           # delete the throwaway victim afterward

Design notes
------------
* In-process: reuses ml_engine.model / preprocessor / log_ingest / live_watcher
  and playbooks.mitigation — no code is duplicated from the API.
* Zero new dependencies: standard-library argparse only. Colour auto-disables
  when output isn't a TTY or NO_COLOR is set.
* Safe by default: `live contain` is the CLI equivalent of the dashboard's
  two-click approval — it prints a preview and requires an explicit yes (or
  --yes) before any real IAM change. It runs through the SAME safety gate
  (threshold, protected-principals denylist, blast cap) as everything else.
* Machine-friendly: pass --json for structured output on stdout; all human
  status text goes to stderr so pipes stay clean.

Run it with the project venv (Microsoft Store Python has no activate script):

    .venv\\Scripts\\python.exe cli.py <command>      (Windows)

…or just use the bundled `cpeds.bat` wrapper so you can type `cpeds <command>`.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys

# ----------------------------------------------------------------------
# Output helpers (colour, stderr status, JSON mode)
# ----------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None


class C:
    """ANSI colour codes; blanked out when colour is disabled."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOR or not codes:
        return text
    return "".join(codes) + text + C.RESET


def eprint(*args, **kwargs) -> None:
    """Print human status to stderr, so --json stdout stays machine-clean."""
    print(*args, file=sys.stderr, **kwargs)


# Per-class colour, matching the dashboard palette.
_CLASS_COLOR = {
    0: C.GREEN,     # C0 Benign
    1: C.YELLOW,    # C1 Horizontal
    2: C.RED,       # C2 Vertical
    3: C.MAGENTA,   # C3 Exfiltration
    4: C.YELLOW,    # C4 Lateral
}


def _fmt_class(pred_class: int, label: str) -> str:
    return _c(label, _CLASS_COLOR.get(pred_class, ""), C.BOLD)


def _die(msg: str, code: int = 1):
    eprint(_c("error: ", C.RED, C.BOLD) + msg)
    sys.exit(code)


def _fmt_actions(actions) -> str:
    """Render the mitigation 'actions' list as a readable one-liner.

    Live contain/undo return actions as a list of dicts (action/status/detail);
    older/mock paths may return plain strings. Handle both so the human summary
    never crashes on join. The --json output is unaffected (it dumps raw dicts).
    """
    parts = []
    for a in actions or []:
        if isinstance(a, dict):
            parts.append(a.get("detail") or a.get("action") or str(a))
        else:
            parts.append(str(a))
    return ", ".join(parts) or "—"


# ----------------------------------------------------------------------
# Lazy engine access (keeps heavy ML libs out of the fast paths)
# ----------------------------------------------------------------------
def _engine_import_die(e: Exception):
    """Friendly, consistent error when a heavy ml_engine import fails — almost
    always because the CLI was run with the wrong Python instead of the venv."""
    _die(f"could not import the model engine ({e}). "
         f"Run with the project venv: .venv\\Scripts\\python.exe cli.py …")


def _get_clf():
    """Return the trained singleton classifier.

    First call trains the model (a few seconds). Training chatter is redirected
    to stderr so it never pollutes --json output on stdout.
    """
    eprint(_c("• training model (first run may take a few seconds)…", C.DIM))
    try:
        from ml_engine.model import get_classifier
    except Exception as e:  # pragma: no cover - import/env dependent
        _engine_import_die(e)
    with contextlib.redirect_stdout(sys.stderr):
        clf = get_classifier()
    return clf


def _parse_events(raw: str, filename: str = ""):
    from ml_engine.log_ingest import parse_logs, LogParseError
    try:
        return parse_logs(raw, fmt="auto", filename=filename)
    except LogParseError as e:
        _die(f"could not parse logs: {e}")


def _read_source(path: str) -> str:
    """Read a file, or stdin when path is '-'."""
    if path == "-":
        return sys.stdin.read()
    if not os.path.exists(path):
        _die(f"file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_simulate(args) -> int:
    if args.threat_class not in range(5):
        _die("class must be 0, 1, 2, 3 or 4")
    try:
        from ml_engine.preprocessor import generate_synthetic_audit_log
    except Exception as e:  # pragma: no cover - import/env dependent
        _engine_import_die(e)
    log = generate_synthetic_audit_log(args.threat_class, randomize=args.randomize)
    clf = _get_clf()
    pred = clf.predict(log)
    if args.json:
        print(json.dumps({"audit_log": log, "prediction": pred}, indent=2))
        return 0
    _print_verdict(pred, event_name=log.get("eventName"),
                   principal=_principal_of(log))
    if args.show_log:
        eprint(_c("\n--- synthetic event ---", C.DIM))
        print(json.dumps(log, indent=2))
    return _threat_exit(pred, args)


def cmd_predict(args) -> int:
    raw = _read_source(args.source)
    events = _parse_events(raw, filename="" if args.source == "-" else args.source)
    if not events:
        _die("no events found in input")
    clf = _get_clf()
    if len(events) > 1:
        eprint(_c(f"• {len(events)} events found — scoring the first. "
                  f"Use `analyze` for the whole file.", C.DIM))
    pred = clf.predict(events[0])
    if args.json:
        print(json.dumps({"prediction": pred}, indent=2))
        return 0
    _print_verdict(pred, event_name=events[0].get("eventName"),
                   principal=_principal_of(events[0]))
    return _threat_exit(pred, args)


def cmd_analyze(args) -> int:
    raw = _read_source(args.source)
    events = _parse_events(raw, filename="" if args.source == "-" else args.source)
    if not events:
        _die("no events found in input")
    clf = _get_clf()
    limit = args.limit or len(events)
    rows, threats = [], 0
    for ev in events[:limit]:
        p = clf.predict(ev)
        is_threat = p["predicted_class"] != 0
        threats += int(is_threat)
        rows.append({
            "event_name": ev.get("eventName", "—"),
            "principal": _principal_of(ev),
            "predicted_class": p["predicted_class"],
            "class_label": p["class_label"],
            "confidence": p["confidence"],
            "action": ("CONTAINED" if is_threat and p["confidence"] >= 0.75
                       else "MONITORED"),
        })
    summary = {
        "analyzed": len(rows),
        "total": len(events),
        "threats": threats,
        "benign": len(rows) - threats,
        "avg_confidence": round(sum(r["confidence"] for r in rows) / len(rows), 4)
        if rows else 0.0,
    }
    if args.json:
        print(json.dumps({"summary": summary, "results": rows}, indent=2))
        return 0
    _print_analyze_table(rows, summary)
    if args.fail_on_threat and threats:
        return 2
    return 0


def cmd_metrics(args) -> int:
    clf = _get_clf()
    measured = getattr(clf, "measured_metrics", None) or {}
    if args.json:
        print(json.dumps({"measured": measured}, indent=2))
        return 0
    eprint()
    print(_c("CPEDS-X model — measured metrics (this session's training run)",
             C.BOLD))
    if not measured:
        eprint(_c("no measured metrics available", C.DIM))
        return 0
    for k in ("accuracy", "macro_f1", "weighted_f1", "roc_auc"):
        if k in measured:
            print(f"  {k:<14} {_c(f'{measured[k]:.4f}', C.CYAN, C.BOLD)}")
    # Print anything else we didn't explicitly format.
    for k, v in measured.items():
        if k not in ("accuracy", "macro_f1", "weighted_f1", "roc_auc") \
                and isinstance(v, (int, float)):
            print(f"  {k:<14} {v}")
    return 0


# ---- live subcommands -------------------------------------------------
def cmd_live_status(args) -> int:
    from ml_engine import live_watcher
    st = live_watcher.live_ready()
    if args.json:
        print(json.dumps(st, indent=2))
        return 0
    ready = st.get("ready")
    eprint()
    chip = _c(" LIVE ARMED ", C.GREEN, C.BOLD) if ready \
        else _c(f" {str(st.get('mode', 'mock')).upper()} ", C.YELLOW, C.BOLD)
    print(f"Live containment: {chip}")
    if ready:
        ident = st.get("identity") or {}
        print(f"  account   {_c(ident.get('account', '—'), C.CYAN)}")
        print(f"  identity  {ident.get('arn', '—')}")
    else:
        print(f"  reason    {st.get('reason', 'not armed')}")
        eprint(_c("  arm it with CONTAINMENT_MODE=live + cpeds-responder creds "
                  "on a sandbox account.", C.DIM))
    return 0


def cmd_live_poll(args) -> int:
    from ml_engine import live_watcher
    clf = _get_clf()
    result = live_watcher.evaluate(clf, minutes=args.minutes)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    verdicts = result.get("verdicts", [])
    eprint()
    print(_c(f"CloudTrail verdicts — {result.get('events_seen', len(verdicts))} "
             f"events, {result.get('pending_count', 0)} pending "
             f"({result.get('polled_minutes', args.minutes)} min look-back)",
             C.BOLD))
    if not result.get("ready"):
        eprint(_c(f"  {result.get('status_reason', 'live mode not armed')}", C.DIM))
    if not verdicts:
        eprint(_c("  no events in the look-back window.", C.DIM))
        return 0
    for v in verdicts:
        _print_verdict_line(v)
    eprint(_c("\nConfirm a pending threat with: "
              "cpeds live contain --principal <arn> --class <n>", C.DIM))
    return 0


def cmd_live_contain(args) -> int:
    from ml_engine import live_watcher
    st = live_watcher.live_ready()
    if not st.get("ready"):
        _die(f"live mode is not armed ({st.get('mode', 'mock')}): "
             f"{st.get('reason', '')}. "
             f"Set CONTAINMENT_MODE=live with cpeds-responder creds.")
    if args.threat_class not in range(5):
        _die("class must be 0, 1, 2, 3 or 4")

    principal = args.principal
    username = principal.split("/")[-1].split(":")[-1]

    # The CLI equivalent of the dashboard's two-click approval.
    eprint()
    eprint(_c("⚠  Real IAM revoke — preview", C.RED, C.BOLD))
    eprint(f"   principal : {_c(principal, C.YELLOW)}")
    eprint(f"   class     : {args.threat_class}   confidence: {args.confidence}")
    eprint("   on confirm, CPEDS-X will:")
    eprint(f"     • set every access key on {_c(username, C.YELLOW)} to Inactive")
    eprint("     • attach a deny-all CPEDS-Quarantine inline policy")
    eprint(_c("   reversible with: cpeds live undo --username " + username, C.DIM))

    if not args.yes:
        try:
            ans = input(_c("\nType 'yes' to execute the real revoke: ", C.BOLD))
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans.strip().lower() != "yes":
            eprint(_c("aborted — nothing was changed.", C.DIM))
            return 1

    try:
        result = live_watcher.confirm_containment(
            principal, args.threat_class, confidence=args.confidence)
    except PermissionError as e:
        _die(f"guardrail refused the action: {e}")
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"containment failed: {e}", code=2)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    eprint()
    print(_c("✓ CONTAINED on live AWS", C.GREEN, C.BOLD))
    print(f"  principal   {username}")
    print(f"  actions     {_fmt_actions(result.get('actions'))}")
    print(f"  blast room  {result.get('blast_room', '—')}")
    print(_c(f"  undo with   cpeds live undo --username {username}", C.CYAN))
    return 0


def cmd_live_undo(args) -> int:
    from ml_engine import live_watcher
    rollback = {
        "kind": "iam_user",
        "username": args.username,
        "policy_name": args.policy,
    }
    try:
        result = live_watcher.undo_containment(rollback)
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"undo failed: {e}", code=2)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    eprint()
    print(_c("✓ REVERSED", C.GREEN, C.BOLD))
    print(f"  principal  {args.username}")
    print(f"  actions    {_fmt_actions(result.get('actions'))}")
    return 0


# ----------------------------------------------------------------------
# sandbox <sub> — the fixture half of the live demo (create/attack/verify/
# teardown the throwaway victim). These are the ONLY CLI commands that make
# *creative* AWS writes, so each mutating one previews the target account and
# asks for a typed 'yes' (or --yes), exactly like `live contain`. They never
# touch the live-containment code paths.
# ----------------------------------------------------------------------
def _sandbox_import():
    try:
        import sandbox_fixtures as sbx
        return sbx
    except Exception as e:  # pragma: no cover - import/env dependent
        _die(f"could not import sandbox fixtures ({e}). "
             f"Run with the project venv: .venv\\Scripts\\python.exe cli.py …")


def _sandbox_preview(sbx, profile, region) -> Dict:
    """Print which real account we're about to write to; return the identity."""
    who = sbx.whoami(profile=profile, region=region)
    if who.get("ok"):
        eprint(_c("  account   ", C.DIM) + _c(str(who.get("account", "—")), C.CYAN))
        eprint(_c("  identity  ", C.DIM) + str(who.get("arn", "—")))
        eprint(_c("  profile   ", C.DIM) + str(who.get("profile") or "(default chain)"))
    else:
        eprint(_c("  account   ", C.DIM) + _c("unknown", C.YELLOW) +
               _c(f"  ({who.get('reason', '')})", C.DIM))
    return who


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        ans = input(_c(prompt, C.BOLD))
    except (EOFError, KeyboardInterrupt):
        ans = ""
    return ans.strip().lower() == "yes"


def _guard_or_die(sbx, username: str) -> None:
    """Reject an unsafe target name before any preview/confirmation/AWS call."""
    try:
        sbx.assert_safe_name(username)
    except sbx.SandboxError as e:
        _die(str(e))


def cmd_sandbox_setup(args) -> int:
    sbx = _sandbox_import()
    _guard_or_die(sbx, args.username)
    eprint()
    eprint(_c("Sandbox setup — create throwaway attacker user", C.BOLD))
    eprint(f"   user      : {_c(args.username, C.YELLOW)}")
    eprint("   will      : create user • attach IAMFullAccess • mint an access key")
    who = _sandbox_preview(sbx, args.profile, args.region)
    if not who.get("ok"):
        _die("cannot reach AWS with that profile — configure it and retry "
             "(aws configure --profile " + (args.profile or "<name>") + ").")
    eprint(_c("   this creates a REAL IAM user in the account above.", C.RED))

    if not _confirm("\nType 'yes' to create it: ", args.yes):
        eprint(_c("aborted — nothing was created.", C.DIM))
        return 1
    try:
        res = sbx.setup_victim(username=args.username, profile=args.profile,
                               region=args.region,
                               attach_policy=not args.no_policy)
    except sbx.SandboxError as e:
        _die(str(e))
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"setup failed: {e}", code=2)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    eprint()
    print(_c("✓ SANDBOX USER READY", C.GREEN, C.BOLD))
    print(f"  username          {res['username']}")
    print(f"  access_key_id     {res['access_key_id']}")
    print(f"  secret_access_key {res['secret_access_key']}")
    eprint(_c("  ↑ shown once — it is NOT saved anywhere. Copy it if you want to "
              "run the attack from a saved profile.", C.DIM))
    eprint(_c(f"  next: cpeds sandbox attack --username {res['username']} "
              f"--access-key-id {res['access_key_id']} --secret-access-key <secret>",
              C.CYAN))
    return 0


def cmd_sandbox_attack(args) -> int:
    sbx = _sandbox_import()
    _guard_or_die(sbx, args.username)
    try:
        spec = sbx.describe_attack(args.kind)
    except sbx.SandboxError as e:
        _die(str(e))
    eprint()
    eprint(_c(f"Sandbox attack — {spec['event_name']} as the victim", C.BOLD))
    eprint(f"   user      : {_c(args.username, C.YELLOW)}")
    eprint(f"   kind      : {_c(spec['kind'], C.YELLOW)}  → expect "
           f"{_c(spec['expected_label'], C.YELLOW)}")
    eprint(f"   effect    : {spec['summary']}")
    if spec["kind"] == "exfil":
        eprint(_c("   caveat    : the victim has no secrets permission, so this is "
                  "usually AccessDenied — logged, but may score below the 0.75 "
                  "gate (monitored, not contained).", C.DIM))
    if not (args.victim_profile or (args.access_key_id and args.secret_access_key)):
        _die("need the victim's identity: pass --victim-profile, or both "
             "--access-key-id and --secret-access-key (from `sandbox setup`).")

    if not _confirm("\nType 'yes' to run the attack action: ", args.yes):
        eprint(_c("aborted — nothing happened.", C.DIM))
        return 1
    try:
        res = sbx.run_attack(username=args.username,
                             kind=args.kind,
                             victim_profile=args.victim_profile,
                             access_key_id=args.access_key_id,
                             secret_access_key=args.secret_access_key,
                             region=args.region,
                             secret_id=args.secret_id)
    except sbx.SandboxError as e:
        _die(str(e))
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"attack failed: {e}", code=2)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    eprint()
    print(_c("✓ ATTACK ACTION RECORDED", C.GREEN, C.BOLD))
    print(f"  username     {res['username']}")
    print(f"  event        {res['event_name']} → expect {res['expected_label']}")
    print(f"  attempts     {res['attempts']}")
    eprint(_c("  " + res["note"], C.DIM))
    eprint(_c("  next: wait ~5-15 min, then  cpeds live poll --minutes 60", C.CYAN))
    eprint(_c(f"        cpeds live contain --principal {res['username']} "
              f"--class {res['expected_class']}", C.CYAN))
    return 0


def cmd_sandbox_verify(args) -> int:
    sbx = _sandbox_import()
    try:
        res = sbx.verify(username=args.username, profile=args.profile,
                         region=args.region)
    except sbx.SandboxError as e:
        _die(str(e))
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"verify failed: {e}", code=2)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    eprint()
    state = _c(" CONTAINED ", C.RED, C.BOLD) if res["contained"] \
        else _c(" ACTIVE ", C.GREEN, C.BOLD)
    print(f"Sandbox user {_c(res['username'], C.YELLOW)}: {state}")
    for k in res["access_keys"]:
        col = C.RED if k["status"] == "Inactive" else C.GREEN
        print(f"  key {k['access_key_id']}  {_c(k['status'], col)}")
    print(f"  inline policies   {', '.join(res['inline_policies']) or '—'}")
    print(f"  managed policies  {', '.join(res['managed_policies']) or '—'}")
    return 0


def cmd_sandbox_teardown(args) -> int:
    sbx = _sandbox_import()
    _guard_or_die(sbx, args.username)
    eprint()
    eprint(_c("Sandbox teardown — fully delete the throwaway user", C.BOLD))
    eprint(f"   user      : {_c(args.username, C.YELLOW)}")
    eprint("   will      : delete keys • delete inline policies • detach managed • delete user")
    who = _sandbox_preview(sbx, args.profile, args.region)
    if not who.get("ok"):
        _die("cannot reach AWS with that profile — configure it and retry.")

    if not _confirm("\nType 'yes' to delete it: ", args.yes):
        eprint(_c("aborted — nothing was deleted.", C.DIM))
        return 1
    try:
        res = sbx.teardown(username=args.username, profile=args.profile,
                           region=args.region)
    except sbx.SandboxError as e:
        _die(str(e))
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"teardown failed: {e}", code=2)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    eprint()
    print(_c("✓ TORN DOWN", C.GREEN, C.BOLD))
    print(f"  username  {res['username']}")
    for a in res["actions"]:
        mark = {"success": "✓", "skipped": "·", "exists": "·"}.get(a["status"], "✗")
        print(f"    {mark} {a['action']}: {a['detail']}")
    return 0


def cmd_sandbox_run(args) -> int:
    """setup + attack in one go (the fixture side of the demo), leaving you ready
    to poll. Uses the freshly minted key in-memory to attribute the attack, so
    no profile juggling is needed."""
    sbx = _sandbox_import()
    _guard_or_die(sbx, args.username)
    try:
        spec = sbx.describe_attack(args.kind)
    except sbx.SandboxError as e:
        _die(str(e))
    eprint()
    eprint(_c("Sandbox run — setup → attack (then poll/contain/undo yourself)", C.BOLD))
    eprint(f"   user      : {_c(args.username, C.YELLOW)}")
    eprint(f"   attack    : {_c(spec['kind'], C.YELLOW)} → {spec['event_name']} "
           f"(expect {_c(spec['expected_label'], C.YELLOW)})")
    who = _sandbox_preview(sbx, args.profile, args.region)
    if not who.get("ok"):
        _die("cannot reach AWS with that profile — configure it and retry.")
    eprint(_c(f"   creates a REAL IAM user, then performs {spec['event_name']} as it.",
              C.RED))
    if not _confirm("\nType 'yes' to run setup + attack: ", args.yes):
        eprint(_c("aborted — nothing was created.", C.DIM))
        return 1

    try:
        setup = sbx.setup_victim(username=args.username, profile=args.profile,
                                 region=args.region)
        attack = sbx.run_attack(username=args.username,
                                kind=args.kind,
                                access_key_id=setup["access_key_id"],
                                secret_access_key=setup["secret_access_key"],
                                region=args.region,
                                secret_id=args.secret_id)
    except sbx.SandboxError as e:
        _die(str(e))
    except Exception as e:  # pragma: no cover - AWS/runtime dependent
        _die(f"run failed: {e}", code=2)

    result = {"setup": setup, "attack": attack}
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    eprint()
    print(_c("✓ FIXTURE READY", C.GREEN, C.BOLD))
    print(f"  username     {setup['username']}")
    print(f"  attack       {attack['event_name']} → expect {attack['expected_label']}")
    eprint(_c("  next: wait ~5-15 min, then", C.DIM))
    eprint(_c("    cpeds live poll --minutes 60", C.CYAN))
    eprint(_c(f"    cpeds live contain --principal {setup['username']} "
              f"--class {attack['expected_class']}", C.CYAN))
    eprint(_c(f"    cpeds live undo --username {setup['username']}", C.CYAN))
    eprint(_c(f"    cpeds sandbox teardown --username {setup['username']}", C.CYAN))
    return 0


# ----------------------------------------------------------------------
# Pretty-printers
# ----------------------------------------------------------------------
def _principal_of(log: dict) -> str:
    ui = log.get("userIdentity", {}) if isinstance(log, dict) else {}
    return ui.get("arn") or ui.get("userName") or "unknown-principal"


def _print_verdict(pred: dict, event_name=None, principal=None) -> None:
    eprint()
    pc = pred["predicted_class"]
    print(f"{_c('verdict  ', C.DIM)}{_fmt_class(pc, pred['class_label'])}")
    print(f"{_c('confidence', C.DIM)} {pred['confidence'] * 100:.1f}%")
    if event_name:
        print(f"{_c('event    ', C.DIM)} {event_name}")
    if principal:
        print(f"{_c('principal', C.DIM)} {principal}")
    print(f"{_c('latency  ', C.DIM)} {pred.get('execution_latency_ms', '—')} ms")
    # Top probabilities
    probs = pred.get("probabilities") or {}
    if probs:
        top = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)[:3]
        bar = "  ".join(f"{k.split(':')[0]} {v * 100:.0f}%" for k, v in top)
        print(f"{_c('top      ', C.DIM)} {bar}")


def _print_verdict_line(v: dict) -> None:
    pc = v.get("predicted_class", 0)
    label = v.get("class_label", "—")
    decision = (v.get("decision") or {}).get("status", "monitor")
    conf = v.get("confidence", 0) * 100
    tag = {
        "pending": _c("PENDING", C.RED, C.BOLD),
        "blocked": _c("GUARDED", C.YELLOW),
        "monitor": _c("monitored", C.DIM),
    }.get(decision, decision)
    name = (v.get("event_name") or "—")[:22].ljust(22)
    print(f"  {name} {_fmt_class(pc, label.split(':')[0]):<22} "
          f"{conf:5.1f}%  {tag}")
    print(_c(f"      {v.get('principal', '—')} · {v.get('source_ip', 'no-ip')}",
             C.DIM))


def _print_analyze_table(rows, summary) -> None:
    eprint()
    print(_c(f"Analyzed {summary['analyzed']}/{summary['total']} events — "
             f"{summary['threats']} threats, {summary['benign']} benign, "
             f"avg conf {summary['avg_confidence'] * 100:.1f}%", C.BOLD))
    print(_c("─" * 64, C.DIM))
    for r in rows:
        flag = _c("⚠", C.RED) if r["predicted_class"] != 0 else _c("·", C.GREEN)
        name = r["event_name"][:24].ljust(24)
        print(f" {flag} {name} {_fmt_class(r['predicted_class'], r['class_label'].split(':')[0]):<20} "
              f"{r['confidence'] * 100:5.1f}%  {r['action']}")


def _threat_exit(pred: dict, args) -> int:
    if getattr(args, "fail_on_threat", False) and pred["predicted_class"] != 0:
        return 2
    return 0


# ----------------------------------------------------------------------
# Argument parser
# ----------------------------------------------------------------------
def build_parser():
    """Build the top-level parser. Returns (parser, live_subparser) so main()
    can print the `live` help when no action is given."""
    # Shared flags usable before OR after the subcommand.
    # default=SUPPRESS so a flag given BEFORE the subcommand (cpeds --json foo)
    # isn't clobbered by the subparser re-applying its own default. We normalize
    # the two flags with getattr() in main().
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable JSON on stdout")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="disable coloured output")

    p = argparse.ArgumentParser(
        prog="cpeds",
        parents=[common],
        description="CPEDS-X — cloud privilege-escalation detection, from your terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  cpeds simulate 2\n"
               "  cpeds analyze trail.json --fail-on-threat\n"
               "  cpeds live status\n"
               "  cpeds live contain --principal arn:aws:iam::123:user/cpeds-victim --class 1\n"
               "  cpeds sandbox run        # create + attack a throwaway demo victim\n"
               "  cpeds sandbox teardown   # delete it afterward\n",
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")

    s = sub.add_parser("simulate", parents=[common],
                       help="generate a synthetic attack (class 0–4) and score it")
    s.add_argument("threat_class", type=int, metavar="CLASS",
                   help="0 benign, 1 horizontal, 2 vertical, 3 exfil, 4 lateral")
    s.add_argument("--randomize", action="store_true",
                   help="sample overlapping ranges instead of the canonical template")
    s.add_argument("--show-log", action="store_true",
                   help="also print the generated event")
    s.add_argument("--fail-on-threat", action="store_true",
                   help="exit code 2 if a threat is detected (CI gate)")
    s.set_defaults(func=cmd_simulate)

    s = sub.add_parser("predict", parents=[common],
                       help="score a single CloudTrail event from a file or stdin")
    s.add_argument("source", metavar="FILE",
                   help="path to a JSON/CSV log, or '-' for stdin")
    s.add_argument("--fail-on-threat", action="store_true",
                   help="exit code 2 if a threat is detected (CI gate)")
    s.set_defaults(func=cmd_predict)

    s = sub.add_parser("analyze", parents=[common],
                       help="batch-score a whole log file with a summary")
    s.add_argument("source", metavar="FILE",
                   help="path to a CloudTrail/JSON/JSONL/CSV log, or '-' for stdin")
    s.add_argument("--limit", type=int, default=0,
                   help="only score the first N events")
    s.add_argument("--fail-on-threat", action="store_true",
                   help="exit code 2 if any threat is detected (CI gate)")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("metrics", parents=[common],
                       help="show this session's measured model metrics")
    s.set_defaults(func=cmd_metrics)

    # live <sub>
    live = sub.add_parser("live", parents=[common],
                          help="real AWS containment (status/poll/contain/undo)")
    lsub = live.add_subparsers(dest="live_command", metavar="<action>")

    ls = lsub.add_parser("status", parents=[common],
                         help="is live mode armed? which account?")
    ls.set_defaults(func=cmd_live_status)

    ls = lsub.add_parser("poll", parents=[common],
                         help="score real CloudTrail and stage pending threats")
    ls.add_argument("--minutes", type=int, default=60,
                    help="look-back window in minutes (default 60)")
    ls.set_defaults(func=cmd_live_poll)

    ls = lsub.add_parser("contain", parents=[common],
                         help="execute a real, reversible IAM revoke (asks to confirm)")
    ls.add_argument("--principal", required=True,
                    help="ARN or username to contain (e.g. arn:aws:iam::123:user/cpeds-victim)")
    ls.add_argument("--class", dest="threat_class", type=int, required=True,
                    metavar="N", help="predicted threat class 1–4")
    ls.add_argument("--confidence", type=float, default=1.0,
                    help="confidence to record (default 1.0)")
    ls.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation (non-interactive use)")
    ls.set_defaults(func=cmd_live_contain)

    ls = lsub.add_parser("undo", parents=[common],
                         help="reverse a containment by username")
    ls.add_argument("--username", required=True,
                    help="the contained IAM username (e.g. cpeds-victim)")
    ls.add_argument("--policy", default="CPEDS-Quarantine",
                    help="quarantine policy name to remove (default CPEDS-Quarantine)")
    ls.set_defaults(func=cmd_live_undo)

    # sandbox <sub> — fixture half of the live demo (create/attack/verify/teardown)
    sandbox = sub.add_parser("sandbox", parents=[common],
                             help="create/attack/verify/teardown a throwaway demo victim")
    ssub = sandbox.add_subparsers(dest="sandbox_command", metavar="<action>")

    ss = ssub.add_parser("setup", parents=[common],
                         help="create the throwaway victim user + access key")
    ss.add_argument("--username", default="cpeds-victim",
                    help="victim username (must start with cpeds-; default cpeds-victim)")
    ss.add_argument("--profile", default="cpeds-responder",
                    help="AWS profile with IAM write perms (default cpeds-responder)")
    ss.add_argument("--region", default=None, help="AWS region (default us-east-1)")
    ss.add_argument("--no-policy", action="store_true",
                    help="don't attach IAMFullAccess to the victim")
    ss.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation")
    ss.set_defaults(func=cmd_sandbox_setup)

    ss = ssub.add_parser("attack", parents=[common],
                         help="run an attack AS the victim (C1/C2/C3 trigger)")
    ss.add_argument("--username", default="cpeds-victim", help="victim username")
    ss.add_argument("--kind", default="horizontal", metavar="KIND",
                    help="attack to perform: horizontal (C1 CreateAccessKey, "
                         "default), vertical (C2 self-attach AdministratorAccess), "
                         "or exfil (C3 GetSecretValue attempt). C1/C2/C3 also work.")
    ss.add_argument("--victim-profile", default=None,
                    help="a configured profile for the victim identity")
    ss.add_argument("--access-key-id", default=None,
                    help="victim access key id (from `sandbox setup`)")
    ss.add_argument("--secret-access-key", default=None,
                    help="victim secret access key (from `sandbox setup`)")
    ss.add_argument("--secret-id", default=None,
                    help="[exfil kind] Secrets Manager secret to attempt to read "
                         "(default a nonexistent name → AccessDenied-safe)")
    ss.add_argument("--region", default=None, help="AWS region (default us-east-1)")
    ss.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation")
    ss.set_defaults(func=cmd_sandbox_attack)

    ss = ssub.add_parser("verify", parents=[common],
                         help="show the victim's key statuses + policies (read-only)")
    ss.add_argument("--username", default="cpeds-victim", help="victim username")
    ss.add_argument("--profile", default="cpeds-responder", help="AWS profile")
    ss.add_argument("--region", default=None, help="AWS region (default us-east-1)")
    ss.set_defaults(func=cmd_sandbox_verify)

    ss = ssub.add_parser("teardown", parents=[common],
                         help="fully delete the throwaway victim user")
    ss.add_argument("--username", default="cpeds-victim", help="victim username")
    ss.add_argument("--profile", default="cpeds-responder", help="AWS profile")
    ss.add_argument("--region", default=None, help="AWS region (default us-east-1)")
    ss.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation")
    ss.set_defaults(func=cmd_sandbox_teardown)

    ss = ssub.add_parser("run", parents=[common],
                         help="setup + attack in one step (then poll/contain yourself)")
    ss.add_argument("--username", default="cpeds-victim", help="victim username")
    ss.add_argument("--kind", default="horizontal", metavar="KIND",
                    help="attack to perform: horizontal (C1, default), vertical "
                         "(C2), or exfil (C3). C1/C2/C3 also work.")
    ss.add_argument("--secret-id", default=None,
                    help="[exfil kind] Secrets Manager secret to attempt to read "
                         "(default a nonexistent name → AccessDenied-safe)")
    ss.add_argument("--profile", default="cpeds-responder",
                    help="AWS profile with IAM write perms (default cpeds-responder)")
    ss.add_argument("--region", default=None, help="AWS region (default us-east-1)")
    ss.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation")
    ss.set_defaults(func=cmd_sandbox_run)

    return p, live, sandbox


def main(argv=None) -> int:
    global _USE_COLOR
    parser, live_parser, sandbox_parser = build_parser()
    args = parser.parse_args(argv)

    # The shared --json/--no-color flags use default=SUPPRESS (so a value given
    # before the subcommand isn't clobbered by the subparser). That means the
    # attributes may be absent — normalize them to real booleans here before any
    # command function reads args.json.
    args.json = getattr(args, "json", False)
    args.no_color = getattr(args, "no_color", False)

    if args.no_color:
        _USE_COLOR = False

    # Bare `cpeds` or `cpeds live` / `cpeds sandbox` with no action → show help.
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if args.command == "live" and not getattr(args, "live_command", None):
        live_parser.print_help()
        return 0
    if args.command == "sandbox" and not getattr(args, "sandbox_command", None):
        sandbox_parser.print_help()
        return 0

    return args.func(args) or 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("\ninterrupted.")
        sys.exit(130)
