"""
CPEDS-X: Background retrain job manager.

Retraining rebuilds the LightGBM primary + 3 comparison models and, in REAL
mode, also runs a stratified k-fold cross-validation. On a small/imbalanced
real dataset that is heavy enough that running it *inside* the HTTP request made
the request look frozen: the browser lost its "retraining" flag on refresh while
a server thread kept training and holding the global lock, so the next click got
a bare 409 and the CV numbers never appeared.

This module runs the retrain on a background daemon thread and exposes a
thread-safe, pollable status snapshot, so the API can return immediately and the
UI can show live progress (stage + elapsed) and correctly re-disable the button
even across a page refresh.

Deliberately has NO FastAPI/HTTP dependency so it can be unit-tested in a bare
environment and reused from the CLI if ever needed. The single-flight guarantee
lives here (one retrain at a time); callers just call start() and poll status().
"""
import threading
import time
import traceback
from typing import Callable, Dict, Optional


# Public state values (kept as plain strings so the JSON status is self-describing).
IDLE = "idle"
RUNNING = "running"
DONE = "done"
ERROR = "error"


class RetrainJob:
    """
    Owns the lifecycle + status of the (at most one) in-flight retrain.

    A single instance is created in main.py and shared. All mutation goes through
    _lock, and status() returns a copy, so the poller never observes a torn
    half-updated dict. start() is non-blocking and single-flight: a second call
    while a job is RUNNING returns False rather than launching a rival thread.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._state: str = IDLE
        self._mode: Optional[str] = None
        self._stage: str = ""
        self._started_at: Optional[float] = None
        self._finished_at: Optional[float] = None
        self._error: Optional[str] = None
        # On success: the fresh model's measured metrics + training provenance,
        # shaped exactly like the old synchronous /train/reload response so the
        # frontend can consume either without special-casing.
        self._result: Optional[Dict] = None
        self._thread: Optional[threading.Thread] = None

    # -- internal: all writes hold the lock -------------------------------
    def _set_stage(self, stage: str) -> None:
        with self._lock:
            # Ignore late callbacks from a superseded run (defensive; single-flight
            # already prevents overlap, but a stray callback must never revive us).
            if self._state == RUNNING:
                self._stage = stage

    def is_running(self) -> bool:
        with self._lock:
            return self._state == RUNNING

    def status(self) -> Dict:
        """Return a copy of the current status (safe to serialize to JSON)."""
        with self._lock:
            now = time.time()
            if self._started_at is None:
                elapsed_ms = 0
            else:
                end = self._finished_at if self._finished_at is not None else now
                elapsed_ms = int((end - self._started_at) * 1000)
            return {
                "state": self._state,
                "mode": self._mode,
                "stage": self._stage,
                "elapsed_ms": elapsed_ms,
                "error": self._error,
                "result": self._result,
            }

    def start(self, mode: str, runner: Callable[[Callable[[str], None]], Dict]) -> bool:
        """
        Launch `runner` on a background thread if no job is running.

        Args:
            mode:   "synthetic" | "real" — recorded in status for the UI.
            runner: callable taking a `progress(stage:str)` callback and returning
                    the success payload dict (stored as status.result). It should
                    raise on failure; the exception message becomes status.error.

        Returns:
            True if the job was started, False if one is already running
            (single-flight — the caller should surface this as HTTP 409).
        """
        with self._lock:
            if self._state == RUNNING:
                return False
            # (Re)initialise for a fresh run. Prior result/error are cleared so a
            # poller can't confuse an old outcome with the new run.
            self._state = RUNNING
            self._mode = (mode or "synthetic").lower()
            self._stage = "Starting…"
            self._started_at = time.time()
            self._finished_at = None
            self._error = None
            self._result = None

        def _work():
            try:
                result = runner(self._set_stage)
                with self._lock:
                    self._state = DONE
                    self._stage = "Complete"
                    self._finished_at = time.time()
                    self._result = result
            except Exception as e:  # noqa: BLE001 — surface any failure to the UI
                with self._lock:
                    self._state = ERROR
                    self._stage = "Failed"
                    self._finished_at = time.time()
                    self._error = str(e) or e.__class__.__name__
                # Full traceback to server logs for debugging; UI shows the message.
                traceback.print_exc()

        t = threading.Thread(target=_work, name="cpeds-retrain", daemon=True)
        with self._lock:
            self._thread = t
        t.start()
        return True
