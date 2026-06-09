"""Agent runtime wiring (control-plane facade).

Builds and owns the live object graph — ConfigStore, MitreEngine,
SourceManager (with all built-in plugins registered), and Scheduler — and
exposes a small, thread-safe API used by the web control panel and the CLI:

  * status()                      -> snapshot of sources + scheduler + last run
  * enable_source/disable_source  -> runtime source toggles (Architecture §6)
  * set_techniques_per_run        -> change batch size at runtime
  * run_once()                    -> run one evaluation cycle, persist results
  * recent_results()              -> tail of the results file
  * start_loop()/stop_loop()      -> paced background scheduling thread

Targets Python 3.12+.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config_store import ConfigStore
from core.mitre_engine import MitreEngine
from core.scheduler import RunReport, Scheduler
from core.source_manager import SourceManager
from plugins.manageengine import ManageEnginePlugin
from plugins.splunk import SplunkPlugin
from plugins.wazuh import WazuhPlugin

logger = logging.getLogger(__name__)

# Built-in source registry: name -> plugin class.
BUILTIN_PLUGINS: dict[str, type] = {
    "wazuh": WazuhPlugin,
    "manageengine": ManageEnginePlugin,
    "splunk": SplunkPlugin,
}


class AgentRuntime:
    """Owns the live agent object graph and the background scheduling loop."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        results_path: str | Path | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.store = ConfigStore.load(self.config_path)
        self.mitre = MitreEngine()
        self.sources = SourceManager(self.store)
        for name, cls in BUILTIN_PLUGINS.items():
            self.sources.register(name, cls)
        self.sources.sync()
        self.scheduler = Scheduler(self.store, self.mitre, self.sources)

        self.results_path = Path(
            results_path
            or self.store.config.to_dict().get("results_path")  # type: ignore[arg-type]
            or (self.config_path.parent / "results.jsonl")
        )

        self._lock = threading.RLock()
        self._loop_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last_run: dict[str, Any] | None = None
        self._run_count = 0

    # --- control operations ------------------------------------------------- #
    def enable_source(self, name: str) -> dict[str, Any]:
        if name not in BUILTIN_PLUGINS:
            raise KeyError(f"unknown source '{name}'")
        self.store.set_source_enabled(name, True)  # SourceManager re-syncs
        return self.source_status(name)

    def disable_source(self, name: str) -> dict[str, Any]:
        if name not in BUILTIN_PLUGINS:
            raise KeyError(f"unknown source '{name}'")
        self.store.set_source_enabled(name, False)
        return self.source_status(name)

    def set_techniques_per_run(self, value: int) -> int:
        with self._lock:
            sched = self.store.config.scheduler
            sched.techniques_per_run = int(value)
            sched.validate()
        return self.store.config.scheduler.techniques_per_run

    def set_ai_strategy(self, strategy: str, providers: list[str]) -> dict[str, Any]:
        from core.config_store import AIStrategy

        self.store.set_ai_strategy(AIStrategy(strategy), providers)
        return {
            "strategy": str(self.store.config.ai.strategy),
            "providers": list(self.store.config.ai.providers),
        }

    # --- evaluation --------------------------------------------------------- #
    def run_once(self) -> dict[str, Any]:
        report = self.scheduler.run_once()
        self._persist(report)
        with self._lock:
            self._run_count += 1
            self._last_run = {
                "at": datetime.now(timezone.utc).isoformat(),
                "selected": report.selected,
                "active_sources": report.active_sources,
                "evaluations": [
                    {
                        "technique_id": ev.technique_id,
                        "sources_queried": ev.sources_queried,
                        "event_counts": {
                            n: r.count for n, r in ev.results.items()
                        },
                    }
                    for ev in report.evaluations
                ],
            }
        return self._last_run

    def _persist(self, report: RunReport) -> None:
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with self.results_path.open("a", encoding="utf-8") as fh:
            for ev in report.evaluations:
                fh.write(
                    json.dumps(
                        {
                            "technique_id": ev.technique_id,
                            "sources_queried": ev.sources_queried,
                            "event_counts": {
                                n: r.count for n, r in ev.results.items()
                            },
                            "evaluated_at": ev.evaluated_at.isoformat()
                            if ev.evaluated_at
                            else None,
                        }
                    )
                    + "\n"
                )

    def recent_results(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.results_path.exists():
            return []
        lines = self.results_path.read_text(encoding="utf-8").strip().splitlines()
        return [json.loads(ln) for ln in lines[-limit:]]

    # --- status ------------------------------------------------------------- #
    def source_status(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "enabled": self.store.is_source_enabled(name),
            "state": str(self.sources.state_of(name)),
        }

    def status(self) -> dict[str, Any]:
        cfg = self.store.config
        return {
            "sources": [self.source_status(n) for n in BUILTIN_PLUGINS],
            "active_sources": self.sources.active_sources(),
            "scheduler": {
                "techniques_per_run": cfg.scheduler.techniques_per_run,
                "techniques_per_hour": cfg.scheduler.techniques_per_hour,
                "mode": str(cfg.scheduler.mode),
                "interval_seconds": cfg.scheduler.interval_seconds,
            },
            "ai": {
                "strategy": str(cfg.ai.strategy),
                "providers": list(cfg.ai.providers),
            },
            "loop_running": self.is_loop_running(),
            "run_count": self._run_count,
            "last_run": self._last_run,
            "results_path": str(self.results_path),
            "catalog_size": len(self.mitre.techniques),
        }

    # --- background paced loop ---------------------------------------------- #
    def is_loop_running(self) -> bool:
        return self._loop_thread is not None and self._loop_thread.is_alive()

    def start_loop(self) -> bool:
        with self._lock:
            if self.is_loop_running():
                return False
            self._stop.clear()
            self._loop_thread = threading.Thread(
                target=self._loop, name="agent-scheduler", daemon=True
            )
            self._loop_thread.start()
            logger.info("Background scheduling loop started")
            return True

    def stop_loop(self) -> bool:
        with self._lock:
            if not self.is_loop_running():
                return False
            self._stop.set()
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=5)
        logger.info("Background scheduling loop stopped")
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                logger.error("Scheduled run failed: %s", exc)
            interval = max(5.0, self.store.config.scheduler.interval_seconds)
            self._stop.wait(timeout=interval)

    def close(self) -> None:
        self.stop_loop()
        self.sources.close()
