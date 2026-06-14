"""Scheduler (Architecture §5).

Drives the paced evaluation loop. Each *run* selects exactly
``scheduler.techniques_per_run`` techniques (default 5) using the MITRE
engine's selection priority, then dispatches an evaluation against the
currently **active** sources only.

Source isolation guarantee (Architecture §6.3): the scheduler only ever touches
sources the SourceManager reports as ACTIVE, which in turn are only those with
``enabled = true`` in config. If only ``wazuh.enabled = true``, ManageEngine and
Splunk are never initialized, queried, or contacted.

Targets Python 3.12+.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from core.config_store import ConfigStore
from core.mitre_engine import MitreEngine
from core.source_manager import SourceManager
from plugins.base import QueryResult, QuerySpec

__all__ = ["EvaluationResult", "RunReport", "Scheduler"]

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class EvaluationResult:
    """Outcome of evaluating a single technique in a run."""

    technique_id: str
    sources_queried: list[str] = field(default_factory=list)
    results: dict[str, QueryResult] = field(default_factory=dict)
    evaluated_at: datetime | None = None


@dataclass(slots=True)
class RunReport:
    """Outcome of one scheduler run."""

    selected: list[str] = field(default_factory=list)
    evaluations: list[EvaluationResult] = field(default_factory=list)
    active_sources: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.selected)


class Scheduler:
    """Selects and dispatches a bounded batch of techniques per run."""

    def __init__(
        self,
        config_store: ConfigStore,
        mitre_engine: MitreEngine,
        source_manager: SourceManager,
        *,
        clock: Clock = _utcnow,
        window_hours: int = 24,
    ) -> None:
        self._store = config_store
        self._mitre = mitre_engine
        self._sources = source_manager
        self._clock = clock
        self._window_hours = window_hours
        # technique_id -> last evaluation time (staleness cursor, persisted-able)
        self._last_evaluated: dict[str, datetime] = {}
        self._cursor_lock = threading.Lock()

    # --- configuration ------------------------------------------------------ #
    @property
    def techniques_per_run(self) -> int:
        return self._store.config.scheduler.techniques_per_run

    # --- selection ---------------------------------------------------------- #
    def _enabled_data_sources(self) -> list[str]:
        """Data sources advertised by ACTIVE sources only.

        Because SourceManager.supported_data_sources() iterates active sources
        exclusively, disabled sources contribute nothing here.
        """
        labels: set[str] = set()
        for refs in self._sources.supported_data_sources().values():
            labels.update(str(r) for r in refs)
        return sorted(labels)

    def select_batch(self) -> list[str]:
        """Return EXACTLY ``techniques_per_run`` technique IDs (or fewer only
        if the catalog is smaller than the batch size)."""
        n = max(0, self.techniques_per_run)  # never slice with a negative n
        data_sources = self._enabled_data_sources()
        rules = [r for rs in self._sources.existing_rules().values() for r in rs]
        with self._cursor_lock:
            last_eval = dict(self._last_evaluated)
        order = self._mitre.selection_order(
            enabled_data_sources=data_sources,
            existing_rules=rules,
            last_evaluated=last_eval,
        )
        return order[:n]

    def _now(self) -> datetime:
        """Clock output, normalized to timezone-aware UTC (defensive: an
        injected clock may return a naive datetime)."""
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now

    # --- dispatch ----------------------------------------------------------- #
    def run_once(self) -> RunReport:
        """Select a batch and evaluate it against active sources only."""
        active = self._sources.active_sources()
        selected = self.select_batch()
        report = RunReport(selected=list(selected), active_sources=list(active))

        # Trailing window of exactly window_hours, both bounds tz-aware and on
        # the same (whole-second) precision. Use timedelta, not timestamp
        # round-tripping, so a naive clock can't shift the window by the local
        # UTC offset.
        end = self._now().replace(microsecond=0)
        spec_start = end - timedelta(hours=self._window_hours)

        for tid in selected:
            spec = QuerySpec(start=spec_start, end=end, technique_id=tid)
            # query_all only contacts ACTIVE sources (isolation guarantee).
            results = self._sources.query_all(spec)
            with self._cursor_lock:
                self._last_evaluated[tid] = end
            report.evaluations.append(
                EvaluationResult(
                    technique_id=tid,
                    sources_queried=list(results.keys()),
                    results=results,
                    evaluated_at=end,
                )
            )
        logger.info(
            "Scheduler run: selected %d technique(s), active sources=%s",
            report.count,
            active,
        )
        return report

    # --- cursor persistence helpers ----------------------------------------- #
    def last_evaluated(self) -> dict[str, datetime]:
        with self._cursor_lock:
            return dict(self._last_evaluated)

    def load_cursor(self, cursor: dict[str, datetime]) -> None:
        with self._cursor_lock:
            self._last_evaluated = dict(cursor)
