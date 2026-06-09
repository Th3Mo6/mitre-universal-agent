"""Tests for the Scheduler (Step 6).

Asserts:
  * the scheduler selects EXACTLY 5 techniques per run (not 10), and
  * it respects the enabled-sources list: with only wazuh enabled it must NOT
    initialize, query, or otherwise contact manageengine or splunk.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.config_store import AppConfig, ConfigStore, SchedulerConfig, SourceConfig
from core.mitre_engine import MitreEngine, Technique
from core.scheduler import Scheduler
from core.source_manager import SourceManager
from plugins.base import (
    DataSourceRef,
    DetectionRule,
    DetectionSpec,
    HealthState,
    HealthStatus,
    QueryResult,
    QuerySpec,
    RenderedArtifact,
    ValidationReport,
)


# --------------------------------------------------------------------------- #
# A spy plugin that records every interaction so we can prove disabled sources
# are never touched.
# --------------------------------------------------------------------------- #
class SpyPlugin:
    def __init__(self, name: str, data_source: str) -> None:
        self.name = name
        self.display_name = name.title()
        self.version = "test"
        self._ds = data_source
        self.init_count = 0
        self.query_count = 0
        self.health_count = 0

    def initialize(self, config: dict[str, Any]) -> None:
        self.init_count += 1

    def health_check(self) -> HealthStatus:
        self.health_count += 1
        return HealthStatus(HealthState.CONNECTED, "ok")

    def shutdown(self) -> None: ...

    def supported_data_sources(self) -> list[DataSourceRef]:
        ds, comp = self._ds.split(": ", 1)
        return [DataSourceRef(ds, comp)]

    def existing_rules(self) -> list[DetectionRule]:
        return []

    def query(self, spec: QuerySpec) -> QueryResult:
        self.query_count += 1
        return QueryResult(events=[], source_name=self.name)

    def render_rule(self, detection: DetectionSpec) -> RenderedArtifact:
        return RenderedArtifact(source_name=self.name, fmt="x", content="")

    def validate_rule(self, artifact: RenderedArtifact) -> ValidationReport:
        return ValidationReport(valid=True)


def _catalog_of(n: int, data_source: str) -> list[Technique]:
    """Build n observable techniques so a batch of 5 is a real subset."""
    return [
        Technique(f"T{9000 + i}", f"Technique {i}", ["execution"], [data_source])
        for i in range(n)
    ]


def _make(enabled: dict[str, bool]) -> tuple[Scheduler, dict[str, SpyPlugin]]:
    ds = "Process: Process Creation"
    cfg = AppConfig(
        sources={n: SourceConfig(enabled=e) for n, e in enabled.items()},
        scheduler=SchedulerConfig(techniques_per_run=5),
    )
    store = ConfigStore(cfg)
    mitre = MitreEngine(_catalog_of(12, ds))  # 12 techniques available
    manager = SourceManager(store)

    spies = {n: SpyPlugin(n, ds) for n in enabled}
    for name, spy in spies.items():
        manager.register(name, (lambda s=spy: s))  # type: ignore[misc]
    manager.sync()

    clock = lambda: datetime(2026, 6, 7, 12, 0, tzinfo=timezone.utc)
    return Scheduler(store, mitre, manager, clock=clock), spies


def test_selects_exactly_five_not_ten() -> None:
    sched, _ = _make({"wazuh": True})
    batch = sched.select_batch()
    assert len(batch) == 5, f"expected exactly 5, got {len(batch)}"
    assert len(batch) != 10
    assert len(set(batch)) == 5  # no duplicates


def test_run_once_reports_five() -> None:
    sched, _ = _make({"wazuh": True})
    report = sched.run_once()
    assert report.count == 5
    assert len(report.evaluations) == 5


def test_respects_enabled_sources_only_wazuh() -> None:
    sched, spies = _make({"wazuh": True, "manageengine": False, "splunk": False})

    # Only wazuh should be active.
    assert sched._sources.active_sources() == ["wazuh"]

    report = sched.run_once()

    # Disabled sources must NEVER be initialized or queried.
    assert spies["manageengine"].init_count == 0
    assert spies["manageengine"].query_count == 0
    assert spies["splunk"].init_count == 0
    assert spies["splunk"].query_count == 0

    # Wazuh was initialized once and queried once per selected technique.
    assert spies["wazuh"].init_count == 1
    assert spies["wazuh"].query_count == 5

    # Every evaluation only ever queried wazuh.
    for ev in report.evaluations:
        assert ev.sources_queried == ["wazuh"]


def test_enabling_second_source_at_runtime_is_respected() -> None:
    sched, spies = _make({"wazuh": True, "splunk": False})
    sched.run_once()
    assert spies["splunk"].query_count == 0

    # Toggle splunk on at runtime -> SourceManager reacts via config event.
    sched._sources._store.set_source_enabled("splunk", True)
    sched.run_once()
    assert spies["splunk"].init_count == 1
    assert spies["splunk"].query_count == 5
