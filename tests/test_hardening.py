"""Regression tests for issues found in the post-implementation code review.

Each test pins a specific bug that was fixed so it can't silently regress.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ai_providers import AIProvider, AIRequest, MockProvider
from core.ai_orchestrator import AIOrchestrator, OrchestratorError
from core.config_store import (
    AIStrategy,
    AppConfig,
    ConfigError,
    ConfigStore,
    SchedulerConfig,
    SourceConfig,
)
from core.mitre_engine import MitreEngine, Technique
from core.runtime import AgentRuntime
from plugins.base import DetectionSpec, QuerySpec, Severity
from plugins.splunk import SplunkPlugin
from plugins.wazuh import WazuhPlugin

_CONFIG = Path(__file__).resolve().parents[1] / "config" / "default.json"


def _range() -> QuerySpec:
    return QuerySpec(
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end=datetime(2026, 12, 31, tzinfo=timezone.utc),
    )


# --------------------------------------------------------------------------- #
# Plugins
# --------------------------------------------------------------------------- #
def test_reachable_endpoint_falls_back_to_mock_not_crash() -> None:
    """A reachable endpoint must not crash query() with NotImplementedError;
    live querying is unimplemented, so it degrades to mock data."""
    p = WazuhPlugin()
    p.initialize({"endpoint": ""})
    p._api_available = True  # simulate a successful probe / reachable endpoint
    result = p.query(_range())  # would raise NotImplementedError before the fix
    assert result.count == 4


def test_use_mock_forces_mock_even_if_reachable() -> None:
    p = WazuhPlugin()
    p.initialize({"endpoint": "http://example.invalid", "use_mock": True})
    assert p._api_available is False
    assert p.query(_range()).count == 4


def test_naive_timestamp_does_not_raise(tmp_path: Path) -> None:
    """An event timestamp without a tz offset must not raise TypeError when
    compared to tz-aware query bounds."""
    mock = tmp_path / "alerts.json"
    mock.write_text(
        json.dumps(
            {
                "alerts": [
                    {
                        "timestamp": "2026-06-01T10:00:00",  # naive, no Z/offset
                        "rule": {"id": "1", "level": 5, "mitre": {"id": ["T1110"]}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    p = WazuhPlugin()
    p.initialize({"endpoint": "", "mock_path": str(mock)})
    result = p.query(_range())
    assert result.count == 1


def test_wazuh_render_with_double_dash_is_valid_xml() -> None:
    p = WazuhPlugin()
    p.initialize({"endpoint": ""})
    spec = DetectionSpec(
        title="Encoded PowerShell",
        description="x",
        technique_ids=["T1059.001"],
        logic="powershell -enc -- cmd --exec value",  # '--' broke XML comments
        severity=Severity.HIGH,
    )
    artifact = p.render_rule(spec)
    report = p.validate_rule(artifact)
    assert report.valid, [i.message for i in report.issues]
    assert "--" in artifact.content  # the logic text is preserved verbatim


def test_splunk_render_with_newline_title_is_valid() -> None:
    p = SplunkPlugin()
    p.initialize({"endpoint": ""})
    spec = DetectionSpec(
        title="Multi\nline\ntitle",
        description="desc\nwith\nnewlines",
        technique_ids=["T1110"],
        logic="index=x",
    )
    artifact = p.render_rule(spec)
    report = p.validate_rule(artifact)
    assert report.valid
    assert artifact.content.splitlines()[0] == "[Multi line title]"


# --------------------------------------------------------------------------- #
# AI orchestrator
# --------------------------------------------------------------------------- #
def _store(strategy: AIStrategy, providers: list[str]) -> ConfigStore:
    s = ConfigStore(AppConfig())
    s.set_ai_strategy(strategy, providers)
    return s


@pytest.mark.asyncio
async def test_ensemble_nested_dict_insertion_order_agrees() -> None:
    """Structured payloads equal up to nested key order must vote together."""
    providers: dict[str, AIProvider] = {
        "a": MockProvider("a", structured={"o": {"x": 1, "y": 2}, "k": 3}),
        "b": MockProvider("b", structured={"k": 3, "o": {"y": 2, "x": 1}}),
        "c": MockProvider("c", structured={"k": 9}),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.ENSEMBLE, ["a", "b", "c"]))
    resp = await orch.complete(AIRequest(prompt="q", json_mode=True))
    assert resp.metadata["agreed"] == 2


@pytest.mark.asyncio
async def test_ensemble_mixed_type_keys_does_not_crash() -> None:
    bad_payload: dict[object, object] = {1: "x", "b": 2}  # deliberately non-str keys
    providers: dict[str, AIProvider] = {
        "a": MockProvider("a", structured=bad_payload),  # type: ignore[arg-type]
        "b": MockProvider("b", structured={"only": True}),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.ENSEMBLE, ["a", "b"]))
    resp = await orch.complete(AIRequest(prompt="q", json_mode=True))
    assert resp.ok  # must not raise TypeError during aggregation


@pytest.mark.asyncio
async def test_unknown_configured_provider_raises() -> None:
    providers: dict[str, AIProvider] = {"real": MockProvider("real", content="x")}
    orch = AIOrchestrator(providers, _store(AIStrategy.SINGLE, ["typo"]))
    with pytest.raises(OrchestratorError):
        await orch.complete(AIRequest(prompt="q"))


@pytest.mark.asyncio
async def test_single_enforces_json_mode_validity() -> None:
    providers: dict[str, AIProvider] = {"a": MockProvider("a", content="text-only")}
    orch = AIOrchestrator(providers, _store(AIStrategy.SINGLE, ["a"]))
    resp = await orch.complete(AIRequest(prompt="q", json_mode=True))
    assert resp.ok is False  # no structured payload -> invalid under json_mode


# --------------------------------------------------------------------------- #
# Config / scheduler / mitre
# --------------------------------------------------------------------------- #
def test_set_techniques_per_run_invalid_does_not_apply() -> None:
    store = ConfigStore(AppConfig(scheduler=SchedulerConfig(techniques_per_run=5)))
    with pytest.raises(ConfigError):
        store.set_techniques_per_run(0)
    # The invalid value must NOT have been committed.
    assert store.config.scheduler.techniques_per_run == 5


def test_recent_results_skips_corrupt_line(tmp_path: Path) -> None:
    rt = AgentRuntime(_CONFIG, results_path=tmp_path / "r.jsonl")
    try:
        rt.results_path.write_text(
            '{"technique_id": "T1"}\nNOT JSON\n{"technique_id": "T2"}\n',
            encoding="utf-8",
        )
        recent = rt.recent_results()
        assert [r["technique_id"] for r in recent] == ["T1", "T2"]
    finally:
        rt.close()


def test_selection_order_observable_and_staleness() -> None:
    ds = "Process: Process Creation"
    techs = [
        Technique("T-obs-new", "observable never", ["execution"], [ds]),
        Technique("T-obs-old", "observable evaluated", ["execution"], [ds]),
        Technique("T-unobs", "unobservable", ["execution"], ["Other: X"]),
    ]
    engine = MitreEngine(techs)
    last = {"T-obs-old": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    order = engine.selection_order([ds], last_evaluated=last)
    # never-evaluated observable first, evaluated observable next, unobservable last.
    assert order == ["T-obs-new", "T-obs-old", "T-unobs"]


def test_scheduler_naive_clock_produces_aware_window() -> None:
    from core.scheduler import Scheduler
    from core.source_manager import SourceManager

    store = ConfigStore(AppConfig(scheduler=SchedulerConfig(techniques_per_run=1)))
    mgr = SourceManager(store)
    sched = Scheduler(
        store,
        MitreEngine(),
        mgr,
        clock=lambda: datetime(2026, 6, 7, 12, 0),  # NAIVE on purpose
        window_hours=24,
    )
    captured: dict[str, datetime] = {}

    def spy(spec: QuerySpec) -> dict:
        captured["start"] = spec.start
        captured["end"] = spec.end
        return {}

    mgr.query_all = spy  # type: ignore[method-assign]
    sched.run_once()
    assert captured["end"].tzinfo is not None
    assert captured["start"].tzinfo is not None
    assert (captured["end"] - captured["start"]).total_seconds() == 24 * 3600


# --------------------------------------------------------------------------- #
# Source manager config drift
# --------------------------------------------------------------------------- #
def test_config_drift_reinitializes_active_source() -> None:
    cfg = AppConfig(
        sources={"wazuh": SourceConfig(enabled=True, config={"endpoint": ""})}
    )
    store = ConfigStore(cfg)
    mgr = __import__("core.source_manager", fromlist=["SourceManager"]).SourceManager(
        store
    )
    mgr.register("wazuh", WazuhPlugin)
    mgr.sync()
    assert mgr.active_sources() == ["wazuh"]
    assert mgr._sources["wazuh"].applied_config == {"endpoint": ""}

    # Change the source config at runtime -> manager must re-init the plugin.
    store.set_source_config("wazuh", {"endpoint": "", "use_mock": True})
    assert mgr._sources["wazuh"].applied_config == {"endpoint": "", "use_mock": True}
    mgr.close()
