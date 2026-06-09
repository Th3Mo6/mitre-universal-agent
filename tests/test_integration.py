"""End-to-end integration test (Step 9).

Loads the shipped config (wazuh enabled only), runs the scheduler for one cycle
(5 techniques), writes per-technique results to ``<workspace>/results.jsonl``,
and proves that ONLY the Wazuh plugin was contacted — ManageEngine and Splunk
are never constructed, initialized, or queried.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from core.config_store import ConfigStore
from core.mitre_engine import MitreEngine
from core.scheduler import Scheduler
from core.source_manager import SourceManager
from plugins.base import QuerySpec
from plugins.manageengine import ManageEnginePlugin
from plugins.splunk import SplunkPlugin
from plugins.wazuh import WazuhPlugin

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFIG = _REPO_ROOT / "config" / "default.json"
# Literal /workspace/results.jsonl == the workspace parent of the project dir
# (project lives at /workspace/mitre-universal-agent).
_RESULTS_PATH = _REPO_ROOT.parent / "results.jsonl"


class _CountingFactory:
    """Wraps a plugin class, counting how often it is instantiated AND queried."""

    def __init__(self, cls: type) -> None:
        self._cls = cls
        self.build_count = 0
        self.query_count = 0

    def __call__(self):  # type: ignore[no-untyped-def]
        self.build_count += 1
        plugin = self._cls()
        original_query = plugin.query

        def _counting_query(spec: QuerySpec):  # type: ignore[no-untyped-def]
            self.query_count += 1
            return original_query(spec)

        plugin.query = _counting_query  # type: ignore[method-assign]
        return plugin


def test_full_integration_wazuh_only(caplog) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.INFO)

    # 1. Load shipped config: wazuh enabled, ME + Splunk disabled.
    store = ConfigStore.load(_CONFIG)
    assert store.enabled_sources() == ["wazuh"]

    # 2. Wire engine + manager + counting factories for all three sources.
    mitre = MitreEngine()  # 5-technique seed catalog
    manager = SourceManager(store)
    factories = {
        "wazuh": _CountingFactory(WazuhPlugin),
        "manageengine": _CountingFactory(ManageEnginePlugin),
        "splunk": _CountingFactory(SplunkPlugin),
    }
    for name, factory in factories.items():
        manager.register(name, factory)

    manager.sync()  # activate only enabled sources

    # Only wazuh should have been built/activated.
    assert manager.active_sources() == ["wazuh"]
    assert factories["wazuh"].build_count == 1
    assert factories["manageengine"].build_count == 0
    assert factories["splunk"].build_count == 0

    # 3. Run the scheduler for exactly one cycle (5 techniques).
    scheduler = Scheduler(store, mitre, manager)
    report = scheduler.run_once()
    assert report.count == 5
    assert report.active_sources == ["wazuh"]

    # 4. Write results to <workspace>/results.jsonl
    with _RESULTS_PATH.open("w", encoding="utf-8") as fh:
        for ev in report.evaluations:
            line = {
                "technique_id": ev.technique_id,
                "sources_queried": ev.sources_queried,
                "event_counts": {
                    name: res.count for name, res in ev.results.items()
                },
                "evaluated_at": ev.evaluated_at.isoformat()
                if ev.evaluated_at
                else None,
            }
            fh.write(json.dumps(line) + "\n")
    logging.getLogger(__name__).info("Wrote results to %s", _RESULTS_PATH)

    # 5. Confirm ManageEngine and Splunk were NEVER invoked.
    assert factories["manageengine"].query_count == 0
    assert factories["splunk"].query_count == 0
    # Every evaluation queried wazuh and only wazuh.
    for ev in report.evaluations:
        assert ev.sources_queried == ["wazuh"]
    # Wazuh queried once per selected technique.
    assert factories["wazuh"].query_count == 5

    # 6. The results file has exactly 5 lines, each valid JSON.
    lines = _RESULTS_PATH.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
    techniques = {json.loads(ln)["technique_id"] for ln in lines}
    assert len(techniques) == 5
    for ln in lines:
        rec = json.loads(ln)
        assert list(rec["event_counts"].keys()) in ([], ["wazuh"])

    manager.close()
