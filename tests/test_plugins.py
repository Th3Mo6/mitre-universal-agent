"""Tests for ManageEngine and Splunk plugins (Step 8).

Confirms both implement the full interface, fall back to mock data without real
credentials, and that they default to disabled in the shipped config.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.config_store import ConfigStore
from plugins.base import (
    DetectionSpec,
    HealthState,
    LogSourcePlugin,
    QuerySpec,
    Severity,
)
from plugins.manageengine import ManageEnginePlugin
from plugins.splunk import SplunkPlugin

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _full_range() -> QuerySpec:
    return QuerySpec(
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end=datetime(2026, 12, 31, tzinfo=timezone.utc),
    )


# --------------------------------------------------------------------------- #
# Config defaults
# --------------------------------------------------------------------------- #
def test_default_config_disables_me_and_splunk() -> None:
    store = ConfigStore.load(_REPO_ROOT / "config" / "default.json")
    assert store.is_source_enabled("wazuh") is True
    assert store.is_source_enabled("manageengine") is False
    assert store.is_source_enabled("splunk") is False
    assert store.enabled_sources() == ["wazuh"]


# --------------------------------------------------------------------------- #
# ManageEngine
# --------------------------------------------------------------------------- #
@pytest.fixture()
def me() -> ManageEnginePlugin:
    p = ManageEnginePlugin()
    p.initialize({"endpoint": ""})
    return p


def test_me_satisfies_protocol() -> None:
    assert isinstance(ManageEnginePlugin(), LogSourcePlugin)


def test_me_identity_and_mock_fallback(me: ManageEnginePlugin) -> None:
    assert me.name == "manageengine"
    health = me.health_check()
    assert health.state == HealthState.DEGRADED
    assert "mock" in health.detail.lower()


def test_me_query_and_filter(me: ManageEnginePlugin) -> None:
    result = me.query(_full_range())
    assert result.source_name == "manageengine"
    assert result.count == 3

    spec = _full_range()
    spec.technique_id = "T1110"
    filtered = me.query(spec)
    assert filtered.count == 2
    assert all("T1110" in e["technique_ids"] for e in filtered.events)


def test_me_existing_rules(me: ManageEnginePlugin) -> None:
    rules = me.existing_rules()
    ids = {r.rule_id for r in rules}
    assert "me-4625" in ids
    assert "me-4720" in ids


def test_me_render_and_validate(me: ManageEnginePlugin) -> None:
    spec = DetectionSpec(
        title="Brute force on DC",
        description="Many 4625s from one source",
        technique_ids=["T1110"],
        logic="EVENTID=4625 | stats count by SOURCE_IP",
        severity=Severity.HIGH,
    )
    art = me.render_rule(spec)
    assert art.fmt == "manageengine-json"
    parsed = json.loads(art.content)
    assert parsed["mitreTechniques"] == ["T1110"]
    report = me.validate_rule(art)
    assert report.valid


# --------------------------------------------------------------------------- #
# Splunk
# --------------------------------------------------------------------------- #
@pytest.fixture()
def splunk() -> SplunkPlugin:
    p = SplunkPlugin()
    p.initialize({"endpoint": ""})
    return p


def test_splunk_satisfies_protocol() -> None:
    assert isinstance(SplunkPlugin(), LogSourcePlugin)


def test_splunk_identity_and_mock_fallback(splunk: SplunkPlugin) -> None:
    assert splunk.name == "splunk"
    health = splunk.health_check()
    assert health.state == HealthState.DEGRADED
    assert "mock" in health.detail.lower()


def test_splunk_query_and_filter(splunk: SplunkPlugin) -> None:
    result = splunk.query(_full_range())
    assert result.source_name == "splunk"
    assert result.count == 3

    spec = _full_range()
    spec.technique_id = "T1059.001"
    filtered = splunk.query(spec)
    assert filtered.count == 1
    assert filtered.events[0]["technique_ids"] == ["T1059.001"]


def test_splunk_existing_rules(splunk: SplunkPlugin) -> None:
    rules = splunk.existing_rules()
    ids = {r.rule_id for r in rules}
    assert "splunk-linux_secure" in ids
    assert "splunk-WinEventLog" in ids


def test_splunk_render_and_validate(splunk: SplunkPlugin) -> None:
    spec = DetectionSpec(
        title="Encoded PowerShell",
        description="Detect -enc usage",
        technique_ids=["T1059.001"],
        logic="index=win sourcetype=WinEventLog powershell -enc",
        severity=Severity.HIGH,
    )
    art = splunk.render_rule(spec)
    assert art.fmt == "splunk-spl"
    assert art.content.startswith("[Encoded PowerShell]")
    assert "search =" in art.content
    report = splunk.validate_rule(art)
    assert report.valid


def test_splunk_validate_rejects_empty_search(splunk: SplunkPlugin) -> None:
    from plugins.base import RenderedArtifact

    bad = RenderedArtifact(
        source_name="splunk", fmt="splunk-spl", content="[x]\nsearch = \n"
    )
    report = splunk.validate_rule(bad)
    assert not report.valid
