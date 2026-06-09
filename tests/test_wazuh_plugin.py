"""Tests for the Wazuh plugin (Step 5).

Exercises the full LogSourcePlugin interface against the bundled mock alerts,
confirming the plugin falls back to mock data when no real Wazuh API is present.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from plugins.base import (
    DetectionSpec,
    HealthState,
    LogSourcePlugin,
    QuerySpec,
    Severity,
)
from plugins.wazuh import WazuhPlugin


@pytest.fixture()
def plugin() -> WazuhPlugin:
    p = WazuhPlugin()
    # No endpoint -> API unavailable -> mock fallback.
    p.initialize({"endpoint": "", "verify_tls": True})
    return p


def _full_range() -> QuerySpec:
    return QuerySpec(
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end=datetime(2026, 12, 31, tzinfo=timezone.utc),
    )


def test_satisfies_protocol() -> None:
    assert isinstance(WazuhPlugin(), LogSourcePlugin)


def test_identity() -> None:
    p = WazuhPlugin()
    assert p.name == "wazuh"
    assert p.display_name == "Wazuh"
    assert p.version


def test_falls_back_to_mock(plugin: WazuhPlugin) -> None:
    health = plugin.health_check()
    assert health.state == HealthState.DEGRADED
    assert health.is_usable
    assert "mock" in health.detail.lower()


def test_query_returns_all_mock_events(plugin: WazuhPlugin) -> None:
    result = plugin.query(_full_range())
    assert result.source_name == "wazuh"
    assert result.count == 4
    assert result.total_matched == 4
    assert not result.truncated
    # Normalized shape
    first = result.events[0]
    assert {"timestamp", "rule_id", "technique_ids", "source"} <= set(first)
    assert first["source"] == "wazuh"


def test_query_filter_by_technique(plugin: WazuhPlugin) -> None:
    spec = _full_range()
    spec.technique_id = "T1110"
    result = plugin.query(spec)
    assert result.count == 2
    assert all("T1110" in e["technique_ids"] for e in result.events)


def test_query_time_window_excludes_out_of_range(plugin: WazuhPlugin) -> None:
    spec = QuerySpec(
        start=datetime(2026, 6, 2, tzinfo=timezone.utc),
        end=datetime(2026, 6, 2, 23, 59, tzinfo=timezone.utc),
    )
    result = plugin.query(spec)
    # Only the 2026-06-02 PowerShell alert falls in this window.
    assert result.count == 1
    assert result.events[0]["technique_ids"] == ["T1059.001"]


def test_query_limit_truncates(plugin: WazuhPlugin) -> None:
    spec = _full_range()
    spec.limit = 2
    result = plugin.query(spec)
    assert result.count == 2
    assert result.truncated
    assert result.total_matched == 4


def test_existing_rules(plugin: WazuhPlugin) -> None:
    rules = plugin.existing_rules()
    ids = {r.rule_id for r in rules}
    # 4 alerts but two share rule context; ids are distinct here.
    assert {"5710", "5712", "91802", "92052"} == ids
    by_id = {r.rule_id: r for r in rules}
    assert by_id["5710"].technique_ids == ["T1110"]


def test_supported_data_sources(plugin: WazuhPlugin) -> None:
    refs = plugin.supported_data_sources()
    labels = {str(r) for r in refs}
    assert "Process: Process Creation" in labels
    assert "User Account: User Account Authentication" in labels


def test_render_and_validate_rule(plugin: WazuhPlugin) -> None:
    spec = DetectionSpec(
        title="Detect PowerShell encoded command",
        description="Flags suspicious encoded PowerShell",
        technique_ids=["T1059.001"],
        logic="commandLine contains '-enc'",
        severity=Severity.HIGH,
    )
    artifact = plugin.render_rule(spec)
    assert artifact.fmt == "wazuh-xml"
    assert "T1059.001" in artifact.content
    assert "<group" in artifact.content

    report = plugin.validate_rule(artifact)
    assert report.valid
    assert not report.has_errors


def test_validate_rejects_malformed_xml(plugin: WazuhPlugin) -> None:
    from plugins.base import RenderedArtifact

    bad = RenderedArtifact(source_name="wazuh", fmt="wazuh-xml", content="<group><rule>")
    report = plugin.validate_rule(bad)
    assert not report.valid
    assert report.has_errors


def test_render_escapes_xml_special_chars(plugin: WazuhPlugin) -> None:
    spec = DetectionSpec(
        title="A & B < C > D",
        description="x",
        technique_ids=["T1078"],
    )
    artifact = plugin.render_rule(spec)
    # Must still be well-formed after escaping.
    report = plugin.validate_rule(artifact)
    assert report.valid
    assert "&amp;" in artifact.content
