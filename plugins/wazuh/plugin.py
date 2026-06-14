"""Wazuh source plugin (Architecture §3.3).

Implements the full ``LogSourcePlugin`` interface against the Wazuh Indexer /
Wazuh API. When the real API is unavailable (which it always is in the Claude
storage / CI sandbox), the plugin transparently falls back to bundled mock
alerts at ``tests/mocks/wazuh_alerts.json`` so the rest of the system — and the
test-suite — can exercise the full code path.

Read-only on the query path (Architecture §8.2). Renders Wazuh decoder/rule XML
but never deploys it (Architecture §8.4).

Targets Python 3.12+.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from plugins.base import (
    DataSourceRef,
    DetectionRule,
    DetectionSpec,
    HealthState,
    HealthStatus,
    QueryResult,
    QuerySpec,
    RenderedArtifact,
    Severity,
    ValidationIssue,
    ValidationReport,
)

logger = logging.getLogger(__name__)

# Repo root = plugins/wazuh/plugin.py -> parents[2]
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MOCK = _REPO_ROOT / "tests" / "mocks" / "wazuh_alerts.json"

# Severity mapping from Wazuh rule level (0-15) to our Severity.
_LEVEL_SEVERITY = [
    (12, Severity.CRITICAL),
    (9, Severity.HIGH),
    (6, Severity.MEDIUM),
    (3, Severity.LOW),
    (0, Severity.INFO),
]


def _level_to_severity(level: int) -> Severity:
    for threshold, sev in _LEVEL_SEVERITY:
        if level >= threshold:
            return sev
    return Severity.INFO


def _parse_ts(value: str) -> datetime:
    """Parse a Wazuh ISO timestamp into a timezone-aware UTC datetime.

    Replaces only a trailing 'Z' (not stray inner ones) and attaches UTC when
    the value is offset-naive, so comparisons against tz-aware query bounds
    never raise.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class WazuhPlugin:
    """Wazuh connector with transparent mock fallback."""

    name = "wazuh"
    display_name = "Wazuh"
    version = "0.1.0"

    def __init__(self) -> None:
        self._config: dict[str, Any] = {}
        self._endpoint: str = ""
        self._verify_tls: bool = True
        self._mock_path: Path = _DEFAULT_MOCK
        self._api_available: bool = False
        self._using_mock: bool = False
        self._initialized: bool = False

    # --- lifecycle ---------------------------------------------------------- #
    def initialize(self, config: dict[str, Any]) -> None:
        """Validate config and probe the API; fall back to mock if unreachable."""
        self._config = dict(config)
        self._endpoint = str(config.get("endpoint", "")).rstrip("/")
        self._verify_tls = bool(config.get("verify_tls", True))
        mock_path = config.get("mock_path")
        self._mock_path = Path(mock_path) if mock_path else _DEFAULT_MOCK

        # ``use_mock: true`` forces the mock path even if the endpoint is
        # reachable (live querying is not implemented in v1).
        if bool(config.get("use_mock", False)):
            self._api_available = False
        else:
            self._api_available = self._probe_api()
        self._using_mock = not self._api_available

        if self._using_mock and not self._mock_path.exists():
            raise RuntimeError(
                f"Wazuh API unavailable and mock file not found: {self._mock_path}"
            )
        self._initialized = True
        logger.info(
            "Wazuh initialized (api_available=%s, using_mock=%s)",
            self._api_available,
            self._using_mock,
        )

    def _probe_api(self) -> bool:
        """Best-effort reachability probe. Any failure => fall back to mock."""
        if not self._endpoint:
            return False
        try:
            req = urllib.request.Request(self._endpoint, method="GET")
            with urllib.request.urlopen(req, timeout=2):  # noqa: S310
                return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.info("Wazuh API probe failed (%s); using mock fallback", exc)
            return False

    def health_check(self) -> HealthStatus:
        now = datetime.now(timezone.utc)
        if not self._initialized:
            return HealthStatus(HealthState.UNAVAILABLE, "not initialized", now)
        if self._api_available:
            return HealthStatus(HealthState.CONNECTED, "Wazuh API reachable", now)
        if self._mock_path.exists():
            return HealthStatus(
                HealthState.DEGRADED, f"using mock data: {self._mock_path}", now
            )
        return HealthStatus(HealthState.UNAVAILABLE, "no API and no mock", now)

    def shutdown(self) -> None:
        self._initialized = False
        self._api_available = False

    # --- capability advertisement ------------------------------------------ #
    def supported_data_sources(self) -> list[DataSourceRef]:
        return [
            DataSourceRef("Process", "Process Creation"),
            DataSourceRef("Command", "Command Execution"),
            DataSourceRef("User Account", "User Account Authentication"),
            DataSourceRef("Logon Session", "Logon Session Creation"),
            DataSourceRef("Scheduled Job", "Scheduled Job Creation"),
        ]

    def existing_rules(self) -> list[DetectionRule]:
        """Derive normalized rules from observed alert rule definitions."""
        alerts = self._load_alerts()
        seen: dict[str, DetectionRule] = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rid = str(rule.get("id", ""))
            if not rid or rid in seen:
                continue
            mitre_ids = list(rule.get("mitre", {}).get("id", []))
            seen[rid] = DetectionRule(
                rule_id=rid,
                name=str(rule.get("description", "")),
                technique_ids=mitre_ids,
                enabled=True,
                native="",
                metadata={"level": rule.get("level")},
            )
        return list(seen.values())

    # --- telemetry access (read-only) -------------------------------------- #
    def query(self, spec: QuerySpec) -> QueryResult:
        if not self._initialized:
            raise RuntimeError("WazuhPlugin.query called before initialize()")
        alerts = self._load_alerts()
        events: list[dict[str, Any]] = []
        for alert in alerts:
            ts_raw = alert.get("timestamp")
            if ts_raw:
                ts = _parse_ts(str(ts_raw))
                if ts < spec.start or ts > spec.end:
                    continue
            if spec.technique_id is not None:
                mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
                if spec.technique_id not in mitre_ids:
                    continue
            events.append(self._normalize(alert))

        total = len(events)
        truncated = total > spec.limit
        if truncated:
            events = events[: spec.limit]
        return QueryResult(
            events=events,
            total_matched=total,
            truncated=truncated,
            source_name=self.name,
            took_ms=0,
        )

    def _normalize(self, alert: dict[str, Any]) -> dict[str, Any]:
        rule = alert.get("rule", {})
        return {
            "timestamp": alert.get("timestamp"),
            "source": self.name,
            "rule_id": str(rule.get("id", "")),
            "description": rule.get("description", ""),
            "level": rule.get("level"),
            "technique_ids": list(rule.get("mitre", {}).get("id", [])),
            "agent": alert.get("agent", {}),
            "data": alert.get("data", {}),
            "location": alert.get("location", ""),
        }

    def _load_alerts(self) -> list[dict[str, Any]]:
        if self._api_available:
            try:
                return self._fetch_from_api()
            except NotImplementedError:
                # Live querying isn't implemented yet: degrade to mock data
                # rather than crash a reachable-but-unsupported endpoint.
                if not self._mock_path.exists():
                    raise
                logger.warning(
                    "Wazuh live query not implemented; using mock fallback (%s)",
                    self._mock_path,
                )
        raw = json.loads(self._mock_path.read_text(encoding="utf-8"))
        alerts = raw.get("alerts", raw if isinstance(raw, list) else [])
        return list(alerts)

    def _fetch_from_api(self) -> list[dict[str, Any]]:  # pragma: no cover
        # Placeholder for real Wazuh Indexer query (read-only _search).
        raise NotImplementedError("live Wazuh API querying not implemented in v1")

    # --- detection authoring ------------------------------------------------ #
    def render_rule(self, detection: DetectionSpec) -> RenderedArtifact:
        """Render a Wazuh rule XML from a source-agnostic DetectionSpec."""
        techniques = ", ".join(detection.technique_ids)
        mitre_ids = "".join(
            f"      <id>{tid}</id>\n" for tid in detection.technique_ids
        )
        level = {
            Severity.CRITICAL: 13,
            Severity.HIGH: 10,
            Severity.MEDIUM: 7,
            Severity.LOW: 4,
            Severity.INFO: 1,
        }.get(detection.severity or Severity.MEDIUM, 7)

        # Emit techniques/logic as escaped child ELEMENTS, not XML comments:
        # comments may not contain '--', which detection logic routinely does
        # (e.g. "powershell -enc", "cmd --exec"), and would produce malformed XML.
        content = (
            '<group name="mitre,generated,">\n'
            '  <rule id="100000" level="{level}">\n'
            "    <description>{desc}</description>\n"
            "    <mitre>\n{mitre}    </mitre>\n"
            "    <field name=\"techniques\">{techniques}</field>\n"
            "    <field name=\"logic\">{logic}</field>\n"
            "  </rule>\n"
            "</group>\n"
        ).format(
            level=level,
            desc=_xml_escape(detection.title),
            mitre=mitre_ids,
            techniques=_xml_escape(techniques),
            logic=_xml_escape(detection.logic or "n/a"),
        )
        return RenderedArtifact(
            source_name=self.name,
            fmt="wazuh-xml",
            content=content,
            detection_title=detection.title,
            technique_ids=list(detection.technique_ids),
        )

    def validate_rule(self, artifact: RenderedArtifact) -> ValidationReport:
        """Statically validate Wazuh rule XML (well-formedness + basics)."""
        issues: list[ValidationIssue] = []
        try:
            root = ElementTree.fromstring(artifact.content)
        except ElementTree.ParseError as exc:
            return ValidationReport(
                valid=False,
                issues=[ValidationIssue(Severity.CRITICAL, f"malformed XML: {exc}")],
            )
        if root.tag != "group":
            issues.append(
                ValidationIssue(Severity.HIGH, "root element must be <group>")
            )
        if root.find("rule") is None:
            issues.append(
                ValidationIssue(Severity.HIGH, "no <rule> element found")
            )
        for rule in root.findall("rule"):
            if not rule.get("id"):
                issues.append(ValidationIssue(Severity.HIGH, "<rule> missing id"))
            if rule.find("description") is None:
                issues.append(
                    ValidationIssue(Severity.MEDIUM, "<rule> missing <description>")
                )
        valid = not any(
            i.severity in (Severity.HIGH, Severity.CRITICAL) for i in issues
        )
        return ValidationReport(valid=valid, issues=issues)


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
