"""ManageEngine source plugin (Architecture §3.3).

Implements the full ``LogSourcePlugin`` interface against ManageEngine Log360 /
EventLog Analyzer. Defaults to **disabled** in config (Architecture §6.1); when
enabled but the real API is unreachable (always, in the sandbox) it falls back
to bundled mock logs at ``tests/mocks/manageengine_logs.json``.

Read-only query path; renders a ManageEngine correlation rule (JSON) but never
deploys it.

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

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MOCK = _REPO_ROOT / "tests" / "mocks" / "manageengine_logs.json"


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ManageEnginePlugin:
    """ManageEngine connector with transparent mock fallback."""

    name = "manageengine"
    display_name = "ManageEngine"
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
        self._config = dict(config)
        self._endpoint = str(config.get("endpoint", "")).rstrip("/")
        self._verify_tls = bool(config.get("verify_tls", True))
        mock_path = config.get("mock_path")
        self._mock_path = Path(mock_path) if mock_path else _DEFAULT_MOCK

        self._api_available = self._probe_api()
        self._using_mock = not self._api_available
        if self._using_mock and not self._mock_path.exists():
            raise RuntimeError(
                f"ManageEngine API unavailable and mock not found: {self._mock_path}"
            )
        self._initialized = True
        logger.info(
            "ManageEngine initialized (api_available=%s, using_mock=%s)",
            self._api_available,
            self._using_mock,
        )

    def _probe_api(self) -> bool:
        if not self._endpoint:
            return False
        try:
            req = urllib.request.Request(self._endpoint, method="GET")
            with urllib.request.urlopen(req, timeout=2):  # noqa: S310
                return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.info("ManageEngine probe failed (%s); using mock", exc)
            return False

    def health_check(self) -> HealthStatus:
        now = datetime.now(timezone.utc)
        if not self._initialized:
            return HealthStatus(HealthState.UNAVAILABLE, "not initialized", now)
        if self._api_available:
            return HealthStatus(HealthState.CONNECTED, "ManageEngine reachable", now)
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
            DataSourceRef("User Account", "User Account Authentication"),
            DataSourceRef("User Account", "User Account Creation"),
            DataSourceRef("Logon Session", "Logon Session Creation"),
            DataSourceRef("Application Log", "Application Log Content"),
        ]

    def existing_rules(self) -> list[DetectionRule]:
        logs = self._load_logs()
        seen: dict[str, DetectionRule] = {}
        for log in logs:
            eid = str(log.get("EVENTID", ""))
            if not eid or eid in seen:
                continue
            seen[eid] = DetectionRule(
                rule_id=f"me-{eid}",
                name=str(log.get("MESSAGE", ""))[:80],
                technique_ids=list(log.get("MITRE_TECHNIQUE", [])),
                enabled=True,
                metadata={"event_id": eid},
            )
        return list(seen.values())

    # --- telemetry access (read-only) -------------------------------------- #
    def query(self, spec: QuerySpec) -> QueryResult:
        if not self._initialized:
            raise RuntimeError("ManageEnginePlugin.query called before initialize()")
        logs = self._load_logs()
        events: list[dict[str, Any]] = []
        for log in logs:
            ts_raw = log.get("@timestamp")
            if ts_raw:
                ts = _parse_ts(str(ts_raw))
                if ts < spec.start or ts > spec.end:
                    continue
            if spec.technique_id is not None:
                if spec.technique_id not in log.get("MITRE_TECHNIQUE", []):
                    continue
            events.append(self._normalize(log))

        total = len(events)
        truncated = total > spec.limit
        if truncated:
            events = events[: spec.limit]
        return QueryResult(
            events=events,
            total_matched=total,
            truncated=truncated,
            source_name=self.name,
        )

    def _normalize(self, log: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": log.get("@timestamp"),
            "source": self.name,
            "event_id": str(log.get("EVENTID", "")),
            "description": log.get("MESSAGE", ""),
            "severity": log.get("SEVERITY", ""),
            "technique_ids": list(log.get("MITRE_TECHNIQUE", [])),
            "host": log.get("SOURCE", ""),
            "raw": log,
        }

    def _load_logs(self) -> list[dict[str, Any]]:
        if self._api_available:  # pragma: no cover
            raise NotImplementedError("live ManageEngine querying not implemented")
        raw = json.loads(self._mock_path.read_text(encoding="utf-8"))
        return list(raw.get("logs", raw if isinstance(raw, list) else []))

    # --- detection authoring ------------------------------------------------ #
    def render_rule(self, detection: DetectionSpec) -> RenderedArtifact:
        """Render a ManageEngine correlation rule as JSON."""
        rule = {
            "ruleName": detection.title,
            "description": detection.description,
            "severity": str(detection.severity or Severity.MEDIUM),
            "mitreTechniques": list(detection.technique_ids),
            "criteria": detection.logic or "n/a",
            "requiredFields": list(detection.required_fields),
        }
        return RenderedArtifact(
            source_name=self.name,
            fmt="manageengine-json",
            content=json.dumps(rule, indent=2),
            detection_title=detection.title,
            technique_ids=list(detection.technique_ids),
        )

    def validate_rule(self, artifact: RenderedArtifact) -> ValidationReport:
        issues: list[ValidationIssue] = []
        try:
            data = json.loads(artifact.content)
        except json.JSONDecodeError as exc:
            return ValidationReport(
                valid=False,
                issues=[ValidationIssue(Severity.CRITICAL, f"invalid JSON: {exc}")],
            )
        if not isinstance(data, dict):
            return ValidationReport(
                valid=False,
                issues=[ValidationIssue(Severity.HIGH, "rule must be a JSON object")],
            )
        for required in ("ruleName", "criteria"):
            if not data.get(required):
                issues.append(
                    ValidationIssue(Severity.HIGH, f"missing '{required}'")
                )
        if not data.get("mitreTechniques"):
            issues.append(
                ValidationIssue(Severity.MEDIUM, "no mitreTechniques mapped")
            )
        valid = not any(
            i.severity in (Severity.HIGH, Severity.CRITICAL) for i in issues
        )
        return ValidationReport(valid=valid, issues=issues)
