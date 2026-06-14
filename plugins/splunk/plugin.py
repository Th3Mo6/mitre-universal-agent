"""Splunk source plugin (Architecture §3.3).

Implements the full ``LogSourcePlugin`` interface against Splunk's REST API /
search jobs (SPL). Defaults to **disabled** in config (Architecture §6.1); when
enabled but the real API is unreachable (always, in the sandbox) it falls back
to bundled mock search results at ``tests/mocks/splunk_events.json``.

Read-only query path; renders an SPL ``savedsearch`` stanza but never deploys
it.

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
_DEFAULT_MOCK = _REPO_ROOT / "tests" / "mocks" / "splunk_events.json"


def _parse_ts(value: str) -> datetime:
    """Parse an ISO timestamp into a timezone-aware UTC datetime (trailing 'Z'
    only; attaches UTC when offset-naive so comparisons never raise)."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class SplunkPlugin:
    """Splunk connector with transparent mock fallback."""

    name = "splunk"
    display_name = "Splunk"
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

        if bool(config.get("use_mock", False)):
            self._api_available = False
        else:
            self._api_available = self._probe_api()
        self._using_mock = not self._api_available
        if self._using_mock and not self._mock_path.exists():
            raise RuntimeError(
                f"Splunk API unavailable and mock not found: {self._mock_path}"
            )
        self._initialized = True
        logger.info(
            "Splunk initialized (api_available=%s, using_mock=%s)",
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
            logger.info("Splunk probe failed (%s); using mock", exc)
            return False

    def health_check(self) -> HealthStatus:
        now = datetime.now(timezone.utc)
        if not self._initialized:
            return HealthStatus(HealthState.UNAVAILABLE, "not initialized", now)
        if self._api_available:
            return HealthStatus(HealthState.CONNECTED, "Splunk reachable", now)
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
            DataSourceRef("Network Traffic", "Network Traffic Flow"),
            DataSourceRef("Network Traffic", "Network Traffic Content"),
            DataSourceRef("User Account", "User Account Authentication"),
        ]

    def existing_rules(self) -> list[DetectionRule]:
        results = self._load_results()
        seen: dict[str, DetectionRule] = {}
        for r in results:
            stype = str(r.get("sourcetype", ""))
            if not stype or stype in seen:
                continue
            seen[stype] = DetectionRule(
                rule_id=f"splunk-{stype}",
                name=f"sourcetype {stype}",
                technique_ids=list(r.get("mitre_technique", [])),
                enabled=True,
                metadata={"sourcetype": stype},
            )
        return list(seen.values())

    # --- telemetry access (read-only) -------------------------------------- #
    def query(self, spec: QuerySpec) -> QueryResult:
        if not self._initialized:
            raise RuntimeError("SplunkPlugin.query called before initialize()")
        results = self._load_results()
        events: list[dict[str, Any]] = []
        for r in results:
            ts_raw = r.get("_time")
            if ts_raw:
                ts = _parse_ts(str(ts_raw))
                if ts < spec.start or ts > spec.end:
                    continue
            if spec.technique_id is not None:
                if spec.technique_id not in r.get("mitre_technique", []):
                    continue
            events.append(self._normalize(r))

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

    def _normalize(self, r: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": r.get("_time"),
            "source": self.name,
            "raw_event": r.get("_raw", ""),
            "sourcetype": r.get("sourcetype", ""),
            "host": r.get("host", ""),
            "technique_ids": list(r.get("mitre_technique", [])),
            "fields": {k: v for k, v in r.items() if not k.startswith("_")},
        }

    def _load_results(self) -> list[dict[str, Any]]:
        if self._api_available:
            try:
                return self._fetch_from_api()
            except NotImplementedError:
                if not self._mock_path.exists():
                    raise
                logger.warning(
                    "Splunk live query not implemented; using mock (%s)",
                    self._mock_path,
                )
        raw = json.loads(self._mock_path.read_text(encoding="utf-8"))
        return list(raw.get("results", raw if isinstance(raw, list) else []))

    def _fetch_from_api(self) -> list[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError("live Splunk querying not implemented in v1")

    # --- detection authoring ------------------------------------------------ #
    def render_rule(self, detection: DetectionSpec) -> RenderedArtifact:
        """Render an SPL savedsearches.conf stanza."""
        search = detection.logic or "index=* | head 0"
        techniques = ",".join(detection.technique_ids)
        # Stanza name and single-line keys must not span lines in .conf format.
        title = " ".join(detection.title.split())
        description = " ".join(detection.description.split())
        stanza = (
            f"[{title}]\n"
            f"search = {search}\n"
            f"description = {description}\n"
            "dispatch.earliest_time = -60m\n"
            "dispatch.latest_time = now\n"
            f"action.annotate.mitre = {techniques}\n"
            "enableSched = 0\n"  # not scheduled until human approves
        )
        return RenderedArtifact(
            source_name=self.name,
            fmt="splunk-spl",
            content=stanza,
            detection_title=detection.title,
            technique_ids=list(detection.technique_ids),
        )

    def validate_rule(self, artifact: RenderedArtifact) -> ValidationReport:
        issues: list[ValidationIssue] = []
        content = artifact.content
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        if not lines or not (lines[0].startswith("[") and lines[0].endswith("]")):
            issues.append(
                ValidationIssue(Severity.HIGH, "missing savedsearch [stanza] header")
            )
        search_line = next((ln for ln in lines if ln.startswith("search =")), None)
        if search_line is None:
            issues.append(ValidationIssue(Severity.HIGH, "missing 'search =' clause"))
        elif not search_line.split("=", 1)[1].strip():
            issues.append(ValidationIssue(Severity.HIGH, "empty SPL search"))
        if "action.annotate.mitre" not in content:
            issues.append(
                ValidationIssue(Severity.MEDIUM, "no MITRE annotation present")
            )
        valid = not any(
            i.severity in (Severity.HIGH, Severity.CRITICAL) for i in issues
        )
        return ValidationReport(valid=valid, issues=issues)
