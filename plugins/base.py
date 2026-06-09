"""Source plugin interface for the Universal MITRE AI Agent.

Implements the ``LogSourcePlugin`` Protocol and its supporting data types as
described in ``docs/Architecture.md`` §3.1. All telemetry sources (Wazuh,
ManageEngine, Splunk, and future additions) implement this single interface so
the rest of the system never needs source-specific code.

Targets Python 3.12+ (PEP 695 type aliases, ``StrEnum``, ``slots`` dataclasses,
runtime-checkable ``Protocol``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "HealthState",
    "HealthStatus",
    "DataSourceRef",
    "DetectionRule",
    "QuerySpec",
    "QueryResult",
    "DetectionSpec",
    "RenderedArtifact",
    "Severity",
    "ValidationIssue",
    "ValidationReport",
    "LogSourcePlugin",
]


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
class HealthState(StrEnum):
    """Connection/health state of a source, per Architecture §3.1."""

    CONNECTED = "connected"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(slots=True, frozen=True)
class HealthStatus:
    """Result of :meth:`LogSourcePlugin.health_check`."""

    state: HealthState
    detail: str = ""
    checked_at: datetime | None = None

    @property
    def is_usable(self) -> bool:
        """True when the source can serve queries (CONNECTED or DEGRADED)."""
        return self.state in (HealthState.CONNECTED, HealthState.DEGRADED)


# --------------------------------------------------------------------------- #
# Capability advertisement
# --------------------------------------------------------------------------- #
@dataclass(slots=True, frozen=True)
class DataSourceRef:
    """An ATT&CK data source / data component this connector can provide.

    Example: ``DataSourceRef("Process", "Process Creation")`` →
    ``"Process: Process Creation"``.
    """

    data_source: str
    data_component: str

    def __str__(self) -> str:
        return f"{self.data_source}: {self.data_component}"


@dataclass(slots=True)
class DetectionRule:
    """A normalized representation of a detection already deployed in a source.

    Used for coverage/gap analysis. ``native`` keeps the raw source-specific
    rule body for reference.
    """

    rule_id: str
    name: str
    technique_ids: list[str] = field(default_factory=list)
    enabled: bool = True
    native: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Telemetry access
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class QuerySpec:
    """A source-agnostic telemetry query.

    The plugin translates this into its native query mechanism while enforcing
    read-only access (Architecture §8.2).
    """

    start: datetime
    end: datetime
    fields: list[str] = field(default_factory=list)
    filters: dict[str, Any] = field(default_factory=dict)
    technique_id: str | None = None
    limit: int = 1000


@dataclass(slots=True)
class QueryResult:
    """Normalized events returned by :meth:`LogSourcePlugin.query`."""

    events: list[dict[str, Any]] = field(default_factory=list)
    total_matched: int = 0
    truncated: bool = False
    source_name: str = ""
    took_ms: int = 0

    @property
    def count(self) -> int:
        return len(self.events)


# --------------------------------------------------------------------------- #
# Detection authoring
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class DetectionSpec:
    """A source-agnostic detection produced by the AI orchestrator.

    A plugin's :meth:`render_rule` turns this into native rule syntax.
    """

    title: str
    description: str
    technique_ids: list[str] = field(default_factory=list)
    logic: str = ""
    required_fields: list[str] = field(default_factory=list)
    severity: "Severity | None" = None
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RenderedArtifact:
    """Native rule text produced by :meth:`LogSourcePlugin.render_rule`."""

    source_name: str
    fmt: str
    content: str
    detection_title: str = ""
    technique_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Severity(StrEnum):
    """Detection severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True, frozen=True)
class ValidationIssue:
    """A single problem found while statically validating a rendered rule."""

    severity: Severity
    message: str
    location: str = ""


@dataclass(slots=True)
class ValidationReport:
    """Result of :meth:`LogSourcePlugin.validate_rule` (static; never deploys)."""

    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(
            i.severity in (Severity.HIGH, Severity.CRITICAL) for i in self.issues
        )


# --------------------------------------------------------------------------- #
# The plugin contract
# --------------------------------------------------------------------------- #
@runtime_checkable
class LogSourcePlugin(Protocol):
    """Uniform interface every telemetry source implements (Architecture §3.1).

    Implementations MUST enforce read-only access on the :meth:`query` path and
    MUST NOT deploy anything from :meth:`render_rule`/:meth:`validate_rule`.
    """

    # --- Identity & lifecycle ---
    name: str
    display_name: str
    version: str

    def initialize(self, config: dict[str, Any]) -> None:
        """Validate config and establish a connection/session. Idempotent."""
        ...

    def health_check(self) -> HealthStatus:
        """Return CONNECTED | DEGRADED | UNAVAILABLE with detail."""
        ...

    def shutdown(self) -> None:
        """Release connections/resources. Safe to call multiple times."""
        ...

    # --- Capability advertisement ---
    def supported_data_sources(self) -> list[DataSourceRef]:
        """ATT&CK data sources/components this connector can provide."""
        ...

    def existing_rules(self) -> list[DetectionRule]:
        """Currently deployed detections, normalized, for gap analysis."""
        ...

    # --- Telemetry access ---
    def query(self, spec: QuerySpec) -> QueryResult:
        """Run a normalized, read-only query and return normalized events."""
        ...

    # --- Detection authoring ---
    def render_rule(self, detection: DetectionSpec) -> RenderedArtifact:
        """Translate a source-agnostic DetectionSpec into native rule syntax."""
        ...

    def validate_rule(self, artifact: RenderedArtifact) -> ValidationReport:
        """Statically validate native syntax where possible (does NOT deploy)."""
        ...
