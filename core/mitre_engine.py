"""MITRE ATT&CK engine (Architecture §2.1, §5.2, §7).

Holds the ATT&CK technique catalog, maps telemetry data sources to techniques,
and computes coverage / gaps given the set of *enabled* sources and their
existing rules. Also supports the scheduler's technique-selection priority
(never-evaluated → staleness → gap severity → enabled-source relevance).

v1 ships with a small, pinned seed catalog so the system runs without a live
STIX fetch (Architecture §9, open question 3). ``load_catalog`` allows swapping
in a fuller catalog later.

Targets Python 3.12+.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Iterable

__all__ = [
    "Technique",
    "CoverageLevel",
    "TechniqueCoverage",
    "CoverageReport",
    "MitreEngine",
    "DEFAULT_CATALOG",
]


class CoverageLevel(IntEnum):
    """Coverage of a technique by enabled telemetry + existing rules."""

    NONE = 0  # no enabled telemetry can observe this technique
    TELEMETRY_ONLY = 1  # observable, but no detection rule exists
    PARTIAL = 2  # some rules exist but data sources only partly covered
    COVERED = 3  # observable and at least one rule targets it


@dataclass(slots=True)
class Technique:
    """An ATT&CK technique (or sub-technique)."""

    technique_id: str  # e.g. "T1059" or "T1059.001"
    name: str
    tactics: list[str] = field(default_factory=list)
    # ATT&CK data sources as "Data Source: Data Component" strings.
    data_sources: list[str] = field(default_factory=list)
    is_subtechnique: bool = False

    def __post_init__(self) -> None:
        self.is_subtechnique = "." in self.technique_id


@dataclass(slots=True)
class TechniqueCoverage:
    """Coverage result for a single technique."""

    technique_id: str
    level: CoverageLevel
    observable: bool
    matching_data_sources: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    last_evaluated_at: datetime | None = None

    @property
    def is_gap(self) -> bool:
        """A gap = observable but not yet COVERED."""
        return self.observable and self.level < CoverageLevel.COVERED


@dataclass(slots=True)
class CoverageReport:
    """Coverage across the whole catalog for a given enabled-source set."""

    per_technique: dict[str, TechniqueCoverage] = field(default_factory=dict)

    @property
    def gaps(self) -> list[TechniqueCoverage]:
        return [c for c in self.per_technique.values() if c.is_gap]

    @property
    def unobservable(self) -> list[TechniqueCoverage]:
        return [c for c in self.per_technique.values() if not c.observable]

    def summary(self) -> dict[str, int]:
        out = {lvl.name: 0 for lvl in CoverageLevel}
        for c in self.per_technique.values():
            out[c.level.name] += 1
        return out


# A small, pinned seed catalog. Replace via ``load_catalog`` with a fuller set.
DEFAULT_CATALOG: list[Technique] = [
    Technique(
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        ["execution"],
        ["Process: Process Creation", "Command: Command Execution"],
    ),
    Technique(
        "T1078",
        "Valid Accounts",
        ["defense-evasion", "persistence", "initial-access"],
        ["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
    ),
    Technique(
        "T1110",
        "Brute Force",
        ["credential-access"],
        ["User Account: User Account Authentication", "Logon Session: Logon Session Creation"],
    ),
    Technique(
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
        ["execution", "persistence", "privilege-escalation"],
        ["Scheduled Job: Scheduled Job Creation", "Process: Process Creation"],
    ),
    Technique(
        "T1071.001",
        "Application Layer Protocol: Web Protocols",
        ["command-and-control"],
        ["Network Traffic: Network Traffic Flow", "Network Traffic: Network Traffic Content"],
    ),
]


class MitreEngine:
    """ATT&CK catalog + coverage computation."""

    def __init__(self, catalog: Iterable[Technique] | None = None) -> None:
        self._techniques: dict[str, Technique] = {}
        self.load_catalog(catalog if catalog is not None else DEFAULT_CATALOG)

    # --- catalog ------------------------------------------------------------ #
    def load_catalog(self, techniques: Iterable[Technique]) -> None:
        self._techniques = {t.technique_id: t for t in techniques}

    @property
    def techniques(self) -> list[Technique]:
        return list(self._techniques.values())

    def get(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id)

    def techniques_for_data_sources(self, data_sources: Iterable[str]) -> list[Technique]:
        """Techniques observable by at least one of the given data sources."""
        available = set(data_sources)
        return [
            t
            for t in self._techniques.values()
            if available.intersection(t.data_sources)
        ]

    # --- coverage ----------------------------------------------------------- #
    def compute_coverage(
        self,
        enabled_data_sources: Iterable[str],
        existing_rules: Iterable[Any] | None = None,
        last_evaluated: dict[str, datetime] | None = None,
    ) -> CoverageReport:
        """Compute coverage given enabled telemetry and existing rules.

        ``existing_rules`` items must expose ``technique_ids`` and ``rule_id``
        attributes (e.g. ``plugins.base.DetectionRule``).
        """
        available = set(enabled_data_sources)
        last_eval = last_evaluated or {}

        # technique_id -> set of rule ids targeting it
        rules_by_tech: dict[str, list[str]] = {}
        for rule in existing_rules or []:
            for tid in getattr(rule, "technique_ids", []):
                rules_by_tech.setdefault(tid, []).append(
                    getattr(rule, "rule_id", "")
                )

        report = CoverageReport()
        for t in self._techniques.values():
            matching = sorted(available.intersection(t.data_sources))
            observable = bool(matching)
            rule_ids = rules_by_tech.get(t.technique_id, [])

            if not observable:
                level = CoverageLevel.NONE
            elif rule_ids:
                fully = len(matching) == len(set(t.data_sources))
                level = CoverageLevel.COVERED if fully else CoverageLevel.PARTIAL
            else:
                level = CoverageLevel.TELEMETRY_ONLY

            report.per_technique[t.technique_id] = TechniqueCoverage(
                technique_id=t.technique_id,
                level=level,
                observable=observable,
                matching_data_sources=matching,
                rule_ids=rule_ids,
                last_evaluated_at=last_eval.get(t.technique_id),
            )
        return report

    # --- scheduler support -------------------------------------------------- #
    def selection_order(
        self,
        enabled_data_sources: Iterable[str],
        existing_rules: Iterable[Any] | None = None,
        last_evaluated: dict[str, datetime] | None = None,
    ) -> list[str]:
        """Return technique IDs ordered by selection priority (Architecture §5.2).

        Observable-by-an-enabled-source is the PRIMARY key: techniques no
        enabled source can observe can't be meaningfully evaluated, so they are
        deferred to the very end. Within the observable set the order is:
        never-evaluated first, then oldest-evaluated (staleness), then largest
        coverage gap. Staleness is bucketed to whole seconds so the gap-severity
        tiebreak is actually effective (sub-second timestamps would otherwise
        make ties practically impossible).
        """
        report = self.compute_coverage(
            enabled_data_sources, existing_rules, last_evaluated
        )

        def sort_key(tid: str) -> tuple[Any, ...]:
            cov = report.per_technique[tid]
            never = cov.last_evaluated_at is None
            # Older timestamps first; whole-second bucket so gap_severity can
            # break ties. never-evaluated handled by the `never` flag.
            staleness = (
                int(cov.last_evaluated_at.timestamp())
                if cov.last_evaluated_at is not None
                else 0
            )
            gap_severity = CoverageLevel.COVERED - cov.level  # bigger = worse
            return (
                not cov.observable,  # observable first; unobservable last
                not never,  # never-evaluated first
                staleness,  # then oldest
                -int(gap_severity),  # then biggest gap
            )

        return sorted(self._techniques.keys(), key=sort_key)
