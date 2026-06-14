"""Runtime configuration store (Architecture §2.1, §5.3, §6).

Single source of truth for runtime configuration: which sources are enabled,
the AI strategy, and the scheduler rate. Hot-reloadable and observable — other
components subscribe to change events to react to enable/disable and rate
changes at runtime without a restart.

Credentials are NOT stored inline; ``SourceConfig.config`` holds references
(e.g. ``vault://...``) resolved elsewhere (Architecture §8.1).

Targets Python 3.12+.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "AIStrategy",
    "SchedulerMode",
    "SourceConfig",
    "SchedulerConfig",
    "AIConfig",
    "AppConfig",
    "ConfigChange",
    "ConfigError",
    "ConfigStore",
]


class ConfigError(ValueError):
    """Raised when a configuration value fails validation."""


class AIStrategy(StrEnum):
    """Multi-AI orchestration strategy (Architecture §4.2)."""

    SINGLE = "single"
    FALLBACK = "fallback"
    ENSEMBLE = "ensemble"


class SchedulerMode(StrEnum):
    """Pacing distribution within the hour (Architecture §5.1)."""

    EVEN = "even"
    BURST = "burst"


@dataclass(slots=True)
class SourceConfig:
    """Per-source runtime state (Architecture §6.1)."""

    enabled: bool = False
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SchedulerConfig:
    """Scheduler pacing config (Architecture §5)."""

    techniques_per_hour: int = 5
    techniques_per_run: int = 5
    mode: SchedulerMode = SchedulerMode.EVEN
    max_concurrent: int = 1

    # Generous upper bounds to catch fat-finger config without constraining
    # legitimate use (the full ATT&CK matrix is < 1000 techniques).
    _MAX = 100_000

    def validate(self) -> None:
        if not 1 <= self.techniques_per_hour <= self._MAX:
            raise ConfigError(
                f"scheduler.techniques_per_hour must be in [1, {self._MAX}]"
            )
        if not 1 <= self.techniques_per_run <= self._MAX:
            raise ConfigError(
                f"scheduler.techniques_per_run must be in [1, {self._MAX}]"
            )
        if self.max_concurrent < 1:
            raise ConfigError("scheduler.max_concurrent must be >= 1")

    @property
    def interval_seconds(self) -> float:
        """Even-mode spacing between evaluations."""
        return 3600.0 / self.techniques_per_hour


@dataclass(slots=True)
class AIConfig:
    """Multi-AI orchestrator config (Architecture §4)."""

    strategy: AIStrategy = AIStrategy.SINGLE
    providers: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.strategy != AIStrategy.SINGLE and len(self.providers) < 2:
            raise ConfigError(
                f"strategy '{self.strategy}' requires at least 2 providers"
            )


@dataclass(slots=True)
class AppConfig:
    """Top-level runtime configuration."""

    sources: dict[str, SourceConfig] = field(default_factory=dict)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    ai: AIConfig = field(default_factory=AIConfig)

    def validate(self) -> None:
        self.scheduler.validate()
        self.ai.validate()

    # --- (de)serialization -------------------------------------------------- #
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppConfig:
        sources = {
            name: SourceConfig(
                enabled=bool(s.get("enabled", False)),
                config=dict(s.get("config", {})),
            )
            for name, s in data.get("sources", {}).items()
        }
        sched_in = data.get("scheduler", {})
        scheduler = SchedulerConfig(
            techniques_per_hour=int(sched_in.get("techniques_per_hour", 5)),
            techniques_per_run=int(sched_in.get("techniques_per_run", 5)),
            mode=SchedulerMode(sched_in.get("mode", SchedulerMode.EVEN)),
            max_concurrent=int(sched_in.get("max_concurrent", 1)),
        )
        ai_in = data.get("ai", {})
        ai = AIConfig(
            strategy=AIStrategy(ai_in.get("strategy", AIStrategy.SINGLE)),
            providers=list(ai_in.get("providers", [])),
        )
        cfg = cls(sources=sources, scheduler=scheduler, ai=ai)
        cfg.validate()
        return cfg

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": {n: asdict(s) for n, s in self.sources.items()},
            "scheduler": {
                "techniques_per_hour": self.scheduler.techniques_per_hour,
                "techniques_per_run": self.scheduler.techniques_per_run,
                "mode": str(self.scheduler.mode),
                "max_concurrent": self.scheduler.max_concurrent,
            },
            "ai": {
                "strategy": str(self.ai.strategy),
                "providers": list(self.ai.providers),
            },
        }


@dataclass(slots=True, frozen=True)
class ConfigChange:
    """Emitted to subscribers when configuration changes."""

    kind: str  # "source" | "scheduler" | "ai" | "reload"
    key: str  # e.g. source name, or "" for global
    config: AppConfig


ChangeListener = Callable[[ConfigChange], None]


class ConfigStore:
    """Thread-safe, observable, hot-reloadable configuration store."""

    def __init__(self, config: AppConfig | None = None) -> None:
        self._config = config or AppConfig()
        self._config.validate()
        self._listeners: list[ChangeListener] = []
        self._lock = threading.RLock()

    # --- access ------------------------------------------------------------- #
    @property
    def config(self) -> AppConfig:
        with self._lock:
            return self._config

    def is_source_enabled(self, name: str) -> bool:
        with self._lock:
            src = self._config.sources.get(name)
            return bool(src and src.enabled)

    def enabled_sources(self) -> list[str]:
        with self._lock:
            return [n for n, s in self._config.sources.items() if s.enabled]

    # --- subscription ------------------------------------------------------- #
    def subscribe(self, listener: ChangeListener) -> Callable[[], None]:
        """Register a change listener; returns an unsubscribe callable."""
        with self._lock:
            self._listeners.append(listener)

        def _unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return _unsubscribe

    def _emit(self, change: ConfigChange) -> None:
        # Snapshot under the lock, then deliver outside it (avoids re-entrancy/
        # deadlock). One failing listener must not block delivery to the rest.
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(change)
            except Exception:  # noqa: BLE001 - isolate listener failures
                logger.exception("config change listener failed")

    # --- mutation ----------------------------------------------------------- #
    def set_source_enabled(self, name: str, enabled: bool) -> None:
        with self._lock:
            src = self._config.sources.setdefault(name, SourceConfig())
            src.enabled = enabled
            snapshot = self._config
        self._emit(ConfigChange("source", name, snapshot))

    def set_source_config(self, name: str, config: dict[str, Any]) -> None:
        with self._lock:
            src = self._config.sources.setdefault(name, SourceConfig())
            src.config = dict(config)
            snapshot = self._config
        self._emit(ConfigChange("source", name, snapshot))

    def set_techniques_per_hour(self, value: int) -> None:
        with self._lock:
            new = SchedulerConfig(
                techniques_per_hour=value,
                techniques_per_run=self._config.scheduler.techniques_per_run,
                mode=self._config.scheduler.mode,
                max_concurrent=self._config.scheduler.max_concurrent,
            )
            new.validate()  # raises BEFORE we commit anything
            self._config.scheduler = new
            snapshot = self._config
        self._emit(ConfigChange("scheduler", "techniques_per_hour", snapshot))

    def set_techniques_per_run(self, value: int) -> None:
        with self._lock:
            new = SchedulerConfig(
                techniques_per_hour=self._config.scheduler.techniques_per_hour,
                techniques_per_run=value,
                mode=self._config.scheduler.mode,
                max_concurrent=self._config.scheduler.max_concurrent,
            )
            new.validate()  # raises BEFORE we commit anything
            self._config.scheduler = new
            snapshot = self._config
        self._emit(ConfigChange("scheduler", "techniques_per_run", snapshot))

    def set_ai_strategy(self, strategy: AIStrategy, providers: list[str]) -> None:
        with self._lock:
            new = AIConfig(strategy=strategy, providers=list(providers))
            new.validate()
            self._config.ai = new
            snapshot = self._config
        self._emit(ConfigChange("ai", "strategy", snapshot))

    # --- persistence (JSON; stdlib only) ------------------------------------ #
    @classmethod
    def load(cls, path: str | Path) -> ConfigStore:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(AppConfig.from_dict(data))

    def save(self, path: str | Path) -> None:
        with self._lock:
            data = self._config.to_dict()
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def reload(self, path: str | Path) -> None:
        """Hot-reload from disk and notify subscribers."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        new_config = AppConfig.from_dict(data)
        with self._lock:
            self._config = new_config
            snapshot = self._config
        self._emit(ConfigChange("reload", "", snapshot))
