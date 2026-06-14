"""Source Manager (Architecture §2.1, §6).

Loads/unloads source plugins according to the ConfigStore, exposes a uniform
query interface, and tracks per-source health and enable/disable state. Honors
the runtime enable/disable flow from Architecture §6.2:

  * fail-closed enable: a source that fails config validation or health check
    is NOT activated (marked ERROR, excluded);
  * graceful disable: shutdown() is called when a source is disabled;
  * per-source isolation: one source being UNAVAILABLE never blocks others.

Plugins are provided via a factory registry (name -> callable returning a
``LogSourcePlugin``). The manager subscribes to ConfigStore changes so toggles
take effect at runtime without a restart.

Targets Python 3.12+.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from core.config_store import ConfigChange, ConfigStore
from plugins.base import (
    DataSourceRef,
    DetectionRule,
    HealthState,
    LogSourcePlugin,
    QueryResult,
    QuerySpec,
)

__all__ = [
    "SourceState",
    "ManagedSource",
    "SourceManager",
    "PluginFactory",
]

logger = logging.getLogger(__name__)

PluginFactory = Callable[[], LogSourcePlugin]


class SourceState(StrEnum):
    """Runtime activation state of a managed source (Architecture §6.2)."""

    DISABLED = "disabled"
    ACTIVE = "active"
    ERROR = "error"


@dataclass(slots=True)
class ManagedSource:
    """Bookkeeping for one source the manager knows about."""

    name: str
    state: SourceState = SourceState.DISABLED
    plugin: LogSourcePlugin | None = None
    last_error: str = ""
    detail: str = ""
    applied_config: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class SourceManager:
    """Manages the lifecycle of enabled source plugins."""

    def __init__(self, config_store: ConfigStore) -> None:
        self._store = config_store
        self._factories: dict[str, PluginFactory] = {}
        self._sources: dict[str, ManagedSource] = {}
        self._lock = threading.RLock()
        # Single-flights reconciliation so concurrent sync() calls (e.g. a
        # config-change callback racing the constructor's sync) can't double-
        # activate or leak plugins. Distinct from _lock (which guards the maps).
        self._sync_lock = threading.Lock()
        self._unsubscribe = self._store.subscribe(self._on_config_change)

    # --- registration ------------------------------------------------------- #
    def register(self, name: str, factory: PluginFactory) -> None:
        """Register a plugin factory under ``name``."""
        with self._lock:
            self._factories[name] = factory
            self._sources.setdefault(name, ManagedSource(name=name))

    def sync(self) -> None:
        """Reconcile actual plugin state with the ConfigStore.

        Idempotent and single-flighted: handles enable/disable edges AND config
        drift (an already-active source whose config changed is re-initialized
        so runtime config edits actually take effect).
        """
        with self._sync_lock:
            for name in list(self._factories):
                desired = self._store.is_source_enabled(name)
                active = self._is_active(name)
                if desired and not active:
                    self._activate(name)
                elif not desired and active:
                    self._deactivate(name)
                elif desired and active and self._config_drifted(name):
                    logger.info("Config changed for '%s'; reactivating", name)
                    self._deactivate(name)
                    self._activate(name)

    def _config_drifted(self, name: str) -> bool:
        with self._lock:
            managed = self._sources.get(name)
            applied = dict(managed.applied_config) if managed else {}
        cfg = self._store.config.sources.get(name)
        current = dict(cfg.config) if cfg else {}
        return applied != current

    # --- state queries ------------------------------------------------------ #
    def active_sources(self) -> list[str]:
        with self._lock:
            return [
                n for n, s in self._sources.items() if s.state == SourceState.ACTIVE
            ]

    def state_of(self, name: str) -> SourceState:
        with self._lock:
            src = self._sources.get(name)
            return src.state if src else SourceState.DISABLED

    def _is_active(self, name: str) -> bool:
        return self.state_of(name) == SourceState.ACTIVE

    # --- lifecycle ---------------------------------------------------------- #
    def _activate(self, name: str) -> None:
        """Activate a source, failing closed on any error (Architecture §6.3)."""
        # Read the source config from the store BEFORE taking our own lock, so
        # we never nest the store lock under the manager lock (avoids a
        # lock-ordering hazard with the config-change callback path).
        cfg = self._store.config.sources.get(name)
        source_cfg = dict(cfg.config) if cfg else {}

        with self._lock:
            factory = self._factories.get(name)
            if factory is None:
                logger.warning("No factory registered for source '%s'", name)
                return
            managed = self._sources.setdefault(name, ManagedSource(name=name))

        try:
            plugin = factory()
            plugin.initialize(source_cfg)
            health = plugin.health_check()
            if health.state == HealthState.UNAVAILABLE:
                # Fail closed: do not mark ACTIVE. Don't let a shutdown error
                # mask the real UNAVAILABLE reason.
                try:
                    plugin.shutdown()
                except Exception as se:  # noqa: BLE001
                    logger.warning("shutdown after UNAVAILABLE for '%s': %s", name, se)
                raise RuntimeError(f"health check UNAVAILABLE: {health.detail}")
        except Exception as exc:  # noqa: BLE001 - fail closed on any error
            with self._lock:
                managed.state = SourceState.ERROR
                managed.plugin = None
                managed.last_error = str(exc)
                managed.detail = "activation failed"
            logger.error("Failed to enable source '%s': %s", name, exc)
            return

        # Re-check intent before committing: a disable toggle may have arrived
        # while initialize/health_check ran outside the lock (TOCTOU guard).
        if not self._store.is_source_enabled(name):
            try:
                plugin.shutdown()
            except Exception as se:  # noqa: BLE001
                logger.warning("shutdown of '%s' after disable race: %s", name, se)
            with self._lock:
                managed.plugin = None
                managed.state = SourceState.DISABLED
                managed.detail = "disabled during activation"
            logger.info("Source '%s' disabled during activation; not activated", name)
            return

        with self._lock:
            managed.plugin = plugin
            managed.state = SourceState.ACTIVE
            managed.last_error = ""
            managed.detail = health.detail
            managed.applied_config = source_cfg
        logger.info("Source '%s' is ACTIVE (%s)", name, health.state)

    def _deactivate(self, name: str) -> None:
        """Gracefully disable a source (Architecture §6.3)."""
        with self._lock:
            managed = self._sources.get(name)
            plugin = managed.plugin if managed else None

        if plugin is not None:
            try:
                plugin.shutdown()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error during shutdown of '%s': %s", name, exc)

        with self._lock:
            if managed is not None:
                managed.plugin = None
                managed.state = SourceState.DISABLED
                managed.detail = "disabled"
                managed.applied_config = {}
        logger.info("Source '%s' is DISABLED", name)

    # --- config reactivity -------------------------------------------------- #
    def _on_config_change(self, change: ConfigChange) -> None:
        """React to runtime enable/disable toggles."""
        if change.kind in ("source", "reload"):
            self.sync()

    # --- uniform query interface -------------------------------------------- #
    def query(self, name: str, spec: QuerySpec) -> QueryResult:
        """Query a single active source. Raises if not active."""
        plugin = self._require_active(name)
        return plugin.query(spec)

    def query_all(self, spec: QuerySpec) -> dict[str, QueryResult]:
        """Query every active source; per-source isolation (Architecture §6.3).

        A source that errors is skipped (logged) rather than failing the batch.
        """
        results: dict[str, QueryResult] = {}
        for name in self.active_sources():
            try:
                results[name] = self.query(name, spec)
            except Exception as exc:  # noqa: BLE001 - isolate failures
                logger.warning("Query to source '%s' failed: %s", name, exc)
        return results

    def supported_data_sources(self) -> dict[str, list[DataSourceRef]]:
        out: dict[str, list[DataSourceRef]] = {}
        for name in self.active_sources():
            plugin = self._require_active(name)
            out[name] = plugin.supported_data_sources()
        return out

    def existing_rules(self) -> dict[str, list[DetectionRule]]:
        out: dict[str, list[DetectionRule]] = {}
        for name in self.active_sources():
            plugin = self._require_active(name)
            out[name] = plugin.existing_rules()
        return out

    def _require_active(self, name: str) -> LogSourcePlugin:
        with self._lock:
            managed = self._sources.get(name)
            if not managed or managed.state != SourceState.ACTIVE or managed.plugin is None:
                raise RuntimeError(f"source '{name}' is not active")
            return managed.plugin

    # --- teardown ----------------------------------------------------------- #
    def shutdown_all(self) -> None:
        for name in self.active_sources():
            self._deactivate(name)

    def close(self) -> None:
        """Unsubscribe from config changes and shut all sources down."""
        self._unsubscribe()
        self.shutdown_all()
