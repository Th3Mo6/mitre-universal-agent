"""AI provider interface (Architecture §4.1).

Provider-agnostic request/response types plus the ``AIProvider`` Protocol. The
``complete`` method is async so the orchestrator can fan out to multiple
providers concurrently with ``asyncio.TaskGroup`` (Python 3.12).

Targets Python 3.12+.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "AIRequest",
    "AIResponse",
    "CostEstimate",
    "ProviderHealth",
    "AIProvider",
]


@dataclass(slots=True)
class AIRequest:
    """A provider-agnostic completion request."""

    prompt: str
    system: str = ""
    json_mode: bool = False
    max_tokens: int = 1024
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AIResponse:
    """A normalized response from a provider (or the ensemble aggregator)."""

    provider: str
    content: str = ""
    structured: dict[str, Any] | None = None
    ok: bool = True
    error: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class CostEstimate:
    """Estimated cost/usage for a request (Architecture §4.3 budgeting)."""

    input_tokens: int
    output_tokens: int
    usd: float = 0.0


@dataclass(slots=True, frozen=True)
class ProviderHealth:
    """Provider availability."""

    available: bool
    detail: str = ""


@runtime_checkable
class AIProvider(Protocol):
    """Uniform interface every LLM adapter implements (Architecture §4.1)."""

    name: str

    async def complete(self, request: AIRequest) -> AIResponse:
        """Produce a completion. Should not raise for normal provider errors;
        instead return an ``AIResponse`` with ``ok=False`` and ``error`` set."""
        ...

    def health_check(self) -> ProviderHealth:
        ...

    def cost_estimate(self, request: AIRequest) -> CostEstimate:
        ...
