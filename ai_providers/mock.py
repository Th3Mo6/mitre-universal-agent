"""Mock AI provider for testing without API keys (Architecture §9, §4).

Deterministic, configurable provider used by the test-suite and local runs in
the Claude storage sandbox where no real provider credentials exist.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ai_providers.base import (
    AIRequest,
    AIResponse,
    CostEstimate,
    ProviderHealth,
)

__all__ = ["MockProvider"]


class MockProvider:
    """A controllable fake provider.

    Parameters
    ----------
    name: provider id.
    content: text to return (ignored if ``structured`` given).
    structured: structured payload to return.
    fail: if True, returns ``ok=False`` (simulates a provider error).
    raises: if True, raises inside ``complete`` (simulates a hard crash).
    delay: simulated latency in seconds.
    confidence: per-provider confidence to report.
    """

    def __init__(
        self,
        name: str,
        *,
        content: str = "",
        structured: dict[str, Any] | None = None,
        fail: bool = False,
        raises: bool = False,
        delay: float = 0.0,
        confidence: float = 1.0,
    ) -> None:
        self.name = name
        self._content = content or f"response from {name}"
        self._structured = structured
        self._fail = fail
        self._raises = raises
        self._delay = delay
        self._confidence = confidence
        self.call_count = 0

    async def complete(self, request: AIRequest) -> AIResponse:
        self.call_count += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._raises:
            raise RuntimeError(f"{self.name} crashed")
        if self._fail:
            return AIResponse(
                provider=self.name,
                ok=False,
                error=f"{self.name} simulated failure",
            )
        return AIResponse(
            provider=self.name,
            content=self._content,
            structured=self._structured,
            ok=True,
            output_tokens=len(self._content.split()),
            latency_ms=int(self._delay * 1000),
            confidence=self._confidence,
        )

    def health_check(self) -> ProviderHealth:
        return ProviderHealth(available=not self._fail, detail="mock")

    def cost_estimate(self, request: AIRequest) -> CostEstimate:
        return CostEstimate(input_tokens=len(request.prompt.split()), output_tokens=0)
