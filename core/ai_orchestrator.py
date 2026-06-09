"""Multi-AI orchestrator (Architecture §4.2).

Routes an ``AIRequest`` to one or more providers according to the configured
strategy and normalizes the outcome to a single ``AIResponse``:

  * single   — one provider handles the request.
  * fallback — ordered providers; first valid response wins; on error/invalid,
               fall through to the next.
  * ensemble — fan out to all providers in parallel using
               ``asyncio.TaskGroup`` (Python 3.12), then aggregate by
               majority vote with confidence = agreement ratio.

Strategy and provider order are read from the ConfigStore at call time, so
runtime config changes take effect immediately (Architecture §4.3).

Targets Python 3.12+.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter

from ai_providers.base import AIProvider, AIRequest, AIResponse
from core.config_store import AIStrategy, ConfigStore

__all__ = ["AIOrchestrator", "OrchestratorError"]

logger = logging.getLogger(__name__)


class OrchestratorError(RuntimeError):
    """Raised when no usable response can be produced."""


def _is_valid(resp: AIResponse, json_mode: bool) -> bool:
    """A response is acceptable if ok and (when json_mode) structured present."""
    if not resp.ok:
        return False
    if json_mode and resp.structured is None:
        return False
    return True


class AIOrchestrator:
    """Dispatches AI requests per the configured strategy."""

    def __init__(
        self,
        providers: dict[str, AIProvider],
        config_store: ConfigStore,
    ) -> None:
        self._providers = dict(providers)
        self._store = config_store

    # --- provider ordering -------------------------------------------------- #
    def _ordered_providers(self) -> list[AIProvider]:
        cfg = self._store.config.ai
        ordered = [self._providers[n] for n in cfg.providers if n in self._providers]
        if not ordered:
            # No explicit order configured -> use all registered providers.
            ordered = list(self._providers.values())
        if not ordered:
            raise OrchestratorError("no AI providers registered")
        return ordered

    # --- public entrypoint -------------------------------------------------- #
    async def complete(self, request: AIRequest) -> AIResponse:
        strategy = self._store.config.ai.strategy
        providers = self._ordered_providers()
        match strategy:
            case AIStrategy.SINGLE:
                return await self._single(providers, request)
            case AIStrategy.FALLBACK:
                return await self._fallback(providers, request)
            case AIStrategy.ENSEMBLE:
                return await self._ensemble(providers, request)
        raise OrchestratorError(f"unknown strategy: {strategy}")  # pragma: no cover

    # --- strategies --------------------------------------------------------- #
    async def _single(
        self, providers: list[AIProvider], request: AIRequest
    ) -> AIResponse:
        provider = providers[0]
        try:
            resp = await provider.complete(request)
        except Exception as exc:  # noqa: BLE001
            return AIResponse(provider=provider.name, ok=False, error=str(exc))
        return resp

    async def _fallback(
        self, providers: list[AIProvider], request: AIRequest
    ) -> AIResponse:
        last: AIResponse | None = None
        for provider in providers:
            try:
                resp = await provider.complete(request)
            except Exception as exc:  # noqa: BLE001 - try next provider
                last = AIResponse(provider=provider.name, ok=False, error=str(exc))
                logger.info("Provider '%s' raised; falling back: %s", provider.name, exc)
                continue
            if _is_valid(resp, request.json_mode):
                resp.metadata["strategy"] = "fallback"
                return resp
            last = resp
            logger.info("Provider '%s' invalid; falling back", provider.name)
        if last is None:  # pragma: no cover - providers list is non-empty
            raise OrchestratorError("fallback produced no response")
        last.metadata["strategy"] = "fallback"
        last.metadata["exhausted"] = True
        return last

    async def _ensemble(
        self, providers: list[AIProvider], request: AIRequest
    ) -> AIResponse:
        # Fan out concurrently with TaskGroup (Python 3.12).
        tasks: list[asyncio.Task[AIResponse]] = []
        async with asyncio.TaskGroup() as tg:
            for provider in providers:
                tasks.append(tg.create_task(self._safe_complete(provider, request)))
        responses = [t.result() for t in tasks]
        return self._aggregate(responses, request)

    async def _safe_complete(
        self, provider: AIProvider, request: AIRequest
    ) -> AIResponse:
        """Never raises — converts exceptions to ok=False so TaskGroup doesn't
        cancel siblings."""
        try:
            return await provider.complete(request)
        except Exception as exc:  # noqa: BLE001
            return AIResponse(provider=provider.name, ok=False, error=str(exc))

    # --- ensemble aggregation ----------------------------------------------- #
    def _aggregate(
        self, responses: list[AIResponse], request: AIRequest
    ) -> AIResponse:
        valid = [r for r in responses if _is_valid(r, request.json_mode)]
        participating = [r.provider for r in responses]

        if not valid:
            errors = "; ".join(f"{r.provider}: {r.error}" for r in responses)
            return AIResponse(
                provider="ensemble",
                ok=False,
                error=f"all providers failed ({errors})",
                confidence=0.0,
                metadata={
                    "strategy": "ensemble",
                    "providers": participating,
                    "agreed": 0,
                    "total": len(responses),
                },
            )

        # Vote on a comparable key: structured payload (json) or content text.
        def vote_key(r: AIResponse) -> str:
            if r.structured is not None:
                return repr(sorted(r.structured.items()))
            return r.content.strip()

        counts = Counter(vote_key(r) for r in valid)
        winning_key, agree = counts.most_common(1)[0]
        winner = next(r for r in valid if vote_key(r) == winning_key)
        confidence = agree / len(valid)

        return AIResponse(
            provider="ensemble",
            content=winner.content,
            structured=winner.structured,
            ok=True,
            output_tokens=sum(r.output_tokens for r in valid),
            confidence=confidence,
            metadata={
                "strategy": "ensemble",
                "providers": participating,
                "valid_providers": [r.provider for r in valid],
                "winner": winner.provider,
                "agreed": agree,
                "total_valid": len(valid),
                "total": len(responses),
            },
        )
