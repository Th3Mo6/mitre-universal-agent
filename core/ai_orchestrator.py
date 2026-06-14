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
import json
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
        if not cfg.providers:
            # No explicit order configured -> use all registered providers.
            ordered = list(self._providers.values())
            if not ordered:
                raise OrchestratorError("no AI providers registered")
            return ordered
        # Names ARE configured: honor them exactly. Refuse to silently run a
        # different provider set if the configured names are unknown.
        unknown = [n for n in cfg.providers if n not in self._providers]
        if unknown:
            raise OrchestratorError(
                f"configured providers not registered: {', '.join(unknown)}"
            )
        return [self._providers[n] for n in cfg.providers]

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
            case _:  # pragma: no cover - defensive: new enum member unhandled
                raise OrchestratorError(f"unknown strategy: {strategy}")

    # --- strategies --------------------------------------------------------- #
    async def _single(
        self, providers: list[AIProvider], request: AIRequest
    ) -> AIResponse:
        provider = providers[0]
        try:
            resp = await provider.complete(request)
        except Exception as exc:  # noqa: BLE001
            return AIResponse(provider=provider.name, ok=False, error=str(exc))
        # Apply the same validity contract as fallback/ensemble so a json_mode
        # request that yields no structured payload is reported as not-ok.
        if not _is_valid(resp, request.json_mode):
            resp.ok = False
            if not resp.error:
                resp.error = "invalid response (json_mode requires structured)"
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
                # Don't mutate the provider-owned metadata dict in place.
                resp.metadata = {**resp.metadata, "strategy": "fallback"}
                return resp
            last = resp
            logger.info("Provider '%s' invalid; falling back", provider.name)
        if last is None:  # pragma: no cover - providers list is non-empty
            raise OrchestratorError("fallback produced no response")
        last.metadata = {**last.metadata, "strategy": "fallback", "exhausted": True}
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
        """Never raises for normal provider errors — converts Exception to
        ok=False so the TaskGroup doesn't cancel siblings. asyncio.CancelledError
        is a BaseException (not Exception), so genuine cancellation still
        propagates and the TaskGroup remains cancellable."""
        try:
            return await provider.complete(request)
        except Exception as exc:  # noqa: BLE001 - deliberate: see docstring
            return AIResponse(provider=provider.name, ok=False, error=str(exc))

    # --- ensemble aggregation ----------------------------------------------- #
    @staticmethod
    def _vote_key(r: AIResponse, json_mode: bool) -> str:
        """A canonical, comparison-safe key for grouping equal responses.

        The vote dimension is chosen once by json_mode (not per-response) so
        structured and content answers are never mixed in one election.
        Structured payloads are canonicalized with sort_keys so that nested
        dicts built in different insertion orders still compare equal, and a
        try/except guards payloads whose keys aren't natively orderable.
        """
        if json_mode:
            try:
                return "s:" + json.dumps(r.structured, sort_keys=True, default=str)
            except (TypeError, ValueError):
                return "s:" + repr(r.structured)
        return "c:" + r.content.strip()

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

        def vote_key(r: AIResponse) -> str:
            return self._vote_key(r, request.json_mode)

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
