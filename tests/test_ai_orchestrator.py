"""Tests for the multi-AI orchestrator (Step 7).

Covers single / fallback / ensemble. The headline case fans out to 3 mock
providers via asyncio.TaskGroup and checks majority-vote aggregation.
"""

from __future__ import annotations

import pytest

from ai_providers import AIProvider, AIRequest, MockProvider
from core.ai_orchestrator import AIOrchestrator
from core.config_store import AIStrategy, AppConfig, ConfigStore


def _store(strategy: AIStrategy, providers: list[str]) -> ConfigStore:
    s = ConfigStore(AppConfig())
    s.set_ai_strategy(strategy, providers)
    return s


def test_mock_provider_satisfies_protocol() -> None:
    assert isinstance(MockProvider("a"), AIProvider)


@pytest.mark.asyncio
async def test_single_strategy() -> None:
    providers: dict[str, AIProvider] = {
        "a": MockProvider("a", content="A"),
        "b": MockProvider("b", content="B"),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.SINGLE, ["a", "b"]))
    resp = await orch.complete(AIRequest(prompt="hi"))
    assert resp.ok
    assert resp.content == "A"  # only the first provider is used
    assert providers["b"].call_count == 0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_fallback_skips_failing_provider() -> None:
    p_fail = MockProvider("primary", fail=True)
    p_ok = MockProvider("secondary", content="rescued")
    providers: dict[str, AIProvider] = {"primary": p_fail, "secondary": p_ok}
    orch = AIOrchestrator(providers, _store(AIStrategy.FALLBACK, ["primary", "secondary"]))
    resp = await orch.complete(AIRequest(prompt="hi"))
    assert resp.ok
    assert resp.provider == "secondary"
    assert resp.content == "rescued"
    assert resp.metadata["strategy"] == "fallback"
    assert p_fail.call_count == 1
    assert p_ok.call_count == 1


@pytest.mark.asyncio
async def test_fallback_handles_raising_provider() -> None:
    providers: dict[str, AIProvider] = {
        "crash": MockProvider("crash", raises=True),
        "ok": MockProvider("ok", content="ok"),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.FALLBACK, ["crash", "ok"]))
    resp = await orch.complete(AIRequest(prompt="hi"))
    assert resp.ok
    assert resp.provider == "ok"


@pytest.mark.asyncio
async def test_ensemble_three_providers_majority() -> None:
    # Two agree on "yes", one says "no" -> majority "yes", confidence 2/3.
    providers: dict[str, AIProvider] = {
        "a": MockProvider("a", content="yes"),
        "b": MockProvider("b", content="yes"),
        "c": MockProvider("c", content="no"),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.ENSEMBLE, ["a", "b", "c"]))
    resp = await orch.complete(AIRequest(prompt="verdict?"))

    assert resp.ok
    assert resp.provider == "ensemble"
    assert resp.content == "yes"
    assert resp.metadata["agreed"] == 2
    assert resp.metadata["total"] == 3
    assert resp.confidence == pytest.approx(2 / 3)
    # All three providers were actually invoked (parallel fan-out).
    for p in providers.values():
        assert p.call_count == 1  # type: ignore[attr-defined]
    assert set(resp.metadata["providers"]) == {"a", "b", "c"}


@pytest.mark.asyncio
async def test_ensemble_unanimous_full_confidence() -> None:
    providers: dict[str, AIProvider] = {
        n: MockProvider(n, content="same") for n in ("a", "b", "c")
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.ENSEMBLE, ["a", "b", "c"]))
    resp = await orch.complete(AIRequest(prompt="q"))
    assert resp.confidence == pytest.approx(1.0)
    assert resp.metadata["agreed"] == 3


@pytest.mark.asyncio
async def test_ensemble_all_fail_returns_not_ok() -> None:
    providers: dict[str, AIProvider] = {
        "a": MockProvider("a", fail=True),
        "b": MockProvider("b", raises=True),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.ENSEMBLE, ["a", "b"]))
    resp = await orch.complete(AIRequest(prompt="q"))
    assert not resp.ok
    assert resp.confidence == 0.0


@pytest.mark.asyncio
async def test_ensemble_survives_one_crash() -> None:
    # TaskGroup must not cancel siblings when one provider raises.
    providers: dict[str, AIProvider] = {
        "good1": MockProvider("good1", content="x"),
        "boom": MockProvider("boom", raises=True),
        "good2": MockProvider("good2", content="x"),
    }
    orch = AIOrchestrator(providers, _store(AIStrategy.ENSEMBLE, ["good1", "boom", "good2"]))
    resp = await orch.complete(AIRequest(prompt="q"))
    assert resp.ok
    assert resp.content == "x"
    assert resp.metadata["agreed"] == 2  # the two good ones agreed
