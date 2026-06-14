"""Tests for the AgentRuntime and the web ControlServer (deploy step).

Exercises runtime source toggles + evaluation persistence, and smoke-tests the
HTTP control plane (dashboard, status, token auth, run-once) over a real
loopback socket.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from core.runtime import AgentRuntime
from webcontrol.server import ControlServer

_CONFIG = Path(__file__).resolve().parents[1] / "config" / "default.json"


@pytest.fixture()
def runtime(tmp_path: Path) -> Iterator[AgentRuntime]:
    rt = AgentRuntime(_CONFIG, results_path=tmp_path / "results.jsonl")
    yield rt
    rt.close()


def test_runtime_default_active_is_wazuh(runtime: AgentRuntime) -> None:
    assert runtime.sources.active_sources() == ["wazuh"]
    status = runtime.status()
    assert status["scheduler"]["techniques_per_run"] == 5
    assert status["catalog_size"] == 5


def test_runtime_enable_disable(runtime: AgentRuntime) -> None:
    res = runtime.enable_source("splunk")
    assert res["state"] == "active"
    assert "splunk" in runtime.sources.active_sources()
    runtime.disable_source("splunk")
    assert "splunk" not in runtime.sources.active_sources()


def test_runtime_unknown_source_rejected(runtime: AgentRuntime) -> None:
    with pytest.raises(KeyError):
        runtime.enable_source("nope")


def test_runtime_run_once_persists(runtime: AgentRuntime) -> None:
    out = runtime.run_once()
    assert len(out["selected"]) == 5
    assert out["active_sources"] == ["wazuh"]
    recent = runtime.recent_results()
    assert len(recent) == 5
    assert runtime.results_path.exists()


def test_runtime_set_techniques_per_run(runtime: AgentRuntime) -> None:
    assert runtime.set_techniques_per_run(3) == 3
    assert runtime.run_once()["selected"].__len__() == 3
    with pytest.raises(Exception):
        runtime.set_techniques_per_run(0)


# --------------------------------------------------------------------------- #
# HTTP control plane
# --------------------------------------------------------------------------- #
@pytest.fixture()
def server(tmp_path: Path) -> Iterator[ControlServer]:
    rt = AgentRuntime(_CONFIG, results_path=tmp_path / "r.jsonl")
    srv = ControlServer(rt, host="127.0.0.1", port=0, token="tok-123")
    import threading

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    rt.close()


def _get(url: str, token: str | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
        return exc.code, exc.read()


def _post(url: str, token: str | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="POST", data=b"")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
        return exc.code, exc.read()


def test_http_dashboard_served(server: ControlServer) -> None:
    base = f"http://127.0.0.1:{server.bound_port}"
    code, body = _get(f"{base}/")
    assert code == 200
    assert b"Control Panel" in body


def test_http_status_requires_token(server: ControlServer) -> None:
    base = f"http://127.0.0.1:{server.bound_port}"
    # Unauthenticated status is rejected (it would leak paths/providers/state).
    code_noauth, _ = _get(f"{base}/api/status")
    assert code_noauth == 401
    code, body = _get(f"{base}/api/status", token="tok-123")
    assert code == 200
    data = json.loads(body)
    assert data["scheduler"]["techniques_per_run"] == 5


def test_http_post_requires_token(server: ControlServer) -> None:
    base = f"http://127.0.0.1:{server.bound_port}"
    code, _ = _post(f"{base}/api/run")  # no token
    assert code == 401
    code2, body = _post(f"{base}/api/run", token="tok-123")
    assert code2 == 200
    assert len(json.loads(body)["selected"]) == 5


def test_http_enable_source_via_api(server: ControlServer) -> None:
    base = f"http://127.0.0.1:{server.bound_port}"
    code, body = _post(f"{base}/api/sources/splunk/enable", token="tok-123")
    assert code == 200
    assert json.loads(body)["state"] == "active"


def test_control_url_contains_token(server: ControlServer) -> None:
    url = server.control_url("localhost")
    assert url.startswith("http://localhost:")
    assert "token=tok-123" in url
