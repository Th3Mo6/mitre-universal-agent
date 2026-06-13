# Universal MITRE AI Agent

An autonomous detection-engineering assistant that continuously evaluates your
security telemetry against the [MITRE ATT&CK](https://attack.mitre.org/)
framework, identifies detection gaps, and produces source-native detection
content (Wazuh, ManageEngine, Splunk).

> **Status:** v1 — core engine, plugins, scheduler, and multi-AI orchestrator
> implemented and tested. See [`docs/Architecture.md`](docs/Architecture.md) for
> the full design.

---

## Features

- **Universal source support** — pluggable connectors for **Wazuh**,
  **ManageEngine**, and **Splunk**, enabled/disabled at runtime with no restart.
- **MITRE-driven coverage analysis** — maps telemetry + existing rules to ATT&CK
  techniques and surfaces gaps.
- **Multi-AI orchestrator** — `single`, `fallback`, and `ensemble` strategies
  (ensemble fans out concurrently via `asyncio.TaskGroup`).
- **Paced scheduler** — evaluates a configurable number of techniques per run
  (default **5**) and per hour, contacting **only enabled sources**.
- **Mock-friendly** — every plugin falls back to bundled mock data when no real
  API/credentials are present, so the full pipeline runs in CI/sandbox.

---

## Requirements

- **Python 3.12 or higher** (required minimum).
- **[Poetry](https://python-poetry.org/) 2.x** for dependency management/builds.

Verify your interpreter:

```bash
python --version          # must report 3.12.x or higher
python -c "import sys; assert sys.version_info >= (3,12)"
```

---

## Installation

### Option A — from source with Poetry (recommended)

```bash
# 1. Clone / unzip the project, then enter it
cd mitre-universal-agent

# 2. Bind Poetry to a Python 3.12+ interpreter
poetry env use python3.12        # or the full path to a 3.12 interpreter

# 3. Install runtime + dev dependencies
poetry install --with dev

# 4. Confirm the environment
poetry env info
```

### Option B — from the built wheel

After building (see [Building](#building)):

```bash
pip install dist/mitre_universal_agent-0.1.0-py3-none-any.whl
```

### Windows (PowerShell) notes

The Microsoft Store `python` alias is not a real interpreter. Install Python
3.12 first, e.g.:

```powershell
winget install --id Python.Python.3.12 -e
# then use the full interpreter path for poetry env use, e.g.
poetry env use "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
```

---

## Deploy on Ubuntu (one command)

The agent has **no third-party runtime dependencies** (Python stdlib only), so
deployment is simple. From the project directory on your Ubuntu host:

```bash
sudo ./deploy/install.sh
```

The installer will:

1. Install **Python 3.12** (via deadsnakes PPA if needed) + `python3.12-venv`.
2. Create a dedicated `mitre` system user and copy the app to `/opt/mitre-agent`.
3. Create a virtualenv and write `/etc/mitre-agent/agent.env` (with a generated
   access **token**, host, and port).
4. Install + start a hardened **systemd** service (`mitre-agent.service`).
5. Open the port in `ufw` (if active).
6. Print your **control-panel URL with token**, e.g.:

```
================================================================
[+] mitre-agent service is RUNNING.
  Control panel (local):   http://localhost:8080/?token=XXXXXXXX
  Control panel (network): http://192.168.1.20:8080/?token=XXXXXXXX
  Access token:            XXXXXXXX
  Config file:             /opt/mitre-agent/config/default.json
  Results:                 /var/lib/mitre-agent/results.jsonl
================================================================
```

Open that URL in your browser to **enable/disable sources, set the
techniques-per-run, choose the AI strategy, run a cycle, and start/stop the
paced background loop** — all at runtime.

### Manage the service

```bash
systemctl status mitre-agent      # health
journalctl -u mitre-agent -f      # live logs
systemctl restart mitre-agent     # restart
sudo ./deploy/uninstall.sh        # remove (PURGE=1 to also delete data)
```

### Custom port / host

```bash
sudo AGENT_PORT=9000 AGENT_HOST=0.0.0.0 ./deploy/install.sh
```

> **Security:** the control panel is token-protected (bearer token or
> `?token=`). For internet-facing hosts, put it behind a reverse proxy with TLS
> and restrict the port with your firewall.

### Run the control panel manually (without systemd)

```bash
AGENT_PORT=8080 AGENT_AUTOSTART=1 poetry run python app.py
# or, after `pip install` of the wheel:
AGENT_PORT=8080 mitre-agent
```

---

## Quick start

```bash
# Run the full test-suite (uses bundled mock data; no credentials needed)
poetry run pytest -q

# Type-check
poetry run mypy core/ plugins/ ai_providers/
```

### Run a single evaluation cycle (wazuh only, mock data)

```python
from core.config_store import ConfigStore
from core.mitre_engine import MitreEngine
from core.source_manager import SourceManager
from core.scheduler import Scheduler
from plugins.wazuh import WazuhPlugin
from plugins.manageengine import ManageEnginePlugin
from plugins.splunk import SplunkPlugin

store = ConfigStore.load("config/default.json")   # wazuh enabled; ME/Splunk disabled
mitre = MitreEngine()
manager = SourceManager(store)
manager.register("wazuh", WazuhPlugin)
manager.register("manageengine", ManageEnginePlugin)
manager.register("splunk", SplunkPlugin)
manager.sync()                                     # activates only enabled sources

scheduler = Scheduler(store, mitre, manager)
report = scheduler.run_once()                      # selects exactly 5 techniques
print(report.selected, report.active_sources)
manager.close()
```

### Multi-AI orchestration (mock providers)

```python
import asyncio
from ai_providers import MockProvider, AIRequest
from core.ai_orchestrator import AIOrchestrator
from core.config_store import ConfigStore, AIStrategy

store = ConfigStore.load("config/default.json")
store.set_ai_strategy(AIStrategy.ENSEMBLE, ["a", "b", "c"])
providers = {n: MockProvider(n, content="yes") for n in ("a", "b", "c")}

orch = AIOrchestrator(providers, store)
resp = asyncio.run(orch.complete(AIRequest(prompt="Is this a gap?")))
print(resp.content, resp.confidence, resp.metadata)
```

---

## Configuration

Runtime config lives in [`config/default.json`](config/default.json):

```json
{
  "sources": {
    "wazuh":        { "enabled": true,  "config": { "endpoint": "", "verify_tls": true } },
    "manageengine": { "enabled": false, "config": { "endpoint": "", "verify_tls": true } },
    "splunk":       { "enabled": false, "config": { "endpoint": "", "verify_tls": true } }
  },
  "scheduler": { "techniques_per_hour": 5, "techniques_per_run": 5, "mode": "even", "max_concurrent": 1 },
  "ai":        { "strategy": "single", "providers": ["mock-primary"] }
}
```

| Key | Meaning |
|-----|---------|
| `sources.<name>.enabled` | Enable/disable a source at runtime (fail-closed). |
| `sources.<name>.config.endpoint` | Source API endpoint. Empty → mock fallback. |
| `scheduler.techniques_per_run` | Techniques selected per scheduler cycle (default 5). |
| `scheduler.techniques_per_hour` | Pacing budget per hour (default 5). |
| `ai.strategy` | `single` \| `fallback` \| `ensemble`. |
| `ai.providers` | Ordered provider names (fallback order / ensemble members). |

> **Secrets are never stored inline** — `config.endpoint`/auth should use
> references resolved at runtime (see Architecture §8.1).

---

## Project layout

```
mitre-universal-agent/
├── ai_providers/        # AI provider interface + mock provider
│   ├── base.py
│   └── mock.py
├── core/                # config store, MITRE engine, source manager,
│   ├── ai_orchestrator.py    #   scheduler, multi-AI orchestrator
│   ├── config_store.py
│   ├── mitre_engine.py
│   ├── scheduler.py
│   └── source_manager.py
├── plugins/             # source connectors (implement plugins/base.py)
│   ├── base.py          #   LogSourcePlugin Protocol + data types
│   ├── wazuh/plugin.py
│   ├── manageengine/plugin.py
│   └── splunk/plugin.py
├── config/default.json  # runtime configuration
├── docs/Architecture.md # full system design
└── tests/               # pytest suite + mock data under tests/mocks/
```

---

## Building

```bash
poetry build
# produces dist/mitre_universal_agent-0.1.0-py3-none-any.whl
#      and dist/mitre_universal_agent-0.1.0.tar.gz
```

---

## Testing

```bash
poetry run pytest -q            # all tests
poetry run pytest tests/test_integration.py -v --log-cli-level=INFO
```

All tests run against **bundled mock data** — no real Wazuh/ManageEngine/Splunk
or AI credentials are required.

---

## Security

This tool is **read-only** against your sources and **never deploys** generated
rules — all output is statically validated and requires human review before
deployment. See [`docs/Architecture.md`](docs/Architecture.md) 8 for the full
security model.

---

## License

Author: **@Th3Mo6** &lt;atom@xcorner.xyz&gt;. License: TBD.
