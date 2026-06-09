"""Entrypoint for the Universal MITRE AI Agent control plane.

Starts the web control panel bound to the configured host/port and prints the
control URL (including the access token). Run directly or via the
``mitre-agent`` console script.

Environment variables:
  AGENT_CONFIG    path to config JSON (default: config/default.json)
  AGENT_HOST      bind host (default: 0.0.0.0)
  AGENT_PORT      bind port (default: 8080)
  AGENT_TOKEN     fixed access token (default: auto-generated)
  AGENT_AUTOSTART "1" to start the paced scheduling loop on launch
  AGENT_RESULTS   path to the results.jsonl file (default: next to config)
"""

from __future__ import annotations

import logging
import os
import socket
from pathlib import Path

from webcontrol.server import serve

_ROOT = Path(__file__).resolve().parent


def _lan_ip() -> str:
    """Best-effort primary LAN IP for a friendlier control URL."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return str(s.getsockname()[0])
    except OSError:
        return "localhost"
    finally:
        s.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = os.environ.get("AGENT_CONFIG", str(_ROOT / "config" / "default.json"))
    host = os.environ.get("AGENT_HOST", "0.0.0.0")
    port = int(os.environ.get("AGENT_PORT", "8080"))
    token = os.environ.get("AGENT_TOKEN") or None
    autostart = os.environ.get("AGENT_AUTOSTART", "0") == "1"
    results = os.environ.get("AGENT_RESULTS") or None

    server = serve(
        config,
        host=host,
        port=port,
        token=token,
        autostart_loop=autostart,
        results_path=results,
    )

    url_local = server.control_url("localhost")
    url_lan = server.control_url(_lan_ip())
    bar = "=" * 64
    print(f"\n{bar}")
    print("  Universal MITRE AI Agent — control panel is RUNNING")
    print(bar)
    print(f"  Local:   {url_local}")
    print(f"  Network: {url_lan}")
    print(f"  Token:   {server.token}")
    print(f"  Config:  {config}")
    print(f"  Loop:    {'started' if autostart else 'stopped (start from UI)'}")
    print(f"{bar}\n  Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.runtime.close()
        server.shutdown()


if __name__ == "__main__":
    main()
