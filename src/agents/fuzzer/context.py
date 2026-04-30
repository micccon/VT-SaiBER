"""Context building for Fuzzer."""

from __future__ import annotations

from typing import Optional

from src.state.cyber_state import CyberState
from src.core.agent_parsers import iter_target_services


def pick_web_target(discovered_targets: dict[str, dict[str, object]]) -> Optional[dict[str, object]]:
    """Choose the first discovered HTTP(S)-like target to enumerate."""

    for ip, port, name in iter_target_services(discovered_targets):
        if name in {"http", "https", "http-proxy"}:
            return {"ip": ip, "port": int(port), "service_name": name}
    return None


def build_target_url(target: dict[str, object]) -> str:
    """Build the target base URL from the selected service."""

    ip = str(target["ip"])
    port = int(target["port"])
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{ip}:{port}" if port not in {80, 443} else f"{scheme}://{ip}"


def build_fuzzer_context(state: CyberState, base_url: str) -> str:
    """Build the per-target fuzzing context passed to the model."""

    existing = state.get("web_findings", []) or []
    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
        f"TARGET URL: {base_url}\n"
        f"EXISTING WEB FINDINGS: {len(existing)}\n\n"
        "Enumerate high-value paths, endpoints, and weak web surface indicators for this target."
    )

