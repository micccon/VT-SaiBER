"""Context building for Scout."""

from __future__ import annotations

from src.state.cyber_state import CyberState
from src.agents.scout.constants import MAX_SCOUT_TARGETS


def build_scout_context(state: CyberState) -> str:
    """Build a compact recon objective for the model."""

    discovered_targets = list((state.get("discovered_targets", {}) or {}).keys())
    target_scope = state.get("target_scope", []) or []
    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
        f"TARGET SCOPE: {target_scope}\n"
        f"ALREADY KNOWN TARGETS: {discovered_targets[:MAX_SCOUT_TARGETS] or '(none)'}\n\n"
        "Discover live in-scope hosts and enumerate their exposed services with versions. "
        "For concrete hosts, prefer recon_service_probe and omit ports to use Nmap's top 1000 ports."
    )
