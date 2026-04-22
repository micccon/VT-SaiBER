"""
Fuzzer Agent - Web surface discovery worker.
=============================================

Responsibilities
----------------
1. Pick the best HTTP/HTTPS target from discovered_targets.
2. Validate the URL and all tool arguments before execution.
3. Run **ffuf** (primary) then **gobuster** (fallback) then **nikto** (enrichment).
4. Apply rate limiting, per-request timeouts, and soft-404 filtering.
5. Return a deduplicated, normalised list of ``web_findings`` to the shared state.

Soft-404 strategy
-----------------
Many web frameworks return HTTP 200 for every path with a custom error page.
We detect them in three ways:
  a) Static status exclusion  — 404 and 400 are always excluded.
  b) Baseline-size filter     — a random-word probe is sent before fuzzing;
                                any result whose body size matches the baseline
                                is discarded as a soft-404.
  c) Depth limit              — paths deeper than MAX_RECURSION_DEPTH are dropped
                                as low-signal noise.

Rate limiting
-------------
``REQUEST_THROTTLE_MS`` controls the inter-request delay passed to ffuf (-p)
and gobuster (--delay). Set to 0 to disable throttling.

Timeout handling
----------------
Each MCP tool call is wrapped in asyncio.wait_for with TOOL_TIMEOUT_SECONDS.
On timeout the agent logs a warning and falls back to the next tool or to the
static fallback finding so the mission can continue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.utils.parsers import (
    extract_text_payload,
    parse_ffuf_output,
    parse_gobuster_output,
    parse_nikto_output,
)
from src.utils.validators import (
    is_valid_target_url,
    is_safe_wordlist_path,
    is_safe_additional_args,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Tools the Fuzzer is allowed to call through the MCP bridge.
FUZZER_ALLOWED_TOOLS = {"ffuf_scan", "gobuster_scan", "nikto_scan"}

# HTTP tools: primary fuzzer, fallback, enrichment.
TOOL_PRIORITY = ["ffuf_scan", "gobuster_scan", "nikto_scan"]

# Maximum path-segment depth to include in results.
# Paths like /a/b/c/d/e are usually noise at this stage.
MAX_RECURSION_DEPTH = 3

# Maximum number of directories to recurse into during phase 2.
MAX_RECURSIVE_DIRS = 5

# Milliseconds to wait between HTTP requests (throttling).
# Passed as seconds to ffuf (-p) and as --delay to gobuster.
# Set to 0 to disable throttling.
REQUEST_THROTTLE_MS = 200

# Seconds to wait for a single MCP tool call before giving up.
TOOL_TIMEOUT_SECONDS = 120

# HTTP status codes always excluded regardless of tool.
SOFT_404_STATUSES: frozenset = frozenset({404, 400})

# HTTP threads for ffuf. Keep low to avoid overloading the testbed.
FFUF_THREADS = 10

# HTTP status codes that ffuf should report (match-codes flag).
FFUF_MATCH_CODES = "200,204,301,302,307,401,403"

# Tiered wordlists in the Kali container.
# Phase 1 (initial sweep): small/fast list — covers 95% of common paths.
# Phase 2 (recursive):     medium list — only on interesting directories.
# Phase 3 (deep):          large list — only used if explicitly escalated.
WORDLIST_SMALL  = "/usr/share/wordlists/dirb/common.txt"          # ~4.6k words
WORDLIST_MEDIUM = "/usr/share/wordlists/dirb/big.txt"             # ~20k words
WORDLIST_LARGE  = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"  # ~220k words

# Default wordlist for phase 1.
DEFAULT_WORDLIST = WORDLIST_SMALL


class FuzzerAgent(BaseAgent):
    """
    Web surface discovery agent.

    Orchestrates ffuf → gobuster → nikto in priority order,
    merges their findings, applies soft-404 filtering, and
    writes normalised ``web_findings`` to the shared state.
    """

    def __init__(self) -> None:
        super().__init__("fuzzer", "Web Fuzzing Specialist")

    @property
    def system_prompt(self) -> str:
        return (
            "Web enumeration worker. Discover hidden paths, API endpoints, "
            "and admin interfaces using ffuf and gobuster. Apply soft-404 "
            "filtering and rate limiting to avoid false positives and target "
            "disruption."
        )

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Main orchestration loop.

        Steps
        -----
        1. Identify the best HTTP target from discovered_targets.
        2. Validate URL against scope.
        3. Run soft-404 baseline probe.
        4. Run ffuf (primary fuzzer).
        5. Run gobuster (fallback if ffuf found nothing).
        6. Run nikto (enrichment — always attempted).
        7. Merge, deduplicate, and cap results.
        8. Return state update.
        """
        target_scope = state.get("target_scope", []) or []
        discovered = state.get("discovered_targets", {}) or {}

        # Step 1 – pick target
        web_target = self._pick_web_target(discovered)
        if web_target is None:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No HTTP/HTTPS service found in discovered_targets",
            )

        ip = web_target["ip"]
        port = web_target["port"]
        scheme = "https" if port == 443 else "http"
        base_url = (
            f"{scheme}://{ip}:{port}" if port not in {80, 443} else f"{scheme}://{ip}"
        )

        # Step 2 – validate URL against scope
        if not is_valid_target_url(base_url, target_scope):
            return self.log_error(
                state,
                error_type="ScopeViolation",
                error=f"Fuzzer target URL {base_url!r} is outside authorised scope",
            )

        logger.info("Fuzzer targeting %s", base_url)

        # Step 3 – get MCP bridge (best effort)
        bridge = await self._get_bridge()

        # Step 4 – baseline soft-404 probe
        soft_404_size: Optional[int] = None
        if bridge is not None:
            soft_404_size = await self._probe_soft_404_baseline(bridge, base_url)
            if soft_404_size is not None:
                logger.info("Soft-404 baseline size detected: %d bytes", soft_404_size)

        # Step 5/6/7 – run tools
        findings = await self._enumerate_paths(
            bridge=bridge,
            base_url=base_url,
            soft_404_size=soft_404_size,
        )

        # Fallback if everything failed / no results
        if not findings:
            findings = self._fallback_finding(base_url)

        return {
            "current_agent": "fuzzer",
            "web_findings": findings,
            **self.log_action(
                state,
                action="web_enumeration",
                target=base_url,
                findings={
                    "findings_count": len(findings),
                    "max_depth": MAX_RECURSION_DEPTH,
                    "request_throttle_ms": REQUEST_THROTTLE_MS,
                    "soft_404_baseline_size": soft_404_size,
                    "soft_404_statuses": sorted(SOFT_404_STATUSES),
                    "tool_priority": TOOL_PRIORITY,
                },
                reasoning=(
                    "Fuzzer completed constrained GET/HEAD path discovery "
                    "with soft-404 filtering and rate limiting."
                ),
            ),
        }

    # -----------------------------------------------------------------------
    # Target selection
    # -----------------------------------------------------------------------

    def _pick_web_target(
        self, discovered_targets: Dict[str, Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Select the best HTTP(S) target from the scout's discovered_targets.

        Preference order: HTTP on 80 → HTTP on 8000 → any HTTP → HTTPS.

        Args:
            discovered_targets: Dict of IP/hostname → target data from Scout.

        Returns:
            Dict with keys ``ip``, ``port``, ``service_name``, or ``None``.
        """
        http_candidates: List[Dict[str, Any]] = []

        for ip, target_data in discovered_targets.items():
            if not isinstance(target_data, dict):
                continue
            services = target_data.get("services", {}) or {}
            ports = target_data.get("ports", []) or []

            for port in ports:
                svc_data = services.get(str(port)) or services.get(port)
                if isinstance(svc_data, dict):
                    name = str(svc_data.get("service_name", "")).lower()
                else:
                    name = str(svc_data or "").lower()

                if name in {"http", "https", "http-proxy", "http-alt"}:
                    http_candidates.append({"ip": ip, "port": int(port), "service_name": name})

        if not http_candidates:
            return None

        # Sort: prefer well-known ports first.
        preferred = [80, 8000, 8080, 8443, 443]
        http_candidates.sort(
            key=lambda c: preferred.index(c["port"]) if c["port"] in preferred else 999
        )
        return http_candidates[0]

    # -----------------------------------------------------------------------
    # Soft-404 baseline probe
    # -----------------------------------------------------------------------

    async def _probe_soft_404_baseline(
        self, bridge: Any, base_url: str
    ) -> Optional[int]:
        """
        Probe the target with a nonsense path to measure the soft-404 body size.

        A server that returns HTTP 200 for unknown paths (soft-404) will return
        a response of consistent size regardless of the path. By probing once
        with a random/unlikely word, we learn that size and can filter it out
        from ffuf results using ``-fs <size>``.

        Args:
            bridge: Connected MCPToolBridge instance.
            base_url: Target base URL.

        Returns:
            Response body size in bytes if the probe returned 200, else None.
        """
        tools = bridge.get_tools_for_agent({"ffuf_scan"})
        ffuf_tool = next((t for t in tools if t.name.endswith("ffuf_scan")), None)
        if ffuf_tool is None:
            return None

        probe_word = "vtsaiber_baseline_probe_xyzqq"
        probe_url = f"{base_url.rstrip('/')}/{probe_word}"

        try:
            raw = await asyncio.wait_for(
                ffuf_tool.coroutine(
                    url=probe_url,
                    wordlist=DEFAULT_WORDLIST,
                    match_codes="200",
                    rate_limit_delay="0",
                    threads=1,
                    timeout=10,
                    additional_args="",
                ),
                timeout=20,
            )
            # Parse the ffuf JSON output for the probe result size
            payload = _try_parse_ffuf_json(raw)
            results = payload.get("results", [])
            if results and isinstance(results[0], dict):
                return results[0].get("length")
        except Exception as exc:
            logger.debug("Soft-404 baseline probe failed: %s", exc)

        return None

    # -----------------------------------------------------------------------
    # Tool orchestration
    # -----------------------------------------------------------------------

    async def _get_bridge(self) -> Optional[Any]:
        """Return MCP bridge or None on failure (best effort)."""
        try:
            return await get_mcp_bridge()
        except Exception as exc:
            logger.warning("MCP bridge unavailable: %s", exc)
            return None

    async def _enumerate_paths(
        self,
        bridge: Optional[Any],
        base_url: str,
        soft_404_size: Optional[int],
    ) -> List[Dict[str, Any]]:

        """
        Multi-phase web path enumeration.

        Phase 1 — Initial sweep
        -----------------------
        Runs ffuf with the small ``common.txt`` wordlist against the base URL.
        Fast, covers 95%+ of common paths within seconds.

        Phase 2 — Recursive directory discovery
        ----------------------------------------
        Picks up to ``MAX_RECURSIVE_DIRS`` directories from Phase 1 that
        returned 301/302 (redirects) or 200 and are flagged as interesting.
        Runs a second ffuf pass with ``dirb/big.txt`` (medium list) inside
        each of those directories to discover nested paths.

        Phase 3 — gobuster fallback
        ----------------------------
        Only runs if Phase 1 found fewer than 5 results.  Uses gobuster
        with the same small wordlist.

        Phase 4 — nikto enrichment
        ---------------------------
        Always runs regardless of other phases.  Nikto checks for known
        vulnerabilities, misconfigured headers, and exploit-ready paths.

        Rate limiting
        -------------
        ``REQUEST_THROTTLE_MS`` → ``-p {seconds}`` for ffuf,
        ``--delay {ms}ms`` for gobuster.

        Timeouts
        --------
        Each call is wrapped in ``asyncio.wait_for(TOOL_TIMEOUT_SECONDS)``.
        """
        all_findings: List[Dict[str, Any]] = []

        if bridge is None:
            logger.warning("Fuzzer: bridge is None — skipping all tool calls")
            return all_findings

        tools = bridge.get_tools_for_agent(FUZZER_ALLOWED_TOOLS)
        tool_map = {t.name.split("_", 1)[-1]: t for t in tools}

        delay_seconds = str(REQUEST_THROTTLE_MS / 1000) if REQUEST_THROTTLE_MS else "0"
        delay_ms_str = f"{REQUEST_THROTTLE_MS}ms" if REQUEST_THROTTLE_MS else ""

        # ── Phase 1: Initial ffuf sweep (small wordlist) ────────────────────
        ffuf_tool = tool_map.get("ffuf_scan")
        phase1_findings: List[Dict[str, Any]] = []
        if ffuf_tool:
            additional = ""
            if soft_404_size is not None:
                additional = f"-fs {soft_404_size}"
            if not is_safe_additional_args(additional):
                additional = ""

            logger.info("Fuzzer Phase 1: ffuf sweep on %s (wordlist: small)", base_url)
            try:
                raw = await asyncio.wait_for(
                    ffuf_tool.coroutine(
                        url=base_url,
                        wordlist=DEFAULT_WORDLIST,
                        match_codes=FFUF_MATCH_CODES,
                        rate_limit_delay=delay_seconds,
                        threads=FFUF_THREADS,
                        timeout=10,
                        additional_args=additional,
                    ),
                    timeout=TOOL_TIMEOUT_SECONDS,
                )
                phase1_findings = parse_ffuf_output(
                    raw_output=raw,
                    base_url=base_url,
                    max_depth=MAX_RECURSION_DEPTH,
                    soft_404_statuses=set(SOFT_404_STATUSES),
                    soft_404_size=soft_404_size,
                )
                all_findings.extend(phase1_findings)
                logger.info(
                    "Fuzzer Phase 1 complete: %d result(s) on %s",
                    len(phase1_findings),
                    base_url,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Fuzzer Phase 1: ffuf timed out after %ds on %s",
                    TOOL_TIMEOUT_SECONDS,
                    base_url,
                )
            except Exception as exc:
                logger.warning("Fuzzer Phase 1: ffuf failed on %s: %s", base_url, exc)

        # ── Phase 2: Recursive directory discovery (medium wordlist) ────────
        if ffuf_tool and phase1_findings:
            # Collect interesting directories to recurse into.
            recurse_dirs = [
                f["path"].rstrip("/")
                for f in phase1_findings
                if f.get("status_code") in {200, 301, 302, 307}
                and f.get("is_interesting")
                and "/" in f["path"].rstrip("/")  # only real directories
            ][:MAX_RECURSIVE_DIRS]

            # Also add top-level dirs that returned 301/302
            for f in phase1_findings:
                path = f["path"].rstrip("/")
                if f.get("status_code") in {301, 302} and path not in recurse_dirs:
                    recurse_dirs.append(path)
                if len(recurse_dirs) >= MAX_RECURSIVE_DIRS:
                    break

            if recurse_dirs:
                logger.info(
                    "Fuzzer Phase 2: recursive scan on %d dir(s): %s",
                    len(recurse_dirs),
                    recurse_dirs,
                )

            for dir_path in recurse_dirs:
                dir_url = f"{base_url.rstrip('/')}{dir_path}/"
                logger.debug("Fuzzer Phase 2: scanning %s with medium wordlist", dir_url)
                try:
                    raw = await asyncio.wait_for(
                        ffuf_tool.coroutine(
                            url=dir_url,
                            wordlist=WORDLIST_MEDIUM,
                            match_codes=FFUF_MATCH_CODES,
                            rate_limit_delay=delay_seconds,
                            threads=FFUF_THREADS,
                            timeout=10,
                            additional_args=additional if is_safe_additional_args(additional) else "",
                        ),
                        timeout=TOOL_TIMEOUT_SECONDS,
                    )
                    recursive_findings = parse_ffuf_output(
                        raw_output=raw,
                        base_url=base_url,
                        max_depth=MAX_RECURSION_DEPTH + 1,  # allow one extra level
                        soft_404_statuses=set(SOFT_404_STATUSES),
                        soft_404_size=soft_404_size,
                    )
                    all_findings.extend(recursive_findings)
                    logger.info(
                        "Fuzzer Phase 2: %d result(s) found under %s",
                        len(recursive_findings),
                        dir_url,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Fuzzer Phase 2: ffuf timed out on recursive dir %s", dir_url
                    )
                except Exception as exc:
                    logger.warning("Fuzzer Phase 2: ffuf failed on %s: %s", dir_url, exc)

        # ── Phase 3: gobuster fallback (if Phase 1 was sparse) ─────────────
        gobuster_tool = tool_map.get("gobuster_scan")
        if gobuster_tool and len(all_findings) < 5:
            gobuster_args = f"--delay {delay_ms_str}" if delay_ms_str else ""
            if not is_safe_additional_args(gobuster_args):
                gobuster_args = ""

            logger.info(
                "Fuzzer Phase 3: gobuster fallback on %s (Phase 1 had %d results)",
                base_url,
                len(all_findings),
            )
            try:
                raw = await asyncio.wait_for(
                    gobuster_tool.coroutine(
                        url=base_url,
                        mode="dir",
                        wordlist=DEFAULT_WORDLIST,
                        additional_args=gobuster_args,
                    ),
                    timeout=TOOL_TIMEOUT_SECONDS,
                )
                gob_findings = parse_gobuster_output(
                    raw_output=raw,
                    base_url=base_url,
                    max_depth=MAX_RECURSION_DEPTH,
                    soft_404_statuses=set(SOFT_404_STATUSES),
                )
                all_findings.extend(gob_findings)
                logger.info(
                    "Fuzzer Phase 3: gobuster found %d result(s) on %s",
                    len(gob_findings),
                    base_url,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Fuzzer Phase 3: gobuster timed out after %ds on %s",
                    TOOL_TIMEOUT_SECONDS,
                    base_url,
                )
            except Exception as exc:
                logger.warning("Fuzzer Phase 3: gobuster failed on %s: %s", base_url, exc)

        # ── Phase 4: nikto enrichment (always) ─────────────────────────────
        nikto_tool = tool_map.get("nikto_scan")
        if nikto_tool:
            logger.info("Fuzzer Phase 4: nikto enrichment on %s", base_url)
            try:
                raw = await asyncio.wait_for(
                    nikto_tool.coroutine(
                        target=base_url,
                        additional_args="",
                    ),
                    timeout=TOOL_TIMEOUT_SECONDS,
                )
                nikto_findings = parse_nikto_output(
                    raw_output=raw,
                    base_url=base_url,
                    max_depth=MAX_RECURSION_DEPTH,
                )
                all_findings.extend(nikto_findings)
                logger.info(
                    "Fuzzer Phase 4: nikto found %d result(s) on %s",
                    len(nikto_findings),
                    base_url,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Fuzzer Phase 4: nikto timed out after %ds on %s",
                    TOOL_TIMEOUT_SECONDS,
                    base_url,
                )
            except Exception as exc:
                logger.warning("Fuzzer Phase 4: nikto failed on %s: %s", base_url, exc)

        deduped = _deduplicate_findings(all_findings)[:200]
        logger.info(
            "Fuzzer enumeration complete: %d unique finding(s) on %s",
            len(deduped),
            base_url,
        )
        return deduped



    # -----------------------------------------------------------------------
    # Fallback
    # -----------------------------------------------------------------------

    def _fallback_finding(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Produce a single placeholder finding when all tools fail or are
        unavailable. Allows the mission to continue with minimal state.
        """
        return [
            {
                "url": f"{base_url}/",
                "path": "/",
                "status_code": 200,
                "content_length": None,
                "content_type": "unknown",
                "is_api_endpoint": False,
                "is_interesting": False,
                "discovery_depth": 0,
                "rationale": "MCP tools unavailable — fallback placeholder",
            }
        ]

    # -----------------------------------------------------------------------
    # Scan policy (for log / reporting)
    # -----------------------------------------------------------------------

    def _scan_policy(self) -> Dict[str, Any]:
        """Return the active scan policy for inclusion in log entries."""
        return {
            "methods": ["GET", "HEAD"],
            "max_depth": MAX_RECURSION_DEPTH,
            "request_throttle_ms": REQUEST_THROTTLE_MS,
            "tool_timeout_seconds": TOOL_TIMEOUT_SECONDS,
            "soft_404_statuses": sorted(SOFT_404_STATUSES),
            "ffuf_threads": FFUF_THREADS,
            "ffuf_match_codes": FFUF_MATCH_CODES,
            "wordlist": DEFAULT_WORDLIST,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings by (path, status_code) key."""
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for f in findings:
        key = (f.get("path"), f.get("status_code"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _try_parse_ffuf_json(raw: Any) -> Dict[str, Any]:
    """
    Best-effort extraction of ffuf JSON output from a raw MCP result.

    Returns an empty dict if parsing fails entirely.
    """
    text = extract_text_payload(raw)
    start = (text or "").find("{")
    if start >= 0:
        try:
            return json.loads(text[start:])
        except Exception:
            pass
    return {}


# ---------------------------------------------------------------------------
# LangGraph node wrapper
# ---------------------------------------------------------------------------

async def fuzzer_node(state: CyberState) -> Dict[str, Any]:
    """
    LangGraph node wrapper for the FuzzerAgent.

    Called by the graph runner after the Supervisor routes to ``"fuzzer"``.
    Returns a partial state update merged into the global CyberState.
    """
    agent = FuzzerAgent()
    return await agent.call_llm(state)
