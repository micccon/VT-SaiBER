"""
Scout Agent - Network reconnaissance worker.
============================================

Features
--------
- **Performance**          : ``-sn -T4`` ping sweep + ``-sV -T4 --version-intensity 5``
- **Subnet pivoting**      : After host discovery, derives new /24 subnets from
                             discovered IPs and scans them if still in scope.
- **Banner grabbing**      : Runs ``--script banner,http-title,ssh-hostkey`` after
                             the service scan and populates ``ServiceInfo.banner``.
- **Advanced fingerprinting**: Uses NSE scripts tuned per detected service family
                               (HTTP → ``http-headers,http-title``; SSH → ``ssh-auth-methods``;
                               MySQL/MSSQL → ``mysql-info,ms-sql-info``).
- **OS detection**         : Optional ``-O`` pass; result stored in ``os_guess`` and
                             used to optimise follow-up scan strategy.
- **Scan strategy tuning** : nmap arguments adapt based on target type (hostname /
                             single IP / CIDR), and detected OS family
                             (Windows adds ``-Pn``; Cisco shortens port list).
- **Exclusion list**       : Targets matching ``scan_exclusions`` in state are
                             silently skipped and logged at WARNING.
- **Error handling**       : All MCP calls wrapped in ``asyncio.wait_for``; timeouts
                             log a warning and proceed to the next target.
- **Structured logging**   : Full ``logging`` throughout; set log level to DEBUG for
                             per-line nmap trace output.
"""

from __future__ import annotations

import asyncio
import logging
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Tuple

from src.agents.base import BaseAgent
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.state.models import DiscoveredTarget, ServiceInfo
from src.utils.parsers import (
    parse_nmap_hosts,
    parse_nmap_os_detection,
    parse_nmap_script_banners,
    parse_nmap_services,
)
from src.utils.validators import is_excluded_target, normalise_exclusion_list, target_in_scope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

SCOUT_ALLOWED_TOOLS = {"nmap_scan"}

# Maximum hosts we will scan in a single Scout run.
MAX_SCOUT_TARGETS = 5

# Maximum new pivot subnets to sweep per run.
MAX_PIVOT_SUBNETS = 3

# How long (seconds) to wait for a single nmap MCP call.
NMAP_TIMEOUT_SECONDS = 90

# Default ports scanned during service fingerprinting.
SERVICE_SCAN_PORTS = "1-1024,8000,8080,8443,3000,5000,9090"

# Shorter port list for known Cisco/edge devices (avoid false positives).
CISCO_SCAN_PORTS = "22,23,80,443,830"

# Windows-specific ports added when OS is detected as Windows.
WINDOWS_EXTRA_PORTS = "135,139,445,3389,5985,5986"

# nmap timing template.
NMAP_TIMING = "-T4"

# nmap version intensity: 0 (lightest) → 9 (most thorough). 5 = good balance.
VERSION_INTENSITY = 5

# Safe fallback when MCP is completely unavailable.
FALLBACK_SERVICES: Dict[int, ServiceInfo] = {
    22: ServiceInfo(port=22, service_name="ssh", version="OpenSSH", banner=""),
    80: ServiceInfo(port=80, service_name="http", version="Apache", banner=""),
}

# NSE scripts used for banner grabbing (safe, read-only).
BANNER_SCRIPTS = "banner,http-title,ssh-hostkey"

# NSE scripts for HTTP advanced fingerprinting.
HTTP_SCRIPTS = "http-headers,http-title,http-methods"

# NSE scripts for SSH advanced fingerprinting.
SSH_SCRIPTS = "ssh-auth-methods,ssh-hostkey"

# NSE scripts for database fingerprinting.
DB_SCRIPTS = "mysql-info,ms-sql-info,oracle-tns-version"


class ScoutAgent(BaseAgent):
    """
    Network reconnaissance agent.

    Full pipeline per target
    ------------------------
    1. Resolve concrete hosts (known targets → direct scope → ping sweep).
    2. Filter against operator exclusion list.
    3. Run adaptive ``-sV`` scan (strategy tuned by OS hint and target type).
    4. Run OS detection (``-O``) to refine strategy for follow-up scans.
    5. Run banner-grabbing NSE script pass.
    6. Run service-specific advanced fingerprinting scripts.
    7. Discover pivot subnets from discovered IPs and sweep them.
    8. Write normalised ``DiscoveredTarget`` records to state.
    """

    def __init__(self) -> None:
        super().__init__("scout", "Network Reconnaissance Specialist")

    @property
    def system_prompt(self) -> str:
        return "Recon worker: discover active services, versions, and pivot opportunities."

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        target_scope: List[str] = state.get("target_scope", []) or []
        if not target_scope:
            logger.error("Scout: target_scope is empty — nothing to scan")
            return self.log_error(state, error_type="ValidationError",
                                  error="No targets in target_scope")

        # Load and normalise operator exclusion list.
        raw_exclusions: List[str] = state.get("scan_exclusions", []) or []
        exclusions = normalise_exclusion_list(raw_exclusions)
        if exclusions:
            logger.info("Scout: exclusion list active (%d entr(ies)): %s", len(exclusions), exclusions)

        logger.info("Scout starting. scope=%s", target_scope)

        scan_targets = await self._resolve_scan_targets(state)
        if not scan_targets:
            logger.error("Scout: could not resolve any concrete hosts from scope=%s", target_scope)
            return self.log_error(state, error_type="ValidationError",
                                  error="Scout could not derive a concrete in-scope host to scan")

        # Filter against exclusion list.
        allowed_targets = []
        for t in scan_targets:
            if is_excluded_target(t, exclusions):
                logger.warning("Scout: skipping excluded target %s", t)
            else:
                allowed_targets.append(t)

        if not allowed_targets:
            logger.error("Scout: all resolved targets were excluded")
            return self.log_error(state, error_type="ValidationError",
                                  error="All resolved scan targets are in the exclusion list")

        logger.info("Scout scanning %d host(s): %s", len(allowed_targets), allowed_targets)

        discovered_targets: Dict[str, Dict[str, Any]] = {}
        total_ports: List[int] = []
        os_hints: Dict[str, Optional[str]] = {}  # target → os_family

        # ── Phase 1: Service scan all targets ──────────────────────────────
        for target in allowed_targets:
            if not target_in_scope(target, target_scope):
                logger.debug("Scout: skipping out-of-scope target %s", target)
                continue

            strategy = self._build_scan_strategy(target, os_hint=None)
            logger.info("Scout scanning %s  strategy=%s", target, strategy)

            services, os_info, banners = await self._full_scan(target, strategy)

            if os_info:
                os_hints[target] = os_info.get("os_family")
                logger.info("Scout OS detection for %s: %s (accuracy=%s%%)",
                            target, os_info.get("os_detail"), os_info.get("accuracy"))
                # Re-scan with OS-optimised strategy if OS changed the port list
                os_strategy = self._build_scan_strategy(target, os_hint=os_info.get("os_family"))
                if os_strategy["ports"] != strategy["ports"]:
                    logger.info("Scout re-scanning %s with OS-optimised port list", target)
                    services2, _, banners2 = await self._full_scan(target, os_strategy)
                    services.update(services2)
                    banners.update(banners2)

            # Merge banners into service info
            for port, banner_text in banners.items():
                if port in services:
                    # ServiceInfo is a Pydantic model — rebuild with banner
                    svc = services[port]
                    services[port] = ServiceInfo(
                        port=svc.port,
                        protocol=getattr(svc, "protocol", "tcp"),
                        service_name=svc.service_name,
                        version=svc.version,
                        banner=banner_text[:200],
                    )
                    logger.debug("Scout banner port %d: %s", port, banner_text[:80])

            ports = sorted(services.keys())
            total_ports.extend(ports)
            os_guess = (os_info or {}).get("os_detail") or "Unknown"

            discovered_targets[target] = DiscoveredTarget(
                ip_address=target,
                ports=ports,
                services=services,
                os_guess=os_guess,
            ).model_dump()

        if not discovered_targets:
            return self.log_error(state, error_type="ScopeViolation",
                                  error="Scout derived only out-of-scope targets")

        # ── Phase 2: Subnet pivoting ────────────────────────────────────────
        pivot_targets = await self._pivot_subnets(
            discovered_targets=discovered_targets,
            target_scope=target_scope,
            exclusions=exclusions,
        )
        for target, target_data in pivot_targets.items():
            if target not in discovered_targets:
                discovered_targets[target] = target_data
                total_ports.extend(target_data.get("ports", []))
                logger.info("Scout pivot discovered new host: %s", target)

        logger.info(
            "Scout complete. hosts=%d unique_ports=%d",
            len(discovered_targets),
            len(set(total_ports)),
        )

        return {
            "current_agent": "scout",
            "discovered_targets": discovered_targets,
            **self.log_action(
                state,
                action="recon_scan",
                target=", ".join(allowed_targets),
                findings={
                    "targets_scanned": list(discovered_targets.keys()),
                    "ports_found": sorted(set(total_ports)),
                    "services_found": sum(
                        len(d.get("ports", [])) for d in discovered_targets.values()
                    ),
                    "os_hints": os_hints,
                    "pivot_hosts_discovered": len(pivot_targets),
                },
                reasoning=(
                    f"Scout ran adaptive nmap -sV {NMAP_TIMING} with banner grabbing and "
                    f"OS-specific script selection against {allowed_targets}"
                ),
            ),
        }

    # -----------------------------------------------------------------------
    # Target resolution
    # -----------------------------------------------------------------------

    async def _resolve_scan_targets(self, state: CyberState) -> List[str]:
        """Return concrete hostnames/IPs to scan in priority order."""
        discovered_targets = state.get("discovered_targets", {}) or {}
        target_scope = state.get("target_scope", []) or []

        concrete_targets = [
            t for t in discovered_targets if target_in_scope(str(t), target_scope)
        ]
        if concrete_targets:
            return concrete_targets[:MAX_SCOUT_TARGETS]

        direct_targets = [e for e in target_scope if self._is_concrete_target(e)]
        if direct_targets:
            return direct_targets[:MAX_SCOUT_TARGETS]

        # Ping sweep CIDR blocks
        discovered: List[str] = []
        for entry in target_scope:
            if not self._is_network_scope(entry):
                continue
            hosts = await self._host_discovery(entry)
            for h in hosts:
                if h not in discovered and target_in_scope(h, target_scope):
                    discovered.append(h)
                if len(discovered) >= MAX_SCOUT_TARGETS:
                    return discovered
        return discovered

    def _is_concrete_target(self, value: str) -> bool:
        candidate = str(value or "").strip()
        if not candidate or self._is_network_scope(candidate):
            return False
        try:
            ip_address(candidate)
            return True
        except ValueError:
            return True  # hostname

    def _is_network_scope(self, value: str) -> bool:
        candidate = str(value or "").strip()
        if "/" not in candidate:
            return False
        try:
            ip_network(candidate, strict=False)
            return True
        except ValueError:
            return False

    # -----------------------------------------------------------------------
    # Adaptive scan strategy builder
    # -----------------------------------------------------------------------

    def _build_scan_strategy(
        self,
        target: str,
        os_hint: Optional[str],
    ) -> Dict[str, Any]:
        """
        Build an optimised nmap argument set based on target type and OS hint.

        Strategy rules
        --------------
        +------------------+----------------------------------------------+
        | Condition        | Effect                                       |
        +==================+==============================================+
        | CIDR / /24       | Ping sweep only; shorter port list           |
        | Single IP/host   | Full -sV with version scripts                |
        | OS = Windows     | Add ``-Pn`` (no ping dependency) +           |
        |                  | append Windows-specific ports                |
        | OS = Cisco       | Restrict to CISCO_SCAN_PORTS                 |
        | OS = Linux       | Standard port list                           |
        | Port 80/8000/etc | Add HTTP scripts                             |
        | Port 22 open     | Add SSH scripts                              |
        +------------------+----------------------------------------------+

        Args:
            target:   Hostname, IP, or CIDR.
            os_hint:  OS family string from ``parse_nmap_os_detection`` or None.

        Returns:
            Dict with keys ``ports``, ``additional_args``, ``scripts``.
        """
        ports = SERVICE_SCAN_PORTS
        extra_args: List[str] = [NMAP_TIMING, f"--version-intensity {VERSION_INTENSITY}"]
        scripts: List[str] = []

        is_cidr = self._is_network_scope(target)

        # Cisco/embedded: reduce scan surface.
        if os_hint and "cisco" in os_hint.lower():
            ports = CISCO_SCAN_PORTS
            extra_args.append("-Pn")  # Cisco devices often block ping
            logger.debug("Scout strategy: Cisco device, short port list")

        # Windows: add Windows ports, disable ping dependency.
        elif os_hint and "windows" in os_hint.lower():
            ports = f"{SERVICE_SCAN_PORTS},{WINDOWS_EXTRA_PORTS}"
            extra_args.append("-Pn")
            logger.debug("Scout strategy: Windows OS, -Pn + Windows ports")

        # Linux / unknown: standard scan.
        else:
            if is_cidr:
                # CIDRs: don't do heavy version scanning — use lighter scan.
                ports = "22,80,443,8000,8080"
                extra_args = [NMAP_TIMING]
                logger.debug("Scout strategy: CIDR target, lightweight port list")

        return {
            "ports": ports,
            "additional_args": " ".join(extra_args),
            "scripts": scripts,
        }

    def _build_script_args(self, services: Dict[int, ServiceInfo]) -> str:
        """
        Choose NSE script set based on what services are open.

        Called *after* the initial -sV scan so we know which ports are open.
        Returns the ``--script <list>`` argument string to append to nmap.
        """
        script_set: List[str] = ["banner"]  # Always grab raw banners
        open_services = {svc.service_name.lower() for svc in services.values()}
        open_ports = set(services.keys())

        if open_ports & {80, 443, 8000, 8080, 8443}:
            script_set.extend(["http-title", "http-headers", "http-methods"])
        if open_ports & {22}:
            script_set.extend(["ssh-auth-methods", "ssh-hostkey"])
        if "mysql" in open_services or 3306 in open_ports:
            script_set.append("mysql-info")
        if "ms-sql" in open_services or 1433 in open_ports:
            script_set.append("ms-sql-info")
        if "ftp" in open_services or 21 in open_ports:
            script_set.append("ftp-anon")

        return "--script " + ",".join(dict.fromkeys(script_set))  # deduplicate, preserve order

    # -----------------------------------------------------------------------
    # Full scan pipeline for a single target
    # -----------------------------------------------------------------------

    async def _full_scan(
        self,
        target: str,
        strategy: Dict[str, Any],
    ) -> Tuple[Dict[int, ServiceInfo], Optional[Dict[str, Any]], Dict[int, str]]:
        """
        Run the 3-pass scan sequence for a single host:

        1. ``-sV`` service fingerprinting.
        2. ``-O`` OS detection (best effort, skipped on timeout).
        3. ``--script <nse>`` banner grabbing + advanced fingerprinting.

        Returns
        -------
        Tuple of (services dict, os_info dict or None, banner dict).
        """
        services = await self._discover_services(target, strategy)
        os_info = await self._detect_os(target)
        banners = await self._grab_banners(target, services)
        return services, os_info, banners

    # -----------------------------------------------------------------------
    # Individual scan passes
    # -----------------------------------------------------------------------

    async def _host_discovery(self, scope_entry: str) -> List[str]:
        """Fast ``-sn -T4`` ping sweep to find live hosts in a CIDR."""
        bridge = await self._get_bridge()
        if bridge is None:
            return []
        tools = bridge.get_tools_for_agent(SCOUT_ALLOWED_TOOLS)
        nmap_tool = next((t for t in tools if t.name.endswith("nmap_scan")), None)
        if nmap_tool is None:
            logger.warning("Scout: nmap_scan not available for host discovery")
            return []
        try:
            logger.debug("Scout host-discovery: %s on %s", NMAP_TIMING, scope_entry)
            raw = await asyncio.wait_for(
                nmap_tool.coroutine(target=scope_entry, scan_type="-sn",
                                    ports="", additional_args=NMAP_TIMING),
                timeout=NMAP_TIMEOUT_SECONDS,
            )
            hosts = parse_nmap_hosts(raw)
            logger.info("Scout ping sweep %s → %d host(s)", scope_entry, len(hosts))
            return hosts
        except asyncio.TimeoutError:
            logger.warning("Scout: host discovery timed out on %s", scope_entry)
            return []
        except Exception as exc:
            logger.warning("Scout: host discovery failed on %s: %s", scope_entry, exc)
            return []

    async def _discover_services(
        self,
        target: str,
        strategy: Dict[str, Any],
    ) -> Dict[int, ServiceInfo]:
        """Run ``-sV`` with the strategy-determined port list and arguments."""
        bridge = await self._get_bridge()
        if bridge is not None:
            tools = bridge.get_tools_for_agent(SCOUT_ALLOWED_TOOLS)
            nmap_tool = next((t for t in tools if t.name.endswith("nmap_scan")), None)
            if nmap_tool:
                try:
                    logger.debug("Scout -sV: %s ports=%s extra=%s",
                                 target, strategy["ports"], strategy["additional_args"])
                    raw = await asyncio.wait_for(
                        nmap_tool.coroutine(
                            target=target,
                            scan_type="-sV",
                            ports=strategy["ports"],
                            additional_args=strategy["additional_args"],
                        ),
                        timeout=NMAP_TIMEOUT_SECONDS,
                    )
                    parsed = _raw_to_service_infos(raw)
                    if parsed:
                        logger.info("Scout: %d service(s) on %s: %s",
                                    len(parsed), target,
                                    [f"{p}/{v.service_name}" for p, v in parsed.items()])
                        return parsed
                    logger.warning("Scout: no parseable services from nmap for %s", target)
                except asyncio.TimeoutError:
                    logger.warning("Scout: -sV timed out after %ds on %s — fallback",
                                   NMAP_TIMEOUT_SECONDS, target)
                except Exception as exc:
                    logger.warning("Scout: -sV error on %s: %s — fallback", target, exc)

        logger.info("Scout: using fallback services for %s", target)
        return dict(FALLBACK_SERVICES)

    async def _detect_os(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Run ``-O`` OS detection and return parsed result.

        OS detection requires root-level privileges inside the Kali container.
        If it fails (common in unprivileged setups), returns None silently.
        """
        bridge = await self._get_bridge()
        if bridge is None:
            return None
        tools = bridge.get_tools_for_agent(SCOUT_ALLOWED_TOOLS)
        nmap_tool = next((t for t in tools if t.name.endswith("nmap_scan")), None)
        if nmap_tool is None:
            return None
        try:
            logger.debug("Scout OS detection: -O on %s", target)
            raw = await asyncio.wait_for(
                nmap_tool.coroutine(
                    target=target,
                    scan_type="-O",
                    ports="",
                    additional_args=NMAP_TIMING,
                ),
                timeout=NMAP_TIMEOUT_SECONDS,
            )
            return parse_nmap_os_detection(raw)
        except asyncio.TimeoutError:
            logger.debug("Scout: OS detection timed out on %s", target)
            return None
        except Exception as exc:
            logger.debug("Scout: OS detection skipped for %s: %s", target, exc)
            return None

    async def _grab_banners(
        self,
        target: str,
        services: Dict[int, ServiceInfo],
    ) -> Dict[int, str]:
        """
        Run service-specific NSE scripts to grab banners.

        The script set is chosen dynamically based on which services are open:
        - Always: ``banner`` (raw TCP banner)
        - HTTP ports: ``http-title,http-headers,http-methods``
        - SSH port 22: ``ssh-auth-methods,ssh-hostkey``
        - MySQL port 3306: ``mysql-info``
        """
        bridge = await self._get_bridge()
        if bridge is None or not services:
            return {}
        tools = bridge.get_tools_for_agent(SCOUT_ALLOWED_TOOLS)
        nmap_tool = next((t for t in tools if t.name.endswith("nmap_scan")), None)
        if nmap_tool is None:
            return {}

        script_arg = self._build_script_args(services)
        open_ports = ",".join(str(p) for p in sorted(services.keys()))

        try:
            logger.debug("Scout banner grab: %s on %s ports=%s", script_arg, target, open_ports)
            raw = await asyncio.wait_for(
                nmap_tool.coroutine(
                    target=target,
                    scan_type="-sV",
                    ports=open_ports,
                    additional_args=f"{NMAP_TIMING} {script_arg}",
                ),
                timeout=NMAP_TIMEOUT_SECONDS,
            )
            banners = parse_nmap_script_banners(raw)
            if banners:
                logger.info("Scout: grabbed %d banner(s) on %s", len(banners), target)
            return banners
        except asyncio.TimeoutError:
            logger.warning("Scout: banner grab timed out on %s", target)
            return {}
        except Exception as exc:
            logger.warning("Scout: banner grab failed on %s: %s", target, exc)
            return {}

    # -----------------------------------------------------------------------
    # Subnet pivoting
    # -----------------------------------------------------------------------

    async def _pivot_subnets(
        self,
        discovered_targets: Dict[str, Dict[str, Any]],
        target_scope: List[str],
        exclusions: List[str],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Derive /24 pivot subnets from the IPs we just discovered and ping-sweep them.

        A "pivot subnet" is a /24 network derived from each discovered IP.
        Example: discovering ``172.20.0.5`` generates pivot subnet ``172.20.0.0/24``.

        Rules
        -----
        - Only derive subnets that are strictly inside ``target_scope`` CIDRs.
        - Skip subnets already fully covered by a scope entry.
        - Skip subnets in the exclusion list.
        - Hard-cap at ``MAX_PIVOT_SUBNETS`` sweeps per Scout run.

        Returns
        -------
        Dict of newly discovered hosts (IP → DiscoveredTarget dict).
        """
        pivot_results: Dict[str, Dict[str, Any]] = {}
        pivot_subnets: List[str] = []

        for ip_str in discovered_targets:
            try:
                host_ip = ip_address(ip_str)
            except ValueError:
                continue  # hostname — can't derive subnet

            # Derive /24 pivot subnet from this IP
            pivot = str(ip_network(f"{host_ip}/24", strict=False))

            if pivot in pivot_subnets:
                continue

            # Only pivot if the subnet is inside an authorised scope CIDR
            in_scope = False
            for scope_entry in target_scope:
                try:
                    scope_net = ip_network(scope_entry, strict=False)
                    pivot_net = ip_network(pivot, strict=False)
                    if pivot_net.subnet_of(scope_net) or scope_net.subnet_of(pivot_net):
                        in_scope = True
                        break
                except ValueError:
                    pass

            if not in_scope:
                logger.debug("Scout pivot %s not in scope — skipping", pivot)
                continue

            if is_excluded_target(pivot, exclusions):
                logger.warning("Scout pivot %s is excluded — skipping", pivot)
                continue

            pivot_subnets.append(pivot)
            if len(pivot_subnets) > MAX_PIVOT_SUBNETS:
                break

        if not pivot_subnets:
            return {}

        logger.info("Scout pivoting into %d new subnet(s): %s", len(pivot_subnets), pivot_subnets)

        for subnet in pivot_subnets:
            new_hosts = await self._host_discovery(subnet)
            for host in new_hosts:
                if host in discovered_targets or host in pivot_results:
                    continue
                if is_excluded_target(host, exclusions):
                    continue
                # Quick service scan on pivoted hosts (lighter scan).
                strategy = self._build_scan_strategy(host, os_hint=None)
                services, _, banners = await self._full_scan(host, strategy)
                ports = sorted(services.keys())
                pivot_results[host] = DiscoveredTarget(
                    ip_address=host,
                    ports=ports,
                    services=services,
                    os_guess="Unknown (pivot)",
                ).model_dump()

        return pivot_results

    # -----------------------------------------------------------------------
    # MCP bridge helper
    # -----------------------------------------------------------------------

    async def _get_bridge(self) -> Optional[Any]:
        """Return MCP bridge or None on failure (best effort)."""
        try:
            return await get_mcp_bridge()
        except Exception as exc:
            logger.warning("Scout: MCP bridge unavailable: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _raw_to_service_infos(raw: Any) -> Dict[int, ServiceInfo]:
    """
    Convert raw nmap MCP output to ServiceInfo objects via the centralised
    ``parse_nmap_services`` utility.

    The centralised parser handles complex version strings such as::

        22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        8000/tcp open  http    Werkzeug httpd 3.1.8 (Python 3.10.12)
        443/tcp  open  ssl/http Apache/2.4.41

    ``product``, ``version_number``, ``os_hint``, and ``cpe`` are all extracted
    and stored on the dict but only ``version`` is surfaced in ServiceInfo since
    that model pre-dates the richer fields.  The extra fields are available via
    the raw ``parse_nmap_services`` call.
    """
    raw_dict = parse_nmap_services(raw)
    result: Dict[int, ServiceInfo] = {}
    for port, svc in raw_dict.items():
        try:
            result[port] = ServiceInfo(
                port=svc["port"],
                protocol=svc.get("protocol", "tcp"),
                service_name=svc["service_name"],
                version=svc.get("version") or "",
                banner=svc.get("banner") or "",
            )
        except Exception as exc:
            logger.debug("Scout: could not build ServiceInfo for port %d: %s", port, exc)
    return result


# ---------------------------------------------------------------------------
# LangGraph node wrapper
# ---------------------------------------------------------------------------

async def scout_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for ScoutAgent."""
    agent = ScoutAgent()
    return await agent.call_llm(state)
