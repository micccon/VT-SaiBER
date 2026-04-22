"""
Parsing helpers used by orchestration components.

This module centralises all tool-output parsing so that agent classes
stay focused on orchestration logic rather than regex mechanics.

Supported tools
---------------
- nmap          : port/service discovery, host discovery (-sn)
- gobuster      : directory/file enumeration (text output)
- ffuf          : web fuzzing (JSON output via -of json)
- nikto         : web-server vulnerability scanner
- Generic       : JSON extraction from LLM responses, Metasploit key helpers
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


# ============================================================================
# GENERIC HELPERS
# ============================================================================

def extract_text_payload(raw_output: Any) -> str:
    """
    Normalise raw MCP tool output to a plain text string.

    MCP servers wrap tool results in various envelopes:
      - Direct string    : returned as-is
      - JSON string      : unwrapped from common keys (output, stdout, result)
      - dict             : first str value found under known keys is returned

    Args:
        raw_output: Raw value returned by an MCP tool coroutine.

    Returns:
        Plain text string ready for regex parsing, or empty string on failure.
    """
    payload = raw_output

    # 1. If it's a raw string, try JSON-parsing it first.
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return payload  # already plain text

    # 2. If it's a dict, walk known envelope keys.
    if isinstance(payload, dict):
        for key in ("output", "stdout", "result", "data"):
            value = payload.get(key)
            if isinstance(value, str):
                return value
            # Nested envelope: {"result": {"output": "..."}}
            if isinstance(value, dict):
                for inner_key in ("output", "stdout"):
                    maybe = value.get(inner_key)
                    if isinstance(maybe, str):
                        return maybe

    return ""


def extract_json_payload(text: str) -> Dict[str, Any]:
    """
    Extract a JSON object from raw model text output.

    Supports:
      - Plain JSON string
      - Fenced markdown blocks: ```json ... ```

    Args:
        text: Raw LLM or tool response text.

    Returns:
        Parsed dict.

    Raises:
        ValueError: If no valid JSON object is found.
    """
    candidate = (text or "").strip()
    if not candidate:
        raise ValueError("Empty model response")

    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        parsed = _extract_first_object(candidate)

    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object")
    return parsed


def _extract_first_object(text: str) -> Any:
    """Scan text for the first balanced JSON object and parse it."""
    start = text.find("{")
    if start < 0:
        raise ValueError("No JSON object found")

    depth = 0
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : idx + 1])
    raise ValueError("Malformed JSON object")


def to_jsonable(value: Any) -> Any:
    """
    Convert Pydantic or dataclass-like objects into plain JSON-serialisable
    structures.
    """
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


def normalize_tool_result(raw: Any) -> Dict[str, Any]:
    """
    Normalise MCP tool results into a plain dictionary.

    Accepts direct dicts, JSON strings, and common ``{"result": ...}``
    envelope patterns.

    Args:
        raw: Raw tool result from an MCP call.

    Returns:
        Normalised dict, possibly empty on total parse failure.
    """
    payload = raw

    if isinstance(payload, str):
        candidate = payload.strip()
        if not candidate:
            return {}
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            try:
                payload = _extract_first_object(candidate)
            except ValueError:
                return {}

    if not isinstance(payload, dict):
        return {}

    nested = payload.get("result")
    if len(payload) == 1 and isinstance(nested, dict):
        return nested

    return payload


def metasploit_module_key(module_type: Any, module_name: Any) -> str:
    """
    Build a stable lowercase key for Metasploit module bookkeeping.

    Args:
        module_type: Module category (e.g. ``"exploit"``, ``"auxiliary"``).
        module_name: Full module path (e.g. ``"unix/ftp/vsftpd_234_backdoor"``).

    Returns:
        Lowercase ``"type:name"`` string, or just ``"name"`` if type is absent.
    """
    normalized_name = str(module_name or "").strip().lower()
    if not normalized_name:
        return ""

    normalized_type = str(module_type or "").strip().lower()
    if not normalized_type:
        return normalized_name

    return f"{normalized_type}:{normalized_name}"


# ============================================================================
# NMAP PARSERS
# ============================================================================

def parse_nmap_services(raw_output: Any) -> Dict[int, Dict[str, Any]]:
    """
    Parse nmap service-version scan output (``-sV``) into a structured dict.

    Handles complex nmap version strings produced by ``-sV``, including::

        22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        8000/tcp open  http    Werkzeug httpd 3.1.8 (Python 3.10.12)
        8080/tcp open  http    nginx 1.18.0 (Ubuntu)
        3306/tcp open  mysql   MySQL 5.7.38-log
        443/tcp  open  ssl/http Apache httpd 2.4.41 ((Ubuntu))

    Version string extraction
    -------------------------
    The raw version field from nmap can be complex:

    - ``OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)``
    - ``Werkzeug httpd 3.1.8 (Python 3.10.12)``

    This function extracts:
    - ``product``  : First token (e.g. ``"OpenSSH"``, ``"Werkzeug"``)
    - ``version``  : Full raw version string for maximum transparency
    - ``os_hint``  : Parenthetical OS annotation if present (e.g. ``"Ubuntu Linux"``)
    - ``cpe``      : ``cpe:/a:...`` string if present (from ``-sV`` verbose output)

    Args:
        raw_output: Raw MCP tool result (string, dict envelope, or JSON).

    Returns:
        Dict mapping port (int) → service info dict::

            {
              22: {
                "port": 22, "protocol": "tcp", "service_name": "ssh",
                "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5",
                "product": "OpenSSH", "version_number": "8.2p1",
                "os_hint": "Ubuntu Linux", "cpe": None, "banner": None
              }
            }
    """
    text = extract_text_payload(raw_output)
    services: Dict[int, Dict[str, Any]] = {}

    if not text:
        return services

    # Regex: "<port>/<proto>  open  <service>  <optional full version string>"
    port_re = re.compile(
        r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)\s*(.*)$",
        re.IGNORECASE,
    )
    # CPE extraction: "cpe:/a:vendor:product:version"
    cpe_re = re.compile(r"(cpe:/[^\s]+)")

    for line in text.splitlines():
        match = port_re.match(line.strip())
        if not match:
            continue

        port = int(match.group(1))
        proto = match.group(2).lower()
        service_name = match.group(3).lower()
        raw_version = match.group(4).strip()

        # -- CPE extraction --------------------------------------------------
        cpe: Optional[str] = None
        cpe_match = cpe_re.search(raw_version)
        if cpe_match:
            cpe = cpe_match.group(1)
            raw_version = raw_version[:cpe_match.start()].strip()

        # -- OS hint extraction (parenthetical at end) -----------------------
        # e.g. "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)"
        os_hint: Optional[str] = None
        paren_match = re.search(r"\(([^)]+)\)\s*$", raw_version)
        if paren_match:
            # Strip OS/note annotations from the version
            os_hint = paren_match.group(1).split(";")[0].strip()
            raw_version = raw_version[:paren_match.start()].strip()

        # -- Product + version number ----------------------------------------
        # nmap version field: "<Product> <version_number> [extra_tokens]"
        tokens = raw_version.split()
        product: Optional[str] = tokens[0] if tokens else None
        # First token that looks like a version number
        version_number: Optional[str] = None
        semver_re = re.compile(r"^\d+[.\-]")
        for tok in tokens[1:]:
            if semver_re.match(tok):
                version_number = tok
                break

        services[port] = {
            "port": port,
            "protocol": proto,
            "service_name": service_name,
            "version": raw_version or None,       # cleaned full version string
            "product": product,                   # first token ("OpenSSH", "nginx")
            "version_number": version_number,     # semver-ish token ("8.2p1", "1.18.0")
            "os_hint": os_hint,                   # parenthetical annotation
            "cpe": cpe,                           # CPE string if present
            "banner": None,
        }

    return services


def parse_nmap_os_detection(raw_output: Any) -> Optional[Dict[str, Any]]:
    """
    Parse nmap OS detection output (``-O``) into a structured dict.

    Nmap OS detection output looks like::

        Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.0 (93%)
        OS details: Linux 4.15 - 5.6
        Running: Linux 4.X|5.X
        OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5

    Args:
        raw_output: Raw MCP tool result.

    Returns:
        Dict with keys ``os_family``, ``os_detail``, ``accuracy``, ``cpe``
        or ``None`` if no OS information is found.

    Examples::

        result = parse_nmap_os_detection(raw)
        result["os_family"]  # "Linux"
        result["accuracy"]   # 95
        result["cpe"]        # "cpe:/o:linux:linux_kernel:5"
    """
    text = extract_text_payload(raw_output)
    if not text:
        return None

    result: Dict[str, Any] = {
        "os_family": None,
        "os_detail": None,
        "accuracy": None,
        "cpe": None,
        "running": None,
    }

    # "Aggressive OS guesses: <name> (<accuracy>%), ..."
    guess_re = re.compile(
        r"Aggressive OS guesses?:\s*(.+?)(?:\s*\(\s*(\d+)%\s*\))?(?:,|$)",
        re.IGNORECASE,
    )
    for match in guess_re.finditer(text):
        result["os_detail"] = match.group(1).strip()
        if match.group(2):
            result["accuracy"] = int(match.group(2))
        break  # Take highest-confidence guess (first one)

    # "OS details: <detail>"
    detail_re = re.compile(r"^OS details?:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    dm = detail_re.search(text)
    if dm:
        result["os_detail"] = dm.group(1).strip()

    # "Running: <family>"
    running_re = re.compile(r"^Running(?:\s*\(JUST GUESSING\))?:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    rm = running_re.search(text)
    if rm:
        result["running"] = rm.group(1).strip()

    # "OS CPE: cpe:/o:..."
    cpe_re = re.compile(r"OS CPE:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    cm = cpe_re.search(text)
    if cm:
        # Take first CPE in the space-separated list
        cpes = cm.group(1).strip().split()
        result["cpe"] = cpes[0] if cpes else None

    # Derive os_family from detail / running string
    for field in ("os_detail", "running"):
        detail = result.get(field) or ""
        for family in ("Windows", "Linux", "macOS", "FreeBSD", "OpenBSD", "Cisco", "Android"):
            if family.lower() in detail.lower():
                result["os_family"] = family
                break
        if result["os_family"]:
            break

    # Return None if we found nothing useful
    if not any(result.values()):
        return None

    return result


def parse_nmap_script_banners(raw_output: Any) -> Dict[int, str]:
    """
    Parse nmap NSE script output for ``--script banner`` results.

    Nmap outputs script results like::

        22/tcp open  ssh
        | ssh-hostkey:
        |   2048 aa:bb:cc:dd:ee:ff ... (RSA)
        |_  256 11:22:33:44:55:66 ... (ECDSA)
        80/tcp open http
        |_http-title: Automotive Infotainment
        8000/tcp open http-alt
        | banner: HTTP/1.1 302 FOUND\\r\\n
        | Server: Werkzeug/3.1.8 Python/3.10.12\\r\\n

    Args:
        raw_output: Raw MCP tool result containing nmap NSE script output.

    Returns:
        Dict mapping port (int) → banner string extracted from script output.

    Examples::

        banners = parse_nmap_script_banners(raw)
        banners[22]    # "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        banners[80]    # "Automotive Infotainment"
        banners[8000]  # "Werkzeug/3.1.8 Python/3.10.12"
    """
    text = extract_text_payload(raw_output)
    banners: Dict[int, str] = {}

    if not text:
        return banners

    # Detect which port we're in as we parse line by line
    current_port: Optional[int] = None
    port_re = re.compile(r"^(\d{1,5})/(tcp|udp)\s+\w+", re.IGNORECASE)
    banner_lines: Dict[int, List[str]] = {}

    for line in text.splitlines():
        # Port header line — update current context
        pm = port_re.match(line.strip())
        if pm:
            current_port = int(pm.group(1))
            continue

        if current_port is None:
            continue

        stripped = line.strip()

        # NSE output lines start with "|" or "|_"
        if not stripped.startswith("|"):
            continue

        # Strip leading pipe characters
        content = re.sub(r"^\|_?\s*", "", stripped).strip()
        if not content:
            continue

        # Key script outputs we care about
        for prefix in (
            "banner:",          # --script banner
            "_http-title:",     # --script http-title
            "http-title:",
            "_ssh-auth-methods:",
        ):
            if content.lower().startswith(prefix.lower()):
                value = content[len(prefix):].strip()
                banner_lines.setdefault(current_port, []).append(value)
                break
        else:
            # Grab first line of any other script output as context
            if current_port not in banner_lines:
                banner_lines[current_port] = [content]

    # Flatten each port's lines into a single string
    for port, lines in banner_lines.items():
        banners[port] = " | ".join(lines[:3])  # cap at 3 lines

    return banners


def parse_nmap_hosts(raw_output: Any) -> List[str]:
    """
    Parse nmap host-discovery scan output (``-sn`` ping sweep) into a list
    of live host IPs or hostnames.

    Nmap reports live hosts with::

        Nmap scan report for 172.20.0.5
        Nmap scan report for automotive-testbed (172.20.0.5)

    Args:
        raw_output: Raw MCP tool result.

    Returns:
        List of IP address strings for all hosts that responded.
        Hostname-only entries are included verbatim if no parenthesised IP.
    """
    text = extract_text_payload(raw_output)
    hosts: List[str] = []

    if not text:
        return hosts

    report_re = re.compile(r"^Nmap scan report for (.+)$", re.IGNORECASE)
    ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

    for line in text.splitlines():
        match = report_re.match(line.strip())
        if not match:
            continue
        candidate = match.group(1).strip()
        # Prefer IP from parentheses, e.g. "hostname (1.2.3.4)"
        parens_ip = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", candidate)
        if parens_ip:
            host = parens_ip.group(1)
        else:
            ip_match = ip_re.search(candidate)
            host = ip_match.group(1) if ip_match else candidate

        if host and host not in hosts:
            hosts.append(host)

    return hosts


# ============================================================================
# GOBUSTER PARSER
# ============================================================================

_GOBUSTER_LINE_RE = re.compile(
    r"^(/\S*)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?",
    re.IGNORECASE,
)


def parse_gobuster_output(
    raw_output: Any,
    base_url: str,
    max_depth: int = 3,
    soft_404_statuses: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """
    Parse gobuster ``dir`` mode text output into structured web findings.

    Gobuster line format::

        /admin                (Status: 301) [Size: 0] [--> /admin/]
        /login                (Status: 200) [Size: 4096]

    Soft-404 detection
    ------------------
    Soft-404s are server responses that look like errors but return 200 OK.
    Gobuster does not detect them natively. We filter two cases:
      1. Statically excluded status codes (``soft_404_statuses`` set).
      2. Depth limit: deep paths rarely matter for initial recon.

    Args:
        raw_output: Raw MCP tool result.
        base_url: Target base URL used to build absolute ``url`` fields.
        max_depth: Maximum path segment depth to include. Deeper paths are
                   discarded as low-value noise.
        soft_404_statuses: Set of HTTP status codes to treat as soft 404s
                           and exclude. Defaults to ``{404, 400}``.

    Returns:
        List of finding dicts, deduplicated, capped at 200 entries.
    """
    if soft_404_statuses is None:
        soft_404_statuses = {404, 400}

    text = extract_text_payload(raw_output)
    findings: List[Dict[str, Any]] = []

    for line in text.splitlines():
        match = _GOBUSTER_LINE_RE.match(line.strip())
        if not match:
            continue

        path = match.group(1)
        status_code = int(match.group(2))
        content_length = int(match.group(3)) if match.group(3) else None

        if status_code in soft_404_statuses:
            continue

        depth = len([seg for seg in path.split("/") if seg])
        if depth > max_depth:
            continue

        finding = _build_web_finding(
            base_url=base_url,
            path=path,
            status_code=status_code,
            content_length=content_length,
            content_type=None,
            rationale="Discovered by gobuster",
            depth=depth,
        )
        findings.append(finding)

    return _deduplicate_findings(findings)[:200]


# ============================================================================
# FFUF PARSER
# ============================================================================

def parse_ffuf_output(
    raw_output: Any,
    base_url: str,
    max_depth: int = 3,
    soft_404_statuses: Optional[set] = None,
    soft_404_size: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Parse ffuf JSON output (produced by ``-of json``) into structured web
    findings.

    ffuf writes a top-level JSON object with a ``results`` key::

        {
          "commandline": "ffuf -u http://host/FUZZ ...",
          "results": [
            {
              "input":  {"FUZZ": "admin"},
              "url":    "http://host/admin",
              "status": 301,
              "length": 0,
              "words":  0,
              "lines":  0
            },
            ...
          ]
        }

    Soft-404 detection
    ------------------
    ffuf does not distinguish real 200s from soft-404s automatically.
    We apply two heuristics:
      1. Status code exclusion via ``soft_404_statuses``.
      2. Content-length exclusion: if every entry at a given path returns the
         **same body size** as a known random-word probe, it is a soft-404.
         Pass ``soft_404_size`` to activate this filter (use a prior probe call
         to determine the baseline size).

    Args:
        raw_output: Raw MCP tool result (string, dict, or JSON envelope).
        base_url: Target base URL, used to normalise relative paths.
        max_depth: Maximum path depth to include.
        soft_404_statuses: HTTP codes to treat as soft-404 and exclude.
                           Defaults to ``{404, 400}``.
        soft_404_size: If set, findings whose ``content_length`` exactly
                       matches this value are discarded as soft-404s.

    Returns:
        List of deduplicated finding dicts, capped at 200 entries.
    """
    if soft_404_statuses is None:
        soft_404_statuses = {404, 400}

    findings: List[Dict[str, Any]] = []

    # ── Try to parse as ffuf JSON output first ──────────────────────────────
    try:
        payload = _extract_ffuf_json(raw_output)
        results = payload.get("results", [])
        for entry in results:
            if not isinstance(entry, dict):
                continue

            url = entry.get("url", "")
            status = int(entry.get("status", 0))
            length = entry.get("length")
            content_type = entry.get("content-type") or entry.get("headers", {}).get(
                "content-type"
            )

            if status in soft_404_statuses:
                continue
            if soft_404_size is not None and length == soft_404_size:
                continue

            path = _url_to_path(url, base_url)
            depth = len([s for s in path.split("/") if s])
            if depth > max_depth:
                continue

            finding = _build_web_finding(
                base_url=base_url,
                path=path,
                status_code=status,
                content_length=length,
                content_type=content_type,
                rationale="Discovered by ffuf",
                depth=depth,
            )
            findings.append(finding)

        return _deduplicate_findings(findings)[:200]

    except (ValueError, KeyError, TypeError):
        pass  # Fall through to text-mode parsing

    # ── Fallback: ffuf text output (non-JSON mode) ──────────────────────────
    text = extract_text_payload(raw_output)
    # ffuf text line: "admin                   [Status: 200, Size: 4096, ...]"
    text_re = re.compile(
        r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        match = text_re.match(line.strip())
        if not match:
            continue
        word = match.group(1)
        status = int(match.group(2))
        length = int(match.group(3))
        if status in soft_404_statuses:
            continue
        if soft_404_size is not None and length == soft_404_size:
            continue
        path = f"/{word}"
        depth = len([s for s in path.split("/") if s])
        if depth > max_depth:
            continue
        finding = _build_web_finding(
            base_url=base_url,
            path=path,
            status_code=status,
            content_length=length,
            content_type=None,
            rationale="Discovered by ffuf (text mode)",
            depth=depth,
        )
        findings.append(finding)

    return _deduplicate_findings(findings)[:200]


def _extract_ffuf_json(raw_output: Any) -> Dict[str, Any]:
    """
    Pull the ffuf JSON object out of raw MCP output.

    ffuf with ``-of json`` emits output like::

        some-file.json contents: { "commandline": ..., "results": [...] }

    The Kali REST API wraps this in a ``{"stdout": "..."}`` envelope.
    """
    text = extract_text_payload(raw_output)

    # First try the raw text directly
    if not text:
        if isinstance(raw_output, dict):
            text = json.dumps(raw_output)
        else:
            text = str(raw_output)

    # Find the ffuf JSON blob (it may be preceded by status lines)
    start = text.find("{")
    if start >= 0:
        try:
            parsed = json.loads(text[start:])
            if isinstance(parsed, dict) and "results" in parsed:
                return parsed
        except json.JSONDecodeError:
            pass

    # Try the whole text
    parsed = json.loads(text)
    if isinstance(parsed, dict) and "results" in parsed:
        return parsed

    raise ValueError("No ffuf JSON results found")


# ============================================================================
# NIKTO PARSER
# ============================================================================

_NIKTO_LINE_RE = re.compile(r"^\+\s+(/[^:\s]*).*?:\s*(.+)$")


def parse_nikto_output(
    raw_output: Any,
    base_url: str,
    max_depth: int = 3,
) -> List[Dict[str, Any]]:
    """
    Parse nikto scanner text output into structured web findings.

    Nikto line format::

        + /admin/: Default Apache Tomcat admin interface. ...

    All nikto findings are treated as ``is_interesting=True`` since nikto
    already filters to known-vulnerable or notable endpoints.

    Args:
        raw_output: Raw MCP tool result.
        base_url: Target base URL for absolute URL construction.
        max_depth: Maximum path depth to include.

    Returns:
        List of finding dicts, capped at 50 entries.
    """
    text = extract_text_payload(raw_output)
    findings: List[Dict[str, Any]] = []

    for line in text.splitlines():
        match = _NIKTO_LINE_RE.match(line.strip())
        if not match:
            continue
        path = match.group(1)
        detail = match.group(2).strip()
        depth = len([seg for seg in path.split("/") if seg])
        if depth > max_depth:
            continue
        finding = _build_web_finding(
            base_url=base_url,
            path=path,
            status_code=0,  # Nikto doesn't always report status
            content_length=None,
            content_type="nikto-report",
            rationale=f"Nikto finding: {detail[:200]}",
            depth=depth,
            force_interesting=True,
        )
        findings.append(finding)

    return findings[:50]


# ============================================================================
# SHARED FINDING BUILDER
# ============================================================================

_INTERESTING_PATHS = frozenset(
    {"admin", "login", "dashboard", "config", "api", "backup",
     "upload", "uploads", "secret", "private", "manage", "console"}
)
_INTERESTING_STATUSES = frozenset({200, 201, 401, 403})


def _build_web_finding(
    base_url: str,
    path: str,
    status_code: int,
    content_length: Optional[int],
    content_type: Optional[str],
    rationale: str,
    depth: int,
    force_interesting: bool = False,
) -> Dict[str, Any]:
    """
    Build a normalised web finding dict compatible with the
    ``WebFinding`` Pydantic model and the fuzzer state schema.

    Interestingness heuristics
    --------------------------
    A finding is flagged ``is_interesting`` when any of these apply:
    - ``force_interesting`` is True (e.g., nikto findings)
    - HTTP status is 200, 201, 401, or 403
    - Path contains a sensitive keyword (admin, login, api, config, …)
    - Path starts with ``/api``
    """
    path_lower = path.lower()
    path_parts = set(p for p in path_lower.split("/") if p)

    is_api = path_lower.startswith("/api")
    is_interesting = force_interesting or (
        status_code in _INTERESTING_STATUSES
        or is_api
        or bool(path_parts & _INTERESTING_PATHS)
    )

    # Normalise URL
    clean_base = base_url.rstrip("/")
    url = f"{clean_base}{path}"

    return {
        "url": url,
        "path": path,
        "status_code": status_code,
        "content_length": content_length,
        "content_type": content_type,
        "is_api_endpoint": is_api,
        "is_interesting": is_interesting,
        "discovery_depth": depth,
        "rationale": rationale,
    }


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings by (path, status_code, rationale) key."""
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for finding in findings:
        key = (finding.get("path"), finding.get("status_code"), finding.get("rationale"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _url_to_path(url: str, base_url: str) -> str:
    """
    Extract the path component from a full URL relative to a base URL.

    Example::

        _url_to_path("http://host:8000/admin/login", "http://host:8000")
        # → "/admin/login"
    """
    base = base_url.rstrip("/")
    if url.startswith(base):
        path = url[len(base):]
        return path if path.startswith("/") else f"/{path}"
    # Fallback: strip scheme+host
    match = re.match(r"https?://[^/]+(/.*)$", url)
    return match.group(1) if match else "/"


# ============================================================================
# CAN BUS / AUTOMOTIVE OT PARSERS
# ============================================================================

from dataclasses import dataclass, field as dc_field


@dataclass
class CANFrame:
    """
    A single parsed CAN bus frame from candump output.

    candump standard output format::

        vcan0  244   [8]  00 00 00 00 00 00 00 32
        vcan0  188   [3]  00 01 00
        ──────────────────────────────────────────
        ^iface ^id   ^dlc ^────── data bytes ──────^

    With timestamp (``-t a`` flag)::

        (1234567890.123456)  vcan0  244   [8]  00 00 00 00 00 00 00 32
    """
    interface: str
    arb_id: str          # Uppercase hex, e.g. "244"
    arb_id_int: int      # Integer form for comparisons
    dlc: int             # Data length code (0-8)
    data: List[int]      # List of byte values (ints)
    data_hex: str        # "00 00 00 00 00 00 00 32" (raw string)
    timestamp: Optional[float]  # Unix timestamp or None


def parse_candump_output(raw_output: Any) -> List[CANFrame]:
    """
    Parse ``candump`` text output into a list of ``CANFrame`` objects.

    Supports both standard and timestamped candump formats::

        # Standard:
        vcan0  244   [8]  00 00 00 00 00 00 00 32

        # With -t a (absolute timestamp):
        (1713745890.123456)  vcan0  244   [8]  00 00 00 00 00 00 00 32

        # With -t d (delta timestamp):
        (0.000123)  vcan0  244   [8]  00 00 00 00 00 00 00 32

    Args:
        raw_output: Raw MCP tool result (string, dict envelope, or JSON).

    Returns:
        List of CANFrame objects in capture order.

    Examples::

        frames = parse_candump_output(raw)
        speedometer = [f for f in frames if f.arb_id == "244"]
        speeds = [f.data[7] for f in speedometer]  # byte 7 = speed value
    """
    text = extract_text_payload(raw_output)
    frames: List[CANFrame] = []

    if not text:
        return frames

    # Pattern handles both formats:
    # Optional:  (timestamp)   interface  ID   [DLC]  D0 D1 ... Dn
    frame_re = re.compile(
        r"(?:\((\d+\.\d+)\)\s+)?"         # Optional (timestamp)
        r"(\w+)\s+"                        # interface (e.g. vcan0)
        r"([0-9A-Fa-f]+)\s+"              # arbitration ID
        r"\[(\d)\]\s+"                    # [DLC]
        r"((?:[0-9A-Fa-f]{2}\s*)*)"       # data bytes
    )

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = frame_re.search(line)
        if not m:
            continue

        timestamp_str, interface, arb_id_hex, dlc_str, data_str = m.groups()

        timestamp = float(timestamp_str) if timestamp_str else None
        arb_id = arb_id_hex.upper()
        dlc = int(dlc_str)
        data_hex = data_str.strip()
        data_bytes = [int(b, 16) for b in data_hex.split() if b]

        try:
            arb_id_int = int(arb_id, 16)
        except ValueError:
            continue

        frames.append(CANFrame(
            interface=interface,
            arb_id=arb_id,
            arb_id_int=arb_id_int,
            dlc=dlc,
            data=data_bytes,
            data_hex=data_hex,
            timestamp=timestamp,
        ))

    return frames


@dataclass
class CANTrafficSummary:
    """
    Summary of CAN bus traffic from a capture session.

    Produced by ``summarise_can_traffic``.  Contains baseline statistics
    used by the automotive agent for differential analysis.
    """
    total_frames: int = 0
    unique_ids: List[str] = dc_field(default_factory=list)
    id_frequency: Dict[str, int] = dc_field(default_factory=dict)   # arb_id → frame count
    id_data_samples: Dict[str, List[str]] = dc_field(default_factory=dict)  # arb_id → last 5 data_hex
    capture_duration_s: Optional[float] = None
    frames_per_second: Optional[float] = None


def summarise_can_traffic(frames: List[CANFrame]) -> CANTrafficSummary:
    """
    Aggregate a list of ``CANFrame`` objects into a ``CANTrafficSummary``.

    Computes:
    - Total frame count
    - Unique arbitration IDs (sorted by frequency)
    - Per-ID frame frequency
    - Up to 5 most recent data payloads per ID (for pattern detection)
    - Estimated frames-per-second from timestamp range

    Args:
        frames: List of CANFrame objects from ``parse_candump_output``.

    Returns:
        CANTrafficSummary with aggregated statistics.

    Examples::

        summary = summarise_can_traffic(frames)
        summary.unique_ids          # ["188", "244", "19B"]
        summary.id_frequency["244"] # 87 (most common = speedometer)
    """
    summary = CANTrafficSummary(total_frames=len(frames))

    freq: Dict[str, int] = {}
    samples: Dict[str, List[str]] = {}

    for frame in frames:
        fid = frame.arb_id
        freq[fid] = freq.get(fid, 0) + 1
        if fid not in samples:
            samples[fid] = []
        samples[fid].append(frame.data_hex)
        # Keep only last 5 samples per ID
        if len(samples[fid]) > 5:
            samples[fid] = samples[fid][-5:]

    summary.id_frequency = dict(sorted(freq.items(), key=lambda x: -x[1]))
    summary.unique_ids = list(summary.id_frequency.keys())
    summary.id_data_samples = samples

    # Estimate FPS from timestamp range
    timed = [f for f in frames if f.timestamp is not None]
    if len(timed) >= 2:
        duration = timed[-1].timestamp - timed[0].timestamp  # type: ignore[operator]
        if duration > 0:
            summary.capture_duration_s = duration
            summary.frames_per_second = len(frames) / duration

    return summary


def differential_can_analysis(
    baseline: CANTrafficSummary,
    manipulated: CANTrafficSummary,
) -> Dict[str, Any]:
    """
    Compare a baseline CAN traffic capture to a post-manipulation capture.

    This is the core of the automotive agent's attack validation loop.
    It detects:

    - **New IDs**: arbitration IDs present in manipulated capture but not baseline.
    - **Disappeared IDs**: IDs in baseline that vanished after manipulation.
    - **Frequency changes**: IDs whose frame rate changed significantly (>50%).
    - **Payload changes**: IDs whose data bytes changed between captures.

    All findings include the before/after values so the Supervisor LLM can
    make informed decisions about follow-up actions.

    Args:
        baseline:    Summary from a pre-attack candump capture.
        manipulated: Summary from a post-attack candump capture.

    Returns:
        Dict with keys:
        - ``new_ids``          : List of arb IDs seen only after manipulation.
        - ``disappeared_ids``  : List of arb IDs that stopped transmitting.
        - ``frequency_changes``: Dict of IDs with their before/after rate.
        - ``payload_changes``  : Dict of IDs whose data bytes changed.
        - ``anomaly_score``    : Int 0-100 (higher = more anomalous).
        - ``summary``          : Human-readable summary string.

    Examples::

        diff = differential_can_analysis(baseline, after_speedometer_attack)
        diff["payload_changes"]["244"]
        # {"before": "00 00 00 00 00 00 00 05", "after": "00 00 00 00 00 00 00 FF"}
    """
    baseline_ids = set(baseline.unique_ids)
    manipulated_ids = set(manipulated.unique_ids)

    new_ids = sorted(manipulated_ids - baseline_ids)
    disappeared_ids = sorted(baseline_ids - manipulated_ids)

    frequency_changes: Dict[str, Dict[str, Any]] = {}
    for arb_id in baseline_ids & manipulated_ids:
        before_count = baseline.id_frequency.get(arb_id, 0)
        after_count = manipulated.id_frequency.get(arb_id, 0)
        if before_count > 0:
            change_ratio = abs(after_count - before_count) / before_count
            if change_ratio > 0.5:  # >50% change
                frequency_changes[arb_id] = {
                    "before": before_count,
                    "after": after_count,
                    "change_pct": round(change_ratio * 100, 1),
                }

    payload_changes: Dict[str, Dict[str, str]] = {}
    for arb_id in baseline_ids & manipulated_ids:
        before_samples = baseline.id_data_samples.get(arb_id, [])
        after_samples = manipulated.id_data_samples.get(arb_id, [])
        before_last = before_samples[-1] if before_samples else ""
        after_last = after_samples[-1] if after_samples else ""
        if before_last and after_last and before_last != after_last:
            payload_changes[arb_id] = {
                "before": before_last,
                "after": after_last,
            }

    # Anomaly score: weighted count of anomalies
    anomaly_score = min(
        100,
        len(new_ids) * 10 +
        len(disappeared_ids) * 15 +
        len(frequency_changes) * 8 +
        len(payload_changes) * 12,
    )

    parts = []
    if new_ids:
        parts.append(f"new IDs: {new_ids}")
    if disappeared_ids:
        parts.append(f"missing IDs: {disappeared_ids}")
    if payload_changes:
        parts.append(f"payload changes on IDs: {sorted(payload_changes.keys())}")
    if frequency_changes:
        parts.append(f"frequency anomalies on IDs: {sorted(frequency_changes.keys())}")
    summary_str = "; ".join(parts) if parts else "No difference detected"

    return {
        "new_ids": new_ids,
        "disappeared_ids": disappeared_ids,
        "frequency_changes": frequency_changes,
        "payload_changes": payload_changes,
        "anomaly_score": anomaly_score,
        "summary": summary_str,
    }
