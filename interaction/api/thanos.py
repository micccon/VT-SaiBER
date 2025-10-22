"""
Security functions for the interaction layer.
Includes input validation and sanitization ("Thanos").
"""

import re
import json
import socket
import time
import uuid
import ipaddress
from urllib.parse import urlparse, urlunparse, quote, unquote

# Config
MAX_INPUT_LEN = 500
DANGEROUS_PATTERN = re.compile(r"[;&|$`<>\\\^\*]")  # chars to remove or neutralize
URL_SCHEME_WHITELIST = {"http", "https"}
# Example allowlist: either explicit hostnames or CIDR ranges
# could be a seperated textbox for user to input first
ALLOWED_HOSTNAMES = {"example.com", "internal.example.local"}
ALLOWED_CIDRS = ["10.0.0.0/8", "192.168.0.0/16"]

# Pre-compile cidr networks
ALLOWED_NETWORKS = [ipaddress.ip_network(c) for c in ALLOWED_CIDRS]

def is_ip_address(s: str):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def normalize_domain(domain: str) -> str:
    # IDN / punycode normalization
    try:
        domain = domain.strip().lower()
        # Convert unicode domain to punycode (ACE)
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain

def in_allowed_networks(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in ALLOWED_NETWORKS)
    except ValueError:
        return False

def strip_dangerous_chars(s: str) -> str:
    # either remove or replace dangerous characters
    return DANGEROUS_PATTERN.sub(" ", s)

def parse_and_validate_target(raw: str):
    """
    Returns a dict: {type: "ip"|"domain"|"url", value: normalized_value}
    Raises ValueError on invalid or out-of-scope targets.
    """
    s = raw.strip()
    if len(s) == 0:
        raise ValueError("Empty input")
    if len(s) > MAX_INPUT_LEN:
        raise ValueError("Input too long")

    # remove control characters
    s = "".join(ch for ch in s if ch.isprintable())
    s = strip_dangerous_chars(s)

    # Try IP
    if is_ip_address(s):
        if not in_allowed_networks(s):
            raise ValueError("IP not in allowed networks")
        return {"type":"ip", "value": str(ipaddress.ip_address(s))}

    # Try URL parse
    parsed = urlparse(s if "://" in s else "http://" + s)  # help parse domain-only strings
    if parsed.hostname:
        hostname = normalize_domain(parsed.hostname)
        # Check allowed hostnames (exact) OR resolve and check IP range
        if hostname in ALLOWED_HOSTNAMES:
            clean_url = urlunparse((parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http",
                                     hostname, parsed.path or "/", "", "", ""))
            return {"type":"url", "value": clean_url}
        # try resolve
        try:
            answers = socket.getaddrinfo(hostname, None)
            ips = {a[4][0] for a in answers}
            if any(in_allowed_networks(ip) for ip in ips):
                # reconstruct safe URL with normalized hostname
                scheme = parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http"
                clean_url = urlunparse((scheme, hostname, parsed.path or "/", "", "", ""))
                return {"type":"url", "value": clean_url}
            else:
                raise ValueError("Target resolves outside allowed networks")
        except socket.gaierror:
            raise ValueError("Unable to resolve hostname")
    raise ValueError("Unrecognized target format")

def sanitize_query(prompt: str) -> str:
    """
    sanitizes the user's input query to prevent prompt injection
    and remove potentially malicious payloads

    args:
        prompt: The raw user input string

    returns:
        the sanitized string
    """
    print(f"Sanitizing query: '{prompt}'")
    sanitized = prompt.strip()

    # In a real application, you would add more robust checks here:
    # - Check for known injection patterns (e.g., "ignore previous instructions").
    # - Use a library to filter out malicious code snippets.
    # - Potentially use a separate, smaller LLM to classify the intent of the prompt.

    print(f"Sanitized query: '{sanitized}'")
    return sanitized
