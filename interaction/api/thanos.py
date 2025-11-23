"""
Security functions for the interaction layer.
Includes input validation and sanitization ("Thanos").
"""

import re
import json
import socket
import ipaddress
import logging
from urllib.parse import urlparse, urlunparse

# Configs
MAX_INPUT_LEN = 500
DANGEROUS_PATTERN = re.compile(r"[;&|$`<>\\\^\*]")
URL_SCHEME_WHITELIST = {"http", "https"}
ALLOWED_HOSTNAMES = {"example.com", "internal.example.local"}
ALLOWED_CIDRS = ["10.0.0.0/8", "192.168.0.0/16"]
ALLOWED_NETWORKS = [ipaddress.ip_network(c) for c in ALLOWED_CIDRS]

logging.basicConfig(
    filename="./database/logger/input_validation.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def strip_dangerous_chars(s: str) -> str:
    return DANGEROUS_PATTERN.sub(" ", s)

def normalize_domain(domain: str) -> str:
    try:
        return domain.strip().lower().encode("idna").decode("ascii")
    except Exception:
        return domain

def is_ip_address(s: str):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def in_allowed_networks(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in ALLOWED_NETWORKS)
    except ValueError:
        return False

def validate_target(target: str):
    """Single IP/hostname/url validation and sanitization."""
    t = strip_dangerous_chars(target.strip())
    if is_ip_address(t) and in_allowed_networks(t):
        return {"type": "ip", "value": str(ipaddress.ip_address(t)), "raw": target}
    parsed = urlparse(t if "://" in t else "http://" + t)
    if parsed.hostname:
        hostname = normalize_domain(parsed.hostname)
        if hostname in ALLOWED_HOSTNAMES:
            scheme = parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http"
            clean_url = urlunparse((scheme, hostname, parsed.path or "/", "", "", ""))
            return {"type": "url", "value": clean_url, "raw": target}
        # Try resolve to allowed IP
        try:
            answers = socket.getaddrinfo(hostname, None)
            ips = {a[4][0] for a in answers}
            if any(in_allowed_networks(ip) for ip in ips):
                scheme = parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http"
                clean_url = urlunparse((scheme, hostname, parsed.path or "/", "", "", ""))
                return {"type": "url", "value": clean_url, "raw": target}
            else:
                raise ValueError("Resolved IP not allowed")
        except Exception:
            raise ValueError("Unable to resolve hostname")
    raise ValueError("Unrecognized target format")

def process_user_input(raw_input: str, output_context: str = "json"):
    """
    Accept free-form user input. Extract target(s), action, port(s), 
    validate targets, and return structure for downstream usage.
    """
    s = (raw_input or "").strip()

    # Result template
    result = {
        "raw": s,
        "action": "general",
        "targets": [],
        "ports": [],
        "sanitized_targets": [],
        "validation_errors": []
    }
    
    # Quick input checks
    if not s:
        result["validation_errors"].append("empty input")
        return json.dumps(result) if output_context == "json" else result
    if len(s) > MAX_INPUT_LEN:
        result["validation_errors"].append("input too long")
        return json.dumps(result) if output_context == "json" else result
    if not all(ch.isprintable() for ch in s):
        result["validation_errors"].append("non-printable characters")
        return json.dumps(result) if output_context == "json" else result

    s_safe = strip_dangerous_chars(s)
    
    # Infer action
    lower = s_safe.lower()
    if "port" in lower and "scan" in lower:
        result["action"] = "port_scan"
    elif "service" in lower or "version" in lower:
        result["action"] = "service_scan"
    elif "ping" in lower:
        result["action"] = "ping_scan"
    elif "scan" in lower:
        result["action"] = "quick_scan"

    # Extract IP & hostnames/domains
    ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    host_pattern = re.compile(r"\b([a-zA-Z0-9\-_.]+\.[a-zA-Z]{2,})\b")
    ips = ip_pattern.findall(s_safe)
    hosts = host_pattern.findall(s_safe)

    # Merge unique targets
    seen = set()
    for t in ips + hosts:
        if t not in seen:
            seen.add(t)
            result["targets"].append(t)

    # Extract ports (matches 'port 22', 'ports 80,443')
    ports_pattern = re.compile(r"ports?\s*[:=]?\s*([0-9,\s]+)", re.IGNORECASE)
    m = ports_pattern.search(s_safe)
    if m:
        result["ports"] = [p for p in re.split(r"[,\s]+", m.group(1)) if p.isdigit()]

    # Validate targets
    for t in result["targets"]:
        try:
            val = validate_target(t)
            result["sanitized_targets"].append(val)
        except Exception as e:
            result["validation_errors"].append(f"{t}: {e}")

    # If no targets found, try tokens
    if not result["targets"]:
        tokens = re.split(r"\s+", s_safe)
        for tok in tokens:
            if ip_pattern.fullmatch(tok) or host_pattern.fullmatch(tok):
                try:
                    val = validate_target(tok)
                    if tok not in result["targets"]:
                        result["targets"].append(tok)
                        result["sanitized_targets"].append(val)
                except Exception as e:
                    result["validation_errors"].append(f"{tok}: {e}")

    return json.dumps(result) if output_context == "json" else result

# Simple demo
if __name__ == "__main__":
    EXAMPLES = [
        "192.168.0.10",
        "example.com",
        "http://internal.example.local/test",
        "scan badhost.com for port 22",
        "scan 10.0.0.8 ports 22,443",
        "quick scan 123.123.123.123",
        "please check 1.2.3.4; rm -rf /",
        "<script>alert('XSS')</script>",
        "ports 80,8080 on 192.168.1.1"
    ]
    for inp in EXAMPLES:
        res = process_user_input(inp, output_context="json")
        print(f"{inp} ->\n{res}\n")
