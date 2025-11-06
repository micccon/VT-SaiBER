"""
Security functions for the interaction layer.
Includes input validation and sanitization ("Thanos").
"""

import re
import json
import socket
import ipaddress
import logging
from urllib.parse import urlparse, urlunparse, quote, unquote

# Configs
MAX_INPUT_LEN = 500
# validation
DANGEROUS_PATTERN = re.compile(r"[;&|$`<>\\\^\*]")  
URL_SCHEME_WHITELIST = {"http", "https"}


# Example allowlist: either explicit hostnames or CIDR ranges
# could be a seperated textbox for user to input first
ALLOWED_HOSTNAMES = {"example.com", "internal.example.local"}
ALLOWED_CIDRS = ["10.0.0.0/8", "192.168.0.0/16"]
ALLOWED_NETWORKS = [ipaddress.ip_network(c) for c in ALLOWED_CIDRS]

logging.basicConfig(filename="./database/logger/input_validation.log", 
                    level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

def is_ip_address(s: str):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def normalize_domain(domain: str) -> str:
    try:
        domain = domain.strip().lower()
        # Convert unicode domain to punycode (ACE) to ensure system understand text
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
    return DANGEROUS_PATTERN.sub(" ", s)


def validate_input(prompt: str):
    """
    Validate raw user input.
    Only allow IP/domain/URL, in allowed hosts/networks, length and printable.
    """
    s = prompt.strip()
    if len(s) == 0:
        logging.warning("Empty input")
        raise ValueError("Empty input")
    if len(s) > MAX_INPUT_LEN:
        logging.warning(f"Too long input: {len(s)} chars")
        raise ValueError("Input too long")
    if not all(ch.isprintable() for ch in s):
        logging.warning("Non-printable char detected")
        raise ValueError("Contains non-printable character")
    s = strip_dangerous_chars(s)

    # IP
    if is_ip_address(s) and in_allowed_networks(s):
        return {"type": "ip", "value": str(ipaddress.ip_address(s))}

    # URL/domain 
    parsed = urlparse(s if "://" in s else "http://" + s)
    if parsed.hostname:
        hostname = normalize_domain(parsed.hostname)
        if hostname in ALLOWED_HOSTNAMES:
            scheme = parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http"
            clean_url = urlunparse((scheme, hostname, parsed.path or "/", "", "", ""))
            return {"type": "url", "value": clean_url}
        # Hostname not allowed, check IP
        try:
            answers = socket.getaddrinfo(hostname, None)
            ips = {a[4][0] for a in answers}
            if any(in_allowed_networks(ip) for ip in ips):
                scheme = parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http"
                clean_url = urlunparse((scheme, hostname, parsed.path or "/", "", "", ""))
                return {"type": "url", "value": clean_url}
            else:
                logging.warning("Resolved IP outside allowed networks")
                raise ValueError("Resolved IP not allowed")
        except socket.gaierror:
            logging.error(f"Host resolve failed: {hostname}")
            raise ValueError("Unable to resolve hostname")
    logging.warning("Unrecognized input format")
    raise ValueError("Unrecognized input format")

def sanitize_for_context(data: str, context: str) -> str:
    if context == "json":
        return json.dumps(data)
    else:
        return strip_dangerous_chars(data)

# Validate and Sanitize
def process_user_input(raw_input: str, output_context: str):
    try:
        valid = validate_input(raw_input)
        safe = sanitize_for_context(valid["value"], output_context)
        logging.info(f"Processed input: {safe}")
        return safe
    except Exception as e:
        logging.error(f"User input error: {e}")
        raise

# Example test main
if __name__ == "__main__":
    EXAMPLES = [
        "192.168.0.10",
        "example.com",
        "http://internal.example.local/test",
        "badhost.com",
        "123.123.123.123",
        "Hello world!",
        "<script>alert('XSS')</script>",
        "1.2.3.4; rm -rf /"
    ]

    for inp in EXAMPLES:
        try:
            result = process_user_input(inp, "json")
            print(f"OK: {inp} -> {result}")
        except Exception as ex:
            print(f"FAIL: {inp} -> {ex}")


# def sanitize_query(prompt: str):
#     """
#     sanitizes the user's input query to prevent prompt injection
#     raises ValueError on invalid or out-of-scope targets.

#     args:
#         prompt: The raw user input string

#     returns:
#         the sanitized dict: {type: "ip"|"domain"|"url", value: normalized_value}
#     """
#     print(f"Sanitizing query: '{prompt}'")
#     s = prompt.strip()
#     if len(s) == 0:
#         raise ValueError("Empty input")
#     if len(s) > MAX_INPUT_LEN:
#         raise ValueError("Input too long")

#     # remove control characters
#     s = "".join(ch for ch in s if ch.isprintable())
#     s = strip_dangerous_chars(s)

#     # Try IP
#     if is_ip_address(s):
#         if not in_allowed_networks(s):
#             raise ValueError("IP not in allowed networks")
#         return {"type":"ip", "value": str(ipaddress.ip_address(s))}

#     # Try URL parse
#     # help parse domain-only strings
#     parsed = urlparse(s if "://" in s else "http://" + s)  
#     if parsed.hostname:
#         hostname = normalize_domain(parsed.hostname)
#         # Check allowed hostnames (exact) OR resolve and check IP range
#         if hostname in ALLOWED_HOSTNAMES:
#             clean_url = urlunparse((parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http",
#                                      hostname, parsed.path or "/", "", "", ""))
#             return {"type":"url", "value": clean_url}
#         # try resolve when not in ALLOWED_HOSTNAMES Whitelist
#         try:
#             answers = socket.getaddrinfo(hostname, None)
#             ips = {a[4][0] for a in answers}
#             if any(in_allowed_networks(ip) for ip in ips):
#                 # reconstruct safe URL with normalized hostname
#                 scheme = parsed.scheme if parsed.scheme in URL_SCHEME_WHITELIST else "http"
#                 clean_url = urlunparse((scheme, hostname, parsed.path or "/", "", "", ""))
#                 return {"type":"url", "value": clean_url}
#             else:
#                 raise ValueError("Target resolves outside allowed networks")
#         except socket.gaierror:
#             raise ValueError("Unable to resolve hostname")
#     raise ValueError("Unrecognized target format")
