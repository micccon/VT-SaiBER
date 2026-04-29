"""
Unified attackbox MCP server for VT-SaiBER.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

from src.mcp import metasploit_rpc

ARTIFACT_ROOT = pathlib.Path(os.getenv("ATTACKBOX_ARTIFACT_DIR", "/tmp/vt-saiber-artifacts"))
ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT = int(os.getenv("ATTACKBOX_COMMAND_TIMEOUT", "180"))
ATTACKBOX_HOST = os.getenv("ATTACKBOX_MCP_HOST", "0.0.0.0")
ATTACKBOX_PORT = int(os.getenv("ATTACKBOX_MCP_PORT", "8080"))
mcp = FastMCP("vt-saiber-attackbox", host=ATTACKBOX_HOST, port=ATTACKBOX_PORT)


def _timestamp() -> str:
    """Generate a stable UTC timestamp for artifact filenames."""

    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _envelope(
    *,
    status: str,
    summary: str,
    evidence: Any = None,
    artifacts: Optional[List[Dict[str, Any]]] = None,
    raw: Any = None,
    validation: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Wrap tool results in the normalized payload shape expected by the agents."""

    return {
        "status": status,
        "summary": summary,
        "evidence": evidence if evidence is not None else {},
        "artifacts": artifacts or [],
        "raw": raw if raw is not None else {},
        "validation": validation or {
            "outcome": "inconclusive",
            "reason": "Tool did not return structured validation evidence.",
            "details": {},
        },
        "metadata": metadata or {},
    }


def _validation(outcome: str, reason: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Normalize validation truthfulness separately from process status."""

    return {
        "outcome": str(outcome or "inconclusive"),
        "reason": str(reason or ""),
        "details": details or {},
    }


def _validation_from_signal_results(
    results: Iterable[Dict[str, Any]],
    *,
    signal_key: str,
    positive_reason: str,
    negative_reason: str,
) -> Dict[str, Any]:
    """Summarize signal-bearing probe results into a validation verdict."""

    positives = [item for item in results if isinstance(item, dict) and bool(item.get(signal_key))]
    if positives:
        return _validation("positive", positive_reason, {"signal_count": len(positives)})
    return _validation("negative", negative_reason, {"signal_count": 0})


def _artifact(tool_name: str, suffix: str, content: str) -> Optional[Dict[str, Any]]:
    """Persist tool output to disk and return a file artifact reference."""

    if not content:
        return None
    safe_tool = tool_name.replace("/", "_")
    path = ARTIFACT_ROOT / f"{_timestamp()}-{safe_tool}{suffix}"
    path.write_text(content, encoding="utf-8", errors="replace")
    return {
        "type": "file",
        "label": f"{tool_name}{suffix}",
        "path": str(path),
    }


def _which_any(*names: str) -> Optional[str]:
    """Return the first installed executable from the provided candidate names."""

    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _run_shell_command(
    tool_name: str,
    command: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a shell command on the attackbox and normalize its output."""

    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    # Most attackbox tools are simple command wrappers, so we always capture combined stdout/stderr as an artifact.
    artifact = _artifact(tool_name, ".log", "\n".join(part for part in [stdout, stderr] if part).strip())
    status = "success" if completed.returncode == 0 else "error"
    summary = f"{tool_name} completed with exit code {completed.returncode}"
    return _envelope(
        status=status,
        summary=summary,
        evidence={},
        artifacts=[artifact] if artifact else [],
        raw={
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": completed.returncode,
        },
        validation=_validation(
            "inconclusive",
            f"{tool_name} completed, but produced no structured validation claim.",
            {"exit_code": completed.returncode},
        ),
        metadata={"tool": tool_name},
    )


def _parse_nmap_hosts(output: str) -> List[str]:
    """Extract discovered hosts from nmap host-discovery output."""

    hosts: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("nmap scan report for "):
            host = line.split("for ", 1)[1].strip()
            if host:
                hosts.append(host.rsplit(" ", 1)[-1].strip("()"))
    return hosts


def _parse_nmap_services(output: str) -> List[Dict[str, Any]]:
    """Extract open-service records from nmap service-scan output."""

    findings: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) < 3 or "/tcp" not in parts[0] and "/udp" not in parts[0]:
            continue
        state = parts[1].lower()
        if state != "open":
            continue
        port_text, proto = parts[0].split("/", 1)
        service = parts[2]
        version = " ".join(parts[3:]).strip()
        findings.append(
            {
                "port": int(port_text),
                "protocol": proto,
                "service_name": service,
                "version": version or None,
            }
        )
    return findings


def _parse_gobuster(output: str) -> List[Dict[str, Any]]:
    """Extract path/status pairs from gobuster output."""

    findings: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("/"):
            continue
        path = line.split(" ", 1)[0]
        status_code = None
        marker = "Status:"
        if marker in line:
            try:
                status_code = int(line.split(marker, 1)[1].split(")", 1)[0].strip())
            except Exception:
                status_code = None
        findings.append({"path": path, "status_code": status_code})
    return findings


def _normalize_msf_payload(
    tool_name: str,
    payload: Any,
    invocation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Wrap varied Metasploit RPC results in the shared attackbox envelope."""

    if isinstance(payload, list):
        return _envelope(
            status="success",
            summary=f"{tool_name} returned {len(payload)} results",
            evidence={"results": payload},
            raw={"result": payload},
            metadata={"tool": tool_name, "invocation": invocation or {}},
        )

    if not isinstance(payload, dict):
        return _envelope(
            status="error",
            summary=f"{tool_name} returned an unexpected payload",
            raw={"payload": payload},
            metadata={"tool": tool_name, "invocation": invocation or {}},
        )

    status = str(payload.get("status") or ("success" if not payload.get("error") else "error")).lower()
    summary = str(payload.get("message") or payload.get("status") or tool_name)
    artifacts: List[Dict[str, Any]] = []
    for key in ("output", "module_output"):
        text = payload.get(key)
        if isinstance(text, str) and text.strip():
            artifact = _artifact(tool_name, ".log", text)
            if artifact:
                artifacts.append(artifact)

    evidence = {key: value for key, value in payload.items() if key not in {"output", "module_output", "message"}}
    return _envelope(
        status=status,
        summary=summary,
        evidence=evidence,
        artifacts=artifacts,
        raw=payload,
        metadata={"tool": tool_name, "invocation": invocation or {}},
    )


def _build_http_url(url_or_host: str, port: Optional[int] = None, scheme: str = "http") -> str:
    """Normalize host-or-URL inputs into a usable HTTP URL."""

    candidate = str(url_or_host or "").strip()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    if port and port not in {80, 443}:
        return f"{scheme}://{candidate}:{port}"
    return f"{scheme}://{candidate}"


@mcp.tool(name="recon_host_discovery")
async def recon_host_discovery(targets: str, additional_args: str = "") -> Dict[str, Any]:
    """Run host discovery and return discovered hosts in normalized evidence."""

    command = f"nmap -sn {shlex.quote(targets)} {additional_args}".strip()
    result = await asyncio.to_thread(_run_shell_command, "recon_host_discovery", command)
    hosts = _parse_nmap_hosts(str(result["raw"].get("stdout", "")))
    result["summary"] = f"Discovered {len(hosts)} host(s)"
    result["evidence"] = {"hosts": hosts}
    return result


@mcp.tool(name="recon_port_scan")
async def recon_port_scan(
    target: str,
    ports: str = "1-1024",
    additional_args: str = "",
) -> Dict[str, Any]:
    """Run a basic nmap port scan and normalize open-service evidence."""

    command = f"nmap -Pn -p {shlex.quote(ports)} {additional_args} {shlex.quote(target)}".strip()
    result = await asyncio.to_thread(_run_shell_command, "recon_port_scan", command)
    services = _parse_nmap_services(str(result["raw"].get("stdout", "")))
    result["summary"] = f"Identified {len(services)} open service(s)"
    result["evidence"] = {"services": services}
    return result


@mcp.tool(name="recon_service_probe")
async def recon_service_probe(
    target: str,
    ports: str = "1-1024",
    additional_args: str = "",
) -> Dict[str, Any]:
    """Run nmap version probing and normalize service/version evidence."""

    command = f"nmap -Pn -sV -p {shlex.quote(ports)} {additional_args} {shlex.quote(target)}".strip()
    result = await asyncio.to_thread(_run_shell_command, "recon_service_probe", command)
    services = _parse_nmap_services(str(result["raw"].get("stdout", "")))
    result["summary"] = f"Probed {len(services)} service(s)"
    result["evidence"] = {"services": services}
    return result


@mcp.tool(name="recon_banner_grab")
async def recon_banner_grab(target: str, port: int, probe: str = "", timeout: int = 10) -> Dict[str, Any]:
    sock = socket.create_connection((target, int(port)), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if probe:
            sock.sendall(probe.encode("utf-8", errors="replace"))
        banner = sock.recv(4096).decode("utf-8", errors="replace")
    finally:
        sock.close()

    artifact = _artifact("recon_banner_grab", ".txt", banner)
    return _envelope(
        status="success",
        summary=f"Captured banner from {target}:{port}",
        evidence={"target": target, "port": port, "banner": banner.strip()},
        artifacts=[artifact] if artifact else [],
        raw={"banner": banner},
        metadata={"tool": "recon_banner_grab"},
    )


@mcp.tool(name="recon_http_fingerprint")
async def recon_http_fingerprint(url: str, additional_args: str = "") -> Dict[str, Any]:
    whatweb = _which_any("whatweb")
    if whatweb:
        command = f"{shlex.quote(whatweb)} {additional_args} {shlex.quote(url)}".strip()
        result = await asyncio.to_thread(_run_shell_command, "recon_http_fingerprint", command)
        result["summary"] = f"HTTP fingerprinted {url}"
        return result

    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        response = await client.get(url)
    body = response.text[:4000]
    artifact = _artifact("recon_http_fingerprint", ".html", body)
    return _envelope(
        status="success",
        summary=f"Fetched HTTP fingerprint data from {url}",
        evidence={
            "status_code": response.status_code,
            "server": response.headers.get("server"),
            "powered_by": response.headers.get("x-powered-by"),
            "title_hint": body[:200],
        },
        artifacts=[artifact] if artifact else [],
        raw={"headers": dict(response.headers), "body": body},
        metadata={"tool": "recon_http_fingerprint"},
    )


@mcp.tool(name="web_content_enum")
async def web_content_enum(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> Dict[str, Any]:
    """Run gobuster directory enumeration against a target URL."""

    gobuster = _which_any("gobuster")
    if not gobuster:
        return _envelope(status="error", summary="gobuster is not installed", metadata={"tool": "web_content_enum"})
    command = (
        f"{shlex.quote(gobuster)} dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} "
        f"--no-error {additional_args}"
    ).strip()
    result = await asyncio.to_thread(_run_shell_command, "web_content_enum", command)
    result["summary"] = f"Enumerated web content for {url}"
    result["evidence"] = {"paths": _parse_gobuster(str(result["raw"].get("stdout", "")))}
    return result


@mcp.tool(name="web_vhost_enum")
async def web_vhost_enum(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> Dict[str, Any]:
    gobuster = _which_any("gobuster")
    if not gobuster:
        return _envelope(status="error", summary="gobuster is not installed", metadata={"tool": "web_vhost_enum"})
    host = urlparse(url).hostname or url
    command = (
        f"{shlex.quote(gobuster)} vhost -u {shlex.quote(_build_http_url(host))} "
        f"-w {shlex.quote(wordlist)} {additional_args}"
    ).strip()
    return await asyncio.to_thread(_run_shell_command, "web_vhost_enum", command)


@mcp.tool(name="web_param_discovery")
async def web_param_discovery(url: str, additional_args: str = "") -> Dict[str, Any]:
    arjun = _which_any("arjun")
    if not arjun:
        return _envelope(status="error", summary="arjun is not installed", metadata={"tool": "web_param_discovery"})
    command = f"{shlex.quote(arjun)} -u {shlex.quote(url)} {additional_args}".strip()
    return await asyncio.to_thread(_run_shell_command, "web_param_discovery", command)


@mcp.tool(name="web_waf_detect")
async def web_waf_detect(url: str, additional_args: str = "") -> Dict[str, Any]:
    wafw00f = _which_any("wafw00f")
    if not wafw00f:
        return _envelope(status="error", summary="wafw00f is not installed", metadata={"tool": "web_waf_detect"})
    command = f"{shlex.quote(wafw00f)} {additional_args} {shlex.quote(url)}".strip()
    return await asyncio.to_thread(_run_shell_command, "web_waf_detect", command)


@mcp.tool(name="web_nikto_scan")
async def web_nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
    """Run a Nikto scan and return the raw command envelope."""

    command = f"nikto -h {shlex.quote(target)} {additional_args}".strip()
    return await asyncio.to_thread(_run_shell_command, "web_nikto_scan", command)


@mcp.tool(name="web_http_request")
async def web_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        response = await client.request(
            method.upper(),
            url,
            headers=headers,
            params=params,
            data=data,
            json=json_body,
        )
    body = response.text[:8000]
    artifact = _artifact("web_http_request", ".http", body)
    return _envelope(
        status="success",
        summary=f"{method.upper()} {url} -> {response.status_code}",
        evidence={
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_preview": body[:500],
        },
        artifacts=[artifact] if artifact else [],
        raw={"body": body, "headers": dict(response.headers)},
        metadata={"tool": "web_http_request", "method": method.upper()},
    )


@mcp.tool(name="web_auth_form_probe")
async def web_auth_form_probe(
    url: str,
    username_field: str = "username",
    password_field: str = "password",
    username: str = "admin",
    password: str = "admin",
    method: str = "POST",
    extra_fields: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    payload = dict(extra_fields or {})
    payload[username_field] = username
    payload[password_field] = password
    async with httpx.AsyncClient(follow_redirects=False, timeout=20.0) as client:
        response = await client.request(method.upper(), url, data=payload)
    return _envelope(
        status="success",
        summary=f"Auth form probe returned {response.status_code}",
        evidence={
            "status_code": response.status_code,
            "location": response.headers.get("location"),
            "set_cookie": response.headers.get("set-cookie"),
            "body_preview": response.text[:500],
        },
        raw={"headers": dict(response.headers), "body": response.text[:4000]},
        metadata={"tool": "web_auth_form_probe"},
    )


@mcp.tool(name="web_file_upload_probe")
async def web_file_upload_probe(
    url: str,
    file_field: str = "file",
    filename: str = "probe.txt",
    content: str = "vt-saiber-upload-probe",
    method: str = "POST",
    extra_fields: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    files = {file_field: (filename, content.encode("utf-8"), "text/plain")}
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        response = await client.request(method.upper(), url, data=extra_fields or {}, files=files)
    return _envelope(
        status="success",
        summary=f"Upload probe returned {response.status_code}",
        evidence={
            "status_code": response.status_code,
            "body_preview": response.text[:500],
        },
        raw={"headers": dict(response.headers), "body": response.text[:4000]},
        metadata={"tool": "web_file_upload_probe"},
    )


@mcp.tool(name="web_idor_probe")
async def web_idor_probe(
    url_template: str,
    object_ids: List[str],
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    observations: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        for object_id in object_ids:
            url = url_template.format(object_id=object_id)
            response = await client.request(method.upper(), url, headers=headers)
            observations.append(
                {
                    "object_id": object_id,
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.text),
                }
            )
    return _envelope(
        status="success",
        summary=f"Probed {len(observations)} object identifiers",
        evidence={"observations": observations},
        raw={"observations": observations},
        metadata={"tool": "web_idor_probe"},
    )


@mcp.tool(name="web_sqlmap_scan")
async def web_sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
    command = f"sqlmap -u {shlex.quote(url)} --batch {additional_args}"
    if data:
        command += f" --data {shlex.quote(data)}"
    return await asyncio.to_thread(_run_shell_command, "web_sqlmap_scan", command)


@mcp.tool(name="web_command_injection_probe")
async def web_command_injection_probe(
    url: str,
    param_name: str,
    method: str = "GET",
    base_params: Optional[Dict[str, str]] = None,
    payloads: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payloads = payloads or [";id", "|id", "&&id"]
    findings: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        for payload in payloads:
            params = dict(base_params or {})
            params[param_name] = payload
            response = await client.request(method.upper(), url, params=params if method.upper() == "GET" else None, data=params if method.upper() != "GET" else None)
            body = response.text[:2000]
            findings.append(
                {
                    "payload": payload,
                    "status_code": response.status_code,
                    "body_preview": body[:200],
                    "possible_signal": "uid=" in body or "gid=" in body,
                }
            )
    return _envelope(
        status="success",
        summary=f"Sent {len(findings)} command injection probe(s)",
        evidence={"payload_results": findings},
        raw={"payload_results": findings},
        validation=_validation_from_signal_results(
            findings,
            signal_key="possible_signal",
            positive_reason="Command injection probe observed command-execution output.",
            negative_reason="Command injection probe found no command-execution signal.",
        ),
        metadata={"tool": "web_command_injection_probe"},
    )


@mcp.tool(name="web_traversal_probe")
async def web_traversal_probe(
    url: str,
    param_name: str,
    method: str = "GET",
    base_params: Optional[Dict[str, str]] = None,
    payloads: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payloads = payloads or ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    findings: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        for payload in payloads:
            params = dict(base_params or {})
            params[param_name] = payload
            response = await client.request(method.upper(), url, params=params if method.upper() == "GET" else None, data=params if method.upper() != "GET" else None)
            body = response.text[:2000]
            findings.append(
                {
                    "payload": payload,
                    "status_code": response.status_code,
                    "body_preview": body[:200],
                    "possible_signal": "root:x:" in body or "[fonts]" in body.lower(),
                }
            )
    return _envelope(
        status="success",
        summary=f"Sent {len(findings)} traversal probe(s)",
        evidence={"payload_results": findings},
        raw={"payload_results": findings},
        validation=_validation_from_signal_results(
            findings,
            signal_key="possible_signal",
            positive_reason="Traversal probe observed file-disclosure output.",
            negative_reason="Traversal probe found no file-disclosure signal.",
        ),
        metadata={"tool": "web_traversal_probe"},
    )


@mcp.tool(name="web_wordpress_scan")
async def web_wordpress_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
    command = f"wpscan --url {shlex.quote(url)} --no-update {additional_args}".strip()
    return await asyncio.to_thread(_run_shell_command, "web_wordpress_scan", command)


@mcp.tool(name="access_hydra_attack")
async def access_hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    additional_args: str = "",
) -> Dict[str, Any]:
    parts = ["hydra"]
    if username:
        parts.extend(["-l", shlex.quote(username)])
    if username_file:
        parts.extend(["-L", shlex.quote(username_file)])
    if password:
        parts.extend(["-p", shlex.quote(password)])
    if password_file:
        parts.extend(["-P", shlex.quote(password_file)])
    parts.append(shlex.quote(target))
    parts.append(shlex.quote(service))
    command = " ".join(parts + [additional_args]).strip()
    return await asyncio.to_thread(_run_shell_command, "access_hydra_attack", command)


@mcp.tool(name="access_john_crack")
async def access_john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format_type: str = "",
    additional_args: str = "",
) -> Dict[str, Any]:
    command = f"john --wordlist={shlex.quote(wordlist)} {shlex.quote(hash_file)}"
    if format_type:
        command += f" --format={shlex.quote(format_type)}"
    if additional_args:
        command += f" {additional_args}"
    return await asyncio.to_thread(_run_shell_command, "access_john_crack", command)


def _ssh_base_command(host: str, username: str, port: int, password: str = "", identity_file: str = "", additional_args: str = "") -> str:
    ssh_bin = _which_any("ssh")
    if not ssh_bin:
        raise RuntimeError("ssh is not installed")
    parts = []
    if password:
        sshpass = _which_any("sshpass")
        if not sshpass:
            raise RuntimeError("sshpass is required for password-based SSH operations")
        parts.extend([shlex.quote(sshpass), "-p", shlex.quote(password)])
    parts.extend(
        [
            shlex.quote(ssh_bin),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            str(int(port)),
        ]
    )
    if identity_file:
        parts.extend(["-i", shlex.quote(identity_file)])
    if additional_args:
        parts.append(additional_args)
    parts.append(shlex.quote(f"{username}@{host}"))
    return " ".join(parts)


@mcp.tool(name="access_ssh_login")
async def access_ssh_login(
    host: str,
    username: str,
    password: str = "",
    port: int = 22,
    identity_file: str = "",
    additional_args: str = "",
) -> Dict[str, Any]:
    command = _ssh_base_command(host, username, port, password, identity_file, additional_args) + " true"
    result = await asyncio.to_thread(_run_shell_command, "access_ssh_login", command)
    result["summary"] = f"SSH login {'succeeded' if result['status'] == 'success' else 'failed'} for {username}@{host}:{port}"
    return result


@mcp.tool(name="access_ssh_command")
async def access_ssh_command(
    host: str,
    username: str,
    command: str,
    password: str = "",
    port: int = 22,
    identity_file: str = "",
    additional_args: str = "",
) -> Dict[str, Any]:
    remote = _ssh_base_command(host, username, port, password, identity_file, additional_args)
    full_command = f"{remote} {shlex.quote(command)}"
    return await asyncio.to_thread(_run_shell_command, "access_ssh_command", full_command)


@mcp.tool(name="access_smb_enum")
async def access_smb_enum(target: str, additional_args: str = "") -> Dict[str, Any]:
    enum_bin = _which_any("enum4linux-ng", "enum4linux")
    if not enum_bin:
        return _envelope(status="error", summary="enum4linux-ng/enum4linux is not installed", metadata={"tool": "access_smb_enum"})
    command = f"{shlex.quote(enum_bin)} {additional_args} {shlex.quote(target)}".strip()
    return await asyncio.to_thread(_run_shell_command, "access_smb_enum", command)


@mcp.tool(name="msf_search_modules")
async def msf_search_modules(search_term: str, module_type: str = "all") -> Dict[str, Any]:
    """Search the local Metasploit module inventory without executing anything."""

    client = metasploit_rpc.get_msf_client()
    requested = str(module_type or "all").strip().lower()
    module_sources = [
        ("exploit", getattr(client.modules, "exploits", [])),
        ("auxiliary", getattr(client.modules, "auxiliary", [])),
        ("post", getattr(client.modules, "post", [])),
    ]
    results: List[str] = []
    term = search_term.strip().lower()
    for prefix, modules in module_sources:
        if requested not in {"all", prefix, f"{prefix}s"}:
            continue
        for module_name in list(modules):
            candidate = str(module_name).strip()
            haystack = f"{prefix}/{candidate}".lower()
            if not term or term in haystack:
                results.append(f"{prefix}/{candidate}")
    return _normalize_msf_payload(
        "msf_search_modules",
        results[:100],
        {"search_term": search_term, "module_type": module_type},
    )


@mcp.tool(name="msf_get_module_info")
async def msf_get_module_info(module_type: str, module_name: str) -> Dict[str, Any]:
    payload = await metasploit_rpc.get_module_info(module_type=module_type, module_name=module_name)
    return _normalize_msf_payload("msf_get_module_info", payload, {"module_type": module_type, "module_name": module_name})


@mcp.tool(name="msf_get_module_options")
async def msf_get_module_options(
    module_type: str,
    module_name: str,
    search: Optional[str] = None,
    advanced: bool = False,
) -> Dict[str, Any]:
    payload = await metasploit_rpc.get_module_options(
        module_type=module_type,
        module_name=module_name,
        search=search,
        advanced=advanced,
    )
    return _normalize_msf_payload(
        "msf_get_module_options",
        payload,
        {
            "module_type": module_type,
            "module_name": module_name,
            "search": search,
            "advanced": advanced,
        },
    )


@mcp.tool(name="msf_run_exploit")
async def msf_run_exploit(
    module_name: str,
    options: Optional[Dict[str, Any]] = None,
    payload_name: str = "",
    payload_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute a Metasploit exploit via the shared RPC wrapper."""

    payload = await metasploit_rpc.run_exploit(
        module_name=module_name,
        options=options or {},
        payload_name=payload_name,
        payload_options=payload_options or {},
    )
    return _normalize_msf_payload(
        "msf_run_exploit",
        payload,
        {
            "module_name": module_name,
            "options": options or {},
            "payload_name": payload_name,
            "payload_options": payload_options or {},
        },
    )


@mcp.tool(name="msf_run_auxiliary")
async def msf_run_auxiliary(module_name: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a Metasploit auxiliary module via the shared RPC wrapper."""

    payload = await metasploit_rpc.run_auxiliary_module(module_name=module_name, options=options or {})
    return _normalize_msf_payload(
        "msf_run_auxiliary",
        payload,
        {"module_name": module_name, "options": options or {}},
    )


@mcp.tool(name="msf_run_post")
async def msf_run_post(module_name: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a Metasploit post module via the shared RPC wrapper."""

    payload = await metasploit_rpc.run_post_module(module_name=module_name, options=options or {})
    return _normalize_msf_payload(
        "msf_run_post",
        payload,
        {"module_name": module_name, "options": options or {}},
    )


@mcp.tool(name="msf_list_sessions")
async def msf_list_sessions() -> Dict[str, Any]:
    """Return the normalized live-session inventory from Metasploit."""

    payload = await metasploit_rpc.list_active_sessions()
    return _normalize_msf_payload("msf_list_sessions", payload, {})


@mcp.tool(name="msf_session_command")
async def msf_session_command(session_id: int, command: str) -> Dict[str, Any]:
    """Run a command inside a validated Metasploit session."""

    payload = await metasploit_rpc.send_session_command(session_id=session_id, command=command)
    return _normalize_msf_payload("msf_session_command", payload, {"session_id": session_id, "command": command})


@mcp.tool(name="msf_start_listener")
async def msf_start_listener(
    payload_type: str,
    lhost: str,
    lport: int,
    additional_options: Optional[Dict[str, Any]] = None,
    exit_on_session: bool = False,
) -> Dict[str, Any]:
    payload = await metasploit_rpc.start_listener(
        payload_type=payload_type,
        lhost=lhost,
        lport=lport,
        additional_options=additional_options or {},
        exit_on_session=exit_on_session,
    )
    return _normalize_msf_payload(
        "msf_start_listener",
        payload,
        {
            "payload_type": payload_type,
            "lhost": lhost,
            "lport": lport,
            "additional_options": additional_options or {},
            "exit_on_session": exit_on_session,
        },
    )


@mcp.tool(name="msf_terminate_session")
async def msf_terminate_session(session_id: int) -> Dict[str, Any]:
    """Terminate a live Metasploit session through the RPC wrapper."""

    payload = await metasploit_rpc.terminate_session(session_id=session_id)
    return _normalize_msf_payload("msf_terminate_session", payload, {"session_id": session_id})


@mcp.tool(name="system_execute_command")
async def system_execute_command(command: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Run a precise shell command on the attackbox host itself."""

    return await asyncio.to_thread(_run_shell_command, "system_execute_command", command, timeout=timeout)


def main() -> None:
    """Process entrypoint for the unified attackbox MCP server."""

    try:
        metasploit_rpc.initialize_msf_client()
    except Exception as exc:
        # The server can still start so non-Metasploit tools remain usable.
        print(f"[attackbox] Warning: Metasploit RPC initialization failed: {exc}")

    transport = os.getenv("ATTACKBOX_MCP_TRANSPORT", "streamable-http").strip()
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
