#!/usr/bin/env python3
"""
Unit checks for Kali MCP nmap tuning.

Run inside the agents container:
    python -m pytest tests/mcp_tests/test_kali_mcp_server_tuning.py -q
"""

import sys

sys.path.insert(0, "/app")

from src.mcp.kali_mcp_server import _tune_nmap_additional_args


def test_automotive_protocol_ports_enable_light_version_profile():
    tuned = _tune_nmap_additional_args(
        target="10.0.0.5",
        scan_type="-sV",
        ports="22,9555,9556",
        additional_args="-T4",
    )
    assert "--version-light" in tuned
    assert "--max-retries 1" in tuned
    assert "-T4" in tuned


def test_automotive_hostname_enable_light_version_profile_without_ports():
    tuned = _tune_nmap_additional_args(
        target="automotive-testbed",
        scan_type="-sV",
        ports="",
        additional_args="",
    )
    assert "--version-light" in tuned
    assert "--max-retries 1" in tuned


def test_existing_version_tuning_is_preserved():
    tuned = _tune_nmap_additional_args(
        target="automotive-testbed",
        scan_type="-sV",
        ports="9555",
        additional_args="-T4 --version-all --max-retries 3",
    )
    assert "--version-light" not in tuned
    assert "--version-all" in tuned
    assert "--max-retries 1" not in tuned
    assert "--max-retries 3" in tuned


def test_non_automotive_scan_is_unchanged():
    tuned = _tune_nmap_additional_args(
        target="example-host",
        scan_type="-sV",
        ports="22,80,443",
        additional_args="-T4",
    )
    assert tuned == "-T4"


def test_non_version_scan_is_unchanged():
    tuned = _tune_nmap_additional_args(
        target="automotive-testbed",
        scan_type="-sn",
        ports="9555",
        additional_args="-T4",
    )
    assert tuned == "-T4"
