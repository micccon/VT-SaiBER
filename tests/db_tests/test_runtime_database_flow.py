from __future__ import annotations

from src.database.activity_repository import get_agent_logs_by_mission
from src.database.attack_chain_repository import get_attack_chain_by_mission
from src.database.connection import test_connection as db_test_connection
from src.database.findings_store import create_finding, get_findings_by_mission
from src.database.persistence import persist_state_update
from src.database.sessions_repository import get_sessions_by_mission, upsert_session
from src.database.targets_repository import (
    get_services_by_mission,
    get_target_info,
    get_targets_by_mission,
    replace_services_for_target,
    upsert_target,
)


def test_db_connection_smoke() -> None:
    row = db_test_connection()
    print(f"[db] connection smoke row={row}")
    assert row["ok"] == 1


def test_target_service_session_round_trip(mission_id: str) -> None:
    target = upsert_target(
        mission_id=mission_id,
        ip_address="10.20.30.40",
        mac_address="AA:BB:CC:DD:EE:FF",
        os_guess="Linux",
        hostname="integration-target",
    )
    print(f"[db] inserted target id={target['id']} ip=10.20.30.40 mission={mission_id}")

    services = replace_services_for_target(
        target["id"],
        [
            {
                "port": 21,
                "protocol": "tcp",
                "service_name": "ftp",
                "service_version": "vsftpd 2.3.4",
                "banner": "vsFTPd 2.3.4",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
                "service_version": "Apache httpd 2.4.49",
                "banner": "Apache/2.4.49",
            },
        ],
    )
    print(
        "[db] replaced services="
        + ", ".join(f"{svc['service_name']}:{svc['port']}" for svc in services)
    )
    assert len(services) == 2

    finding = create_finding(
        mission_id=mission_id,
        agent_name="scout",
        finding_type="vulnerable_service",
        severity="high",
        target_ip="10.20.30.40",
        target_port=21,
        title="vsftpd 2.3.4 detected",
        description="Classic backdoored vsftpd service fingerprint",
        data={"service": "ftp", "version": "vsftpd 2.3.4"},
        auto_embed=False,
    )
    print(f"[db] created finding id={finding['id']} type=vulnerable_service")
    assert finding["id"] is not None

    session = upsert_session(
        mission_id=mission_id,
        session_id=7,
        target_ip="10.20.30.40",
        target_port=21,
        user_context="root",
        session_type="meterpreter",
        exploit_used="exploit/unix/ftp/vsftpd_234_backdoor",
    )
    print(f"[db] upserted session session_id={session['session_id']} type={session['session_type']}")
    assert session["session_id"] == 7

    target_info = get_target_info(mission_id, "10.20.30.40")
    print(
        "[db] target_info services="
        + ", ".join(f"{svc['service_name']}:{svc['port']}" for svc in target_info["services"])
    )
    assert target_info["target"]["hostname"] == "integration-target"
    assert {service["port"] for service in target_info["services"]} == {21, 80}
    assert target_info["findings"][0]["title"] == "vsftpd 2.3.4 detected"
    assert target_info["sessions"][0]["session_id"] == 7


def test_persist_state_update_writes_deduplicated_runtime_records(mission_id: str) -> None:
    previous_state = {
        "mission_id": mission_id,
        "discovered_targets": {},
        "active_sessions": {},
    }
    updates = {
        "mission_id": mission_id,
        "discovered_targets": {
            "10.10.10.10": {
                "hostname": "demo-target",
                "services": {
                    "21": {
                        "service_name": "ftp",
                        "version": "vsftpd 2.3.4",
                        "banner": "vsFTPd 2.3.4",
                    }
                },
            }
        },
        "web_findings": [
            {
                "path": "/admin",
                "url": "http://10.10.10.10/admin",
                "is_interesting": True,
                "rationale": "Admin console exposed",
            }
        ],
        "intelligence_findings": [
            {
                "source": "librarian",
                "cve": "CVE-2011-2523",
                "description": "vsftpd 2.3.4 likely vulnerable to the backdoored service release.",
                "exploit_available": True,
                "technical_params": {
                    "cve": "CVE-2011-2523",
                    "exploit_module": "exploit/unix/ftp/vsftpd_234_backdoor",
                },
                "citations": [
                    "kb:metasploit_vsftpd_guide.pdf",
                    "cve:https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
                ],
                "confidence": 0.91,
                "is_osint_derived": False,
                "source_types": ["kb", "cve"],
                "source_status": {"kb": "ready", "findings": "empty", "cve": "ready", "osint": "skipped"},
                "degraded_reasons": [],
            }
        ],
        "agent_log": [
            {
                "agent": "supervisor",
                "action": "route_decision",
                "decision": "librarian",
                "reasoning": "Need exploit-path validation before striker.",
                "target": "10.10.10.10",
                "findings": {"specific_goal": "Research exploit path", "confidence_score": 0.88},
                "timestamp": "2026-04-28T12:00:00",
            }
        ],
        "active_sessions": {
            "10.10.10.10": {
                "session_id": 5,
                "user_context": "root",
                "session_type": "meterpreter",
                "module": "exploit/unix/ftp/vsftpd_234_backdoor",
            }
        },
    }

    persist_state_update(previous_state, updates)
    persist_state_update(previous_state, updates)

    targets = get_targets_by_mission(mission_id)
    services = get_services_by_mission(mission_id)
    findings = get_findings_by_mission(mission_id)
    sessions = get_sessions_by_mission(mission_id)
    logs = get_agent_logs_by_mission(mission_id)
    attack_chain = get_attack_chain_by_mission(mission_id)
    print(
        "[db] dedup counts "
        f"targets={len(targets)} services={len(services)} findings={len(findings)} "
        f"sessions={len(sessions)} logs={len(logs)} attack_chain={len(attack_chain)}"
    )

    assert len(targets) == 1
    assert len(services) == 1
    assert len(sessions) == 1
    assert len(logs) == 1
    assert len(attack_chain) == 1

    finding_types = {item["finding_type"] for item in findings}
    assert "web_directory" in finding_types
    assert "intelligence_brief" in finding_types

    intelligence = next(item for item in findings if item["finding_type"] == "intelligence_brief")
    data = intelligence["data"] or {}
    print(
        "[db] intelligence brief "
        f"cve={data.get('cve')} source_types={data.get('source_types')} "
        f"status={data.get('source_status')}"
    )
    assert data["cve"] == "CVE-2011-2523"
    assert data["source_types"] == ["kb", "cve"]
    assert data["source_status"]["cve"] == "ready"
