from src.database.manager import (
    test_connection,
    # targets
    create_target,
    get_targets,
    # services
    create_service,
    get_services_by_target,
    # findings
    create_finding,
    get_findings_by_mission,
    # agent logs
    create_agent_log,
    get_agent_logs_by_mission,
)


def test_db_connection():
    row = test_connection()
    assert row["ok"] == 1


def test_create_and_read_target():
    created = create_target(
        mission_id="mission-001",
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:FF",
        os_guess="Linux",
        hostname="pytest-target",
    )
    assert created["id"] is not None
    assert created["mission_id"] == "mission-001"
    assert created["ip_address"] == "192.168.1.50"

    targets = get_targets()
    assert any(t["id"] == created["id"] for t in targets)


def test_create_and_read_service():
    target = create_target(
        mission_id="mission-002",
        ip_address="192.168.1.51",
        hostname="service-target",
    )

    service = create_service(
        target_id=target["id"],
        port=80,
        protocol="tcp",
        service_name="http",
        service_version="nginx",
        banner="dummy-banner",
    )
    assert service["id"] is not None
    assert service["target_id"] == target["id"]
    assert service["port"] == 80

    services = get_services_by_target(target["id"])
    assert any(s["id"] == service["id"] for s in services)


def test_create_and_read_finding():
    mission_id = "mission-003"

    finding = create_finding(
        mission_id=mission_id,
        agent_name="scout",
        finding_type="vulnerable_service",
        severity="high",
        target_ip="192.168.1.52",
        target_port=21,
        title="pytest finding",
        description="created in test_create_and_read_finding",
        data={"service": "ftp", "version": "vsftpd 2.3.4"},
    )
    assert finding["id"] is not None
    assert finding["mission_id"] == mission_id
    assert finding["severity"] == "high"

    findings = get_findings_by_mission(mission_id)
    assert any(f["id"] == finding["id"] for f in findings)


def test_create_and_read_agent_log():
    mission_id = "mission-004"

    log = create_agent_log(
        mission_id=mission_id,
        agent_name="scout",
        action="nmap_scan",
        reasoning="pytest reasoning",
        result_summary="found open ports",
        details={"ports_found": [22, 80]},
    )
    assert log["id"] is not None
    assert log["mission_id"] == mission_id
    assert log["agent_name"] == "scout"

    logs = get_agent_logs_by_mission(mission_id)
    assert any(l["id"] == log["id"] for l in logs)
