from src.database.manager import (
    create_target,
    create_service,
    create_finding,
    create_agent_log,
    get_target_info,
)


def test_get_target_info():
    mission_id = "mission-010"
    ip = "10.0.0.10"

    # 建立 target
    target = create_target(
        mission_id=mission_id,
        ip_address=ip,
        hostname="info-target",
    )

    # 建立一筆 service
    create_service(
        target_id=target["id"],
        port=80,
        protocol="tcp",
        service_name="http",
        service_version="nginx",
        banner="pytest-banner",
    )

    # 建立一筆 finding
    create_finding(
        mission_id=mission_id,
        agent_name="scout",
        finding_type="web_directory",
        severity="high",
        target_ip=ip,
        target_port=80,
        title="pytest finding",
        description="desc",
        data={"k": "v"},
    )

    # 建立一筆 agent_log（不是必須，但看看聚合有沒有壞）
    create_agent_log(
        mission_id=mission_id,
        agent_name="scout",
        action="nmap_scan",
        reasoning="pytest",
        result_summary="ok",
        details={"ports_found": [80]},
    )

    info = get_target_info(mission_id, ip)

    assert info["target"] is not None
    assert info["target"]["ip_address"] == ip
    assert len(info["services"]) >= 1
    assert len(info["findings"]) >= 1
    # sessions 如果還沒插入，就不強制檢查長度
