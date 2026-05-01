from __future__ import annotations

import json
from pathlib import Path

from src.database.attack_chain_repository import create_attack_chain_step
from src.database.findings_repository import create_finding
from src.database.reporting.exporter import export_mission_bundle
from src.database.sessions_repository import upsert_session
from src.database.targets_repository import replace_services_for_target, upsert_target


def test_export_bundle_includes_librarian_provenance(mission_id: str, report_output_dir: Path) -> None:
    target = upsert_target(
        mission_id=mission_id,
        ip_address="10.77.0.5",
        hostname="report-target",
        os_guess="Linux",
    )
    replace_services_for_target(
        target["id"],
        [
            {
                "port": 21,
                "protocol": "tcp",
                "service_name": "ftp",
                "service_version": "vsftpd 2.3.4",
                "banner": "vsFTPd 2.3.4",
            }
        ],
    )
    create_finding(
        mission_id=mission_id,
        agent_name="librarian",
        finding_type="intelligence_brief",
        severity="high",
        target_ip="10.77.0.5",
        target_port=21,
        title="vsftpd 2.3.4 exploit path",
        description="Likely exploitable via the backdoored vsftpd release.",
        data={
            "cve": "CVE-2011-2523",
            "confidence": 0.93,
            "source_types": ["kb", "cve"],
            "degraded_reasons": [],
            "technical_params": {"exploit_module": "exploit/unix/ftp/vsftpd_234_backdoor"},
        },
        auto_embed=False,
    )
    upsert_session(
        mission_id=mission_id,
        session_id=12,
        target_ip="10.77.0.5",
        target_port=21,
        user_context="root",
        session_type="meterpreter",
        exploit_used="exploit/unix/ftp/vsftpd_234_backdoor",
    )
    create_attack_chain_step(
        mission_id=mission_id,
        agent_name="striker",
        action="run_exploit",
        target="10.77.0.5:21",
        outcome="success",
    )

    written = export_mission_bundle(mission_id, str(report_output_dir))
    print(
        "[report] bundle "
        f"summary={written['summary_json']} md={written['report_md']} html={written['report_html']}"
    )

    summary = json.loads(Path(written["summary_json"]).read_text(encoding="utf-8"))
    report_md = Path(written["report_md"]).read_text(encoding="utf-8")
    report_html = Path(written["report_html"]).read_text(encoding="utf-8")
    print(
        "[report] summary "
        f"intel_briefs={summary['intelligence_findings_count']} "
        f"targets={summary['targets_count']} sessions={summary['sessions_count']}"
    )

    assert summary["intelligence_findings_count"] == 1
    assert "CVE CVE-2011-2523" in report_md
    assert "source=kb/cve" in report_md
    assert "vsftpd 2.3.4 exploit path" in report_html
    assert "CVE-2011-2523" in report_html
