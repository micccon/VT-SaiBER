import pytest

from src.agents.librarian import librarian_node
from src.state.cyber_state import CyberState


@pytest.mark.asyncio
async def test_librarian_vsftpd_exploit():
    state: CyberState = {
        "current_agent": "librarian",
        "next_agent": None,
        "iteration_count": 0,
        "mission_status": "active",

        "mission_goal": "Exploit vsftpd 2.3.4",
        "target_scope": ["192.168.56.0/24"],
        "mission_id": "test-mission-vsftpd",

        "discovered_targets": {
            "192.168.56.101": {
                "services": {
                    21: {
                        "service_name": "vsftpd",
                        "version": "2.3.4",
                    }
                }
            }
        },
        "ot_discovery": {},

        "web_findings": [],

        "active_sessions": {},
        "exploited_services": [],

        "research_cache": {},
        "intelligence_findings": [],

        "supervisor_messages": [],
        "supervisor_expectations": {},

        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }

    new_state = await librarian_node(state)

    intelligence_findings = new_state.get("intelligence_findings", [])
    assert intelligence_findings, "Librarian should produce at least one finding"

    first = intelligence_findings[0]
    desc = first.get("description", "").lower()
    assert "vsftpd" in desc  