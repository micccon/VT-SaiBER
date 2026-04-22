from src.database.persistence import persist_state_update


def test_persist_state_update_deduplicates_findings_and_logs(monkeypatch):
    finding_calls = []
    log_calls = []
    attack_calls = []

    seen_findings = set()
    seen_logs = set()

    monkeypatch.setattr("src.database.persistence.ensure_runtime_indexes", lambda: None)
    monkeypatch.setattr("src.database.persistence.upsert_target", lambda *args, **kwargs: {"id": 1})
    monkeypatch.setattr("src.database.persistence.replace_services_for_target", lambda *args, **kwargs: None)
    monkeypatch.setattr("src.database.persistence.sync_sessions_for_mission", lambda *args, **kwargs: None)

    def _finding_exists(_mission_id, key):
        return key in seen_findings

    def _log_exists(_mission_id, key):
        return key in seen_logs

    def _create_finding(*_args, **kwargs):
        finding_calls.append(kwargs)
        seen_findings.add(kwargs["data"]["persistence_key"])

    def _create_agent_log(*_args, **kwargs):
        log_calls.append(kwargs)
        seen_logs.add(kwargs["details"]["persistence_key"])

    def _create_attack_step(*_args, **kwargs):
        attack_calls.append(kwargs)

    monkeypatch.setattr("src.database.persistence.finding_exists_by_persistence_key", _finding_exists)
    monkeypatch.setattr("src.database.persistence.agent_log_exists_by_persistence_key", _log_exists)
    monkeypatch.setattr("src.database.persistence.create_finding", _create_finding)
    monkeypatch.setattr("src.database.persistence.create_agent_log", _create_agent_log)
    monkeypatch.setattr("src.database.persistence.create_attack_chain_step", _create_attack_step)

    previous_state = {
        "mission_id": "mission-dedup-001",
        "discovered_targets": {"10.0.0.10": {"services": {"80": {"service_name": "http"}}}},
        "active_sessions": {},
    }
    updates = {
        "web_findings": [
            {
                "path": "/admin",
                "url": "http://10.0.0.10/admin",
                "is_interesting": True,
                "rationale": "Admin surface",
            }
        ],
        "agent_log": [
            {
                "agent": "fuzzer",
                "action": "web_enumeration",
                "target": "http://10.0.0.10",
                "findings": {"findings_count": 1},
                "timestamp": "2026-04-22T12:00:00",
            }
        ],
    }

    persist_state_update(previous_state, updates)
    persist_state_update(previous_state, updates)

    assert len(finding_calls) == 1
    assert len(log_calls) == 1
    assert len(attack_calls) == 1
