from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, Dict

from psycopg2.extras import RealDictCursor

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.connection import get_connection


def _resolve_db_host_for_local_run() -> None:
    configured_host = (os.getenv("DB_HOST") or "").strip()
    if not configured_host:
        return
    try:
        socket.gethostbyname(configured_host)
        return
    except OSError:
        pass
    if configured_host.lower() == "postgres":
        os.environ["DB_HOST"] = "localhost"


def _normalize_legacy_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    nested = payload.get("data")
    nested_data = nested if isinstance(nested, dict) else {}

    technical_params = payload.get("technical_params")
    if not isinstance(technical_params, dict):
        technical_params = nested_data.get("technical_params")
    technical_params = dict(technical_params or {})

    citations = payload.get("citations")
    if not isinstance(citations, list):
        citations = nested_data.get("citations")
    citations = [str(item).strip() for item in list(citations or []) if str(item).strip()]

    source_types = payload.get("source_types")
    if not isinstance(source_types, list):
        source_types = nested_data.get("source_types")
    source_types = [str(item).strip() for item in list(source_types or []) if str(item).strip()]

    source_status = payload.get("source_status")
    if not isinstance(source_status, dict):
        source_status = nested_data.get("source_status")
    source_status = {str(key): str(value) for key, value in dict(source_status or {}).items() if str(key).strip()}

    degraded_reasons = payload.get("degraded_reasons")
    if not isinstance(degraded_reasons, list):
        degraded_reasons = nested_data.get("degraded_reasons")
    degraded_reasons = [str(item).strip() for item in list(degraded_reasons or []) if str(item).strip()]

    conflicting_sources = payload.get("conflicting_sources")
    if not isinstance(conflicting_sources, list):
        conflicting_sources = nested_data.get("conflicting_sources")
    conflicting_sources = [str(item).strip() for item in list(conflicting_sources or []) if str(item).strip()]

    confidence = payload.get("confidence", nested_data.get("confidence"))
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    cve = str(
        payload.get("cve")
        or nested_data.get("cve")
        or technical_params.get("cve")
        or ""
    ).strip() or None

    normalized = {
        "source": str(payload.get("source") or "librarian").strip() or "librarian",
        "cve": cve,
        "exploit_available": bool(payload.get("exploit_available")),
        "technical_params": technical_params,
        "citations": citations,
        "confidence": confidence,
        "is_osint_derived": bool(payload.get("is_osint_derived", nested_data.get("is_osint_derived"))),
        "conflicting_sources": conflicting_sources,
        "source_types": source_types,
        "source_status": source_status,
        "degraded_reasons": degraded_reasons,
    }

    persistence_key = str(payload.get("persistence_key") or nested_data.get("persistence_key") or "").strip()
    if persistence_key:
        normalized["persistence_key"] = persistence_key

    return normalized


def _is_canonical(payload: Any) -> bool:
    return isinstance(payload, dict) and "data" not in payload and "technical_params" in payload


def migrate() -> int:
    conn = get_connection()
    updated = 0
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, data
                FROM findings
                WHERE finding_type = 'intelligence_brief';
                """
            )
            rows = cur.fetchall()
            for row in rows:
                payload = row.get("data")
                if _is_canonical(payload):
                    continue
                normalized = _normalize_legacy_payload(payload)
                cur.execute(
                    """
                    UPDATE findings
                    SET data = %s
                    WHERE id = %s;
                    """,
                    (json.dumps(normalized), row["id"]),
                )
                updated += 1
        conn.commit()
    finally:
        conn.close()
    return updated


def main() -> int:
    if load_dotenv is not None:
        load_dotenv(ROOT / ".env")
    _resolve_db_host_for_local_run()
    updated = migrate()
    print(f"Normalized {updated} intelligence_brief finding rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
