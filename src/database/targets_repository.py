from __future__ import annotations

from typing import Any, Dict, Iterable, List

from psycopg2.extras import RealDictCursor

from src.database.connection import get_connection


def get_targets_by_mission(mission_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM targets WHERE mission_id = %s ORDER BY id;",
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def get_target_info(mission_id, target_ip):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM targets
                WHERE mission_id = %s AND ip_address = %s
                LIMIT 1;
                """,
                (mission_id, target_ip),
            )
            target = cur.fetchone()

            if not target:
                return {"target": None, "services": [], "findings": [], "sessions": []}

            target_id = target["id"]

            cur.execute(
                """
                SELECT *
                FROM services
                WHERE target_id = %s
                ORDER BY port;
                """,
                (target_id,),
            )
            services = cur.fetchall()

            cur.execute(
                """
                SELECT *
                FROM findings
                WHERE mission_id = %s AND target_ip = %s
                ORDER BY severity DESC, created_at DESC;
                """,
                (mission_id, target_ip),
            )
            findings = cur.fetchall()

            cur.execute(
                """
                SELECT *
                FROM sessions
                WHERE mission_id = %s AND target_ip = %s
                ORDER BY established_at DESC;
                """,
                (mission_id, target_ip),
            )
            sessions = cur.fetchall()

            return {
                "target": target,
                "services": services,
                "findings": findings,
                "sessions": sessions,
            }
    finally:
        conn.close()


def upsert_target(mission_id, ip_address, mac_address=None, os_guess=None, hostname=None, discovered_at=None):
    existing = _get_target_by_mission_ip(mission_id, ip_address)
    if existing is None:
        return _create_target(
            mission_id=mission_id,
            ip_address=ip_address,
            mac_address=mac_address,
            os_guess=os_guess,
            hostname=hostname,
            discovered_at=discovered_at,
        )
    return _update_target(
        existing["id"],
        mission_id=mission_id,
        ip_address=ip_address,
        mac_address=mac_address if mac_address is not None else existing.get("mac_address"),
        os_guess=os_guess if os_guess is not None else existing.get("os_guess"),
        hostname=hostname if hostname is not None else existing.get("hostname"),
        discovered_at=discovered_at,
    )


def replace_services_for_target(target_id: int, services: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    _delete_services_by_target(target_id)
    created: List[Dict[str, Any]] = []
    for service in services:
        created.append(
            _create_service(
                target_id=target_id,
                port=int(service.get("port", 0) or 0),
                protocol=str(service.get("protocol", "tcp") or "tcp"),
                service_name=str(service.get("service_name", "unknown") or "unknown"),
                service_version=str(service.get("service_version") or service.get("version") or "") or None,
                banner=str(service.get("banner") or "") or None,
            )
        )
    return created


def get_services_by_mission(mission_id: str):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    s.*,
                    t.ip_address,
                    t.hostname,
                    t.mission_id
                FROM services s
                JOIN targets t ON s.target_id = t.id
                WHERE t.mission_id = %s
                ORDER BY t.ip_address, s.port;
                """,
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def _create_target(mission_id, ip_address, mac_address=None, os_guess=None, hostname=None, discovered_at=None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO targets (mission_id, ip_address, mac_address,
                                     os_guess, hostname, discovered_at)
                VALUES (%s, %s, %s, %s, %s, COALESCE(%s, NOW()))
                RETURNING *;
                """,
                (mission_id, ip_address, mac_address, os_guess, hostname, discovered_at),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def _update_target(target_id, mission_id=None, ip_address=None, mac_address=None, os_guess=None, hostname=None, discovered_at=None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            updates = []
            params = []

            if mission_id is not None:
                updates.append("mission_id = %s")
                params.append(mission_id)
            if ip_address is not None:
                updates.append("ip_address = %s")
                params.append(ip_address)
            if mac_address is not None:
                updates.append("mac_address = %s")
                params.append(mac_address)
            if os_guess is not None:
                updates.append("os_guess = %s")
                params.append(os_guess)
            if hostname is not None:
                updates.append("hostname = %s")
                params.append(hostname)
            if discovered_at is not None:
                updates.append("discovered_at = %s")
                params.append(discovered_at)

            if not updates:
                return None

            updates.append("updated_at = NOW()")
            params.append(target_id)

            query = f"UPDATE targets SET {', '.join(updates)} WHERE id = %s RETURNING *;"
            cur.execute(query, params)
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def _create_service(target_id, port, protocol, service_name, service_version, banner, discovered_at=None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO services (target_id, port, protocol, service_name, service_version, banner, discovered_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (target_id, port, protocol, service_name, service_version, banner, discovered_at),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def _delete_services_by_target(target_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM services WHERE target_id = %s RETURNING *;",
                (target_id,),
            )
            rows = cur.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _get_target_by_mission_ip(mission_id, ip_address):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM targets
                WHERE mission_id = %s AND ip_address = %s
                ORDER BY updated_at DESC, id DESC
                LIMIT 1;
                """,
                (mission_id, ip_address),
            )
            return cur.fetchone()
    finally:
        conn.close()
