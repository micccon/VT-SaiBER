import os
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from pgvector.psycopg2 import register_vector
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

PERFORMANCE_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS targets_mission_ip_idx ON targets (mission_id, ip_address);",
    "CREATE INDEX IF NOT EXISTS services_target_port_idx ON services (target_id, port);",
    "CREATE INDEX IF NOT EXISTS findings_mission_target_created_idx ON findings (mission_id, target_ip, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS findings_mission_agent_created_idx ON findings (mission_id, agent_name, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS findings_persistence_key_idx ON findings ((data->>'persistence_key')) WHERE data ? 'persistence_key';",
    "CREATE INDEX IF NOT EXISTS agent_logs_mission_created_idx ON agent_logs (mission_id, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS agent_logs_persistence_key_idx ON agent_logs ((details->>'persistence_key')) WHERE details ? 'persistence_key';",
    "CREATE INDEX IF NOT EXISTS sessions_mission_session_idx ON sessions (mission_id, session_id);",
    "CREATE INDEX IF NOT EXISTS sessions_mission_target_open_idx ON sessions (mission_id, target_ip, closed_at, established_at DESC);",
    "CREATE INDEX IF NOT EXISTS attack_chain_mission_step_idx ON attack_chain (mission_id, step_number);",
    "CREATE INDEX IF NOT EXISTS attack_chain_mission_time_idx ON attack_chain (mission_id, timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS knowledge_base_source_path_idx ON knowledge_base ((metadata->>'source_path'));",
    "CREATE INDEX IF NOT EXISTS knowledge_base_tool_idx ON knowledge_base ((metadata->>'tool'));",
    "CREATE INDEX IF NOT EXISTS knowledge_base_metadata_gin_idx ON knowledge_base USING gin (metadata);",
)


# ===== CONNECTION =====
def _get_db_settings() -> Dict[str, str]:
    return {
        "dbname": os.getenv("DB_NAME", "vtsaiber"),
        "user": os.getenv("DB_USER", "vtsaiber"),
        "password": os.getenv("DB_PASSWORD", "password"),
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
    }


def get_connection():
    conn = psycopg2.connect(**_get_db_settings())
    register_vector(conn)
    return conn


@lru_cache(maxsize=1)
def ensure_runtime_indexes() -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            for ddl in PERFORMANCE_INDEX_DDL:
                cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


@lru_cache(maxsize=1)
def _get_embedding_client():
    try:
        from src.database.rag.embedding import EmbeddingClient
        return EmbeddingClient()
    except Exception as exc:
        logger.warning("Embedding client unavailable for finding auto-embed: %s", exc)
        return None


def test_connection():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT 1 AS ok;")
            return cur.fetchone()
    finally:
        conn.close()


# ===== TARGETS =====
def create_target(mission_id, ip_address, mac_address=None,
                  os_guess=None, hostname=None, discovered_at=None):
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


def get_target_by_id(target_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM targets WHERE id = %s;", (target_id,))
            return cur.fetchone()
    finally:
        conn.close()


def get_targets():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM targets ORDER BY id;")
            return cur.fetchall()
    finally:
        conn.close()


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
    """
    aggregate certain complete information for a mission + target_ip：
    - targets basic info（using mission_id + ip_address）
    - services（using target_id）
    - findings（using mission_id + target_ip）
    - sessions（using mission_id + target_ip）
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1) look for target row
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
                return {
                    "target": None,
                    "services": [],
                    "findings": [],
                    "sessions": [],
                }

            target_id = target["id"]

            # 2) look for services
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

            # 3) look for findings
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

            # 4) look for sessions
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


def update_target(target_id, mission_id=None, ip_address=None, mac_address=None,
                  os_guess=None, hostname=None, discovered_at=None):
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


def delete_target(target_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM targets WHERE id = %s RETURNING *;",
                (target_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


# ===== SERVICES =====
def create_service(target_id, port, protocol, service_name, service_version, banner, discovered_at=None):
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


def get_services():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM services ORDER BY id;")
            return cur.fetchall()
    finally:
        conn.close()


def get_services_by_target(target_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM services WHERE target_id = %s ORDER BY discovered_at DESC;",
                (target_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def delete_service(service_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM services WHERE id = %s RETURNING *;",
                (service_id,), 
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def delete_services_by_target(target_id):
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


# ===== FINDINGS =====
def create_finding(mission_id, agent_name, finding_type, severity, target_ip, target_port,
                   title, description, data=None, auto_embed=False):
    conn = get_connection()
    try:

        json_data = json.dumps(data) if data is not None else None

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO findings (
                    mission_id, agent_name, finding_type, severity, target_ip, target_port,
                    title, description, data
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (mission_id, agent_name, finding_type,
                 severity, target_ip, target_port,
                 title, description, json_data),
            )
            row = cur.fetchone()
        conn.commit()
        if auto_embed and row is not None:
            _embed_finding_row(row)
        return row
    finally:
        conn.close()


def get_findings():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings ORDER BY id;")
            return cur.fetchall()
    finally:
        conn.close()


def get_findings_by_mission(mission_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM findings WHERE mission_id = %s ORDER BY severity DESC;",
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def finding_exists_by_persistence_key(mission_id: str, persistence_key: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM findings
                WHERE mission_id = %s
                  AND data->>'persistence_key' = %s
                LIMIT 1;
                """,
                (mission_id, persistence_key),
            )
            return cur.fetchone() is not None
    finally:
        conn.close()


def delete_finding(finding_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM findings WHERE id = %s RETURNING *;",
                (finding_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()



# ===== AGENT LOGS =====
def create_agent_log(mission_id, agent_name, action, reasoning, result_summary,
                     details, created_at=None):
    conn = get_connection()
    try:

        json_details = json.dumps(details) if details is not None else None

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO agent_logs (mission_id, agent_name, action, reasoning, result_summary, details)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (mission_id, agent_name, action, reasoning, result_summary, json_details),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_agent_logs():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM agent_logs ORDER BY created_at DESC;")
            return cur.fetchall()
    finally:
        conn.close()


def get_agent_logs_by_mission(mission_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM agent_logs WHERE mission_id = %s ORDER BY created_at DESC;",
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


# ===== FINDINGS EMBEDDINGS =====
def _embed_finding_row(finding_row: Dict[str, Any]) -> None:
    embedding_client = _get_embedding_client()
    if embedding_client is None:
        return

    try:
        embedded_text = "\n".join(
            part for part in [
                str(finding_row.get("title") or "").strip(),
                str(finding_row.get("description") or "").strip(),
                json.dumps(finding_row.get("data") or {}, default=str),
            ]
            if part
        )
        if not embedded_text.strip():
            return

        embedding_vector = embedding_client.embed_text_sync(embedded_text)
        create_finding_embedding(
            finding_id=finding_row["id"],
            embedding_vector=embedding_vector,
            embedded_text=embedded_text,
            embedding_model="BAAI/bge-large-en-v1.5",
        )
    except Exception as exc:
        logger.warning("Failed to auto-embed finding %s: %s", finding_row.get("id"), exc)


def create_finding_embedding(finding_id, embedding_vector, embedded_text, embedding_model='BAAI/bge-large-en-v1.5'):
    """
    Store finding's embedding vector

    Args:
        finding_id: ID from findings table
        embedding_vector: 1024-dimensional embedding vector (list or array)
        embedded_text: Source text used to generate embedding (title + description)
        embedding_model: Name of the embedding model used

    Returns:
        Inserted record (dict)
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO findings_embeddings (finding_id, embedding, embedded_text, embedding_model)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (finding_id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    embedded_text = EXCLUDED.embedded_text,
                    embedding_model = EXCLUDED.embedding_model,
                    updated_at = NOW()
                RETURNING *;
                """,
                (finding_id, embedding_vector, embedded_text, embedding_model),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def search_similar_findings(
    embedding_vector,
    limit=5,
    threshold=0.7,
    filters: Optional[Dict[str, Any]] = None,
):
    """
    Vector similarity search - Find findings most similar to given embedding
    Uses cosine similarity (1 - cosine_distance)
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where_clauses = ["1 - (fe.embedding <=> %s::vector) >= %s"]
            params: List[Any] = [embedding_vector, threshold]

            for key, value in dict(filters or {}).items():
                if value is None:
                    continue
                if key in {"mission_id", "agent_name", "finding_type", "severity", "target_ip"}:
                    where_clauses.append(f"f.{key} = %s")
                    params.append(value)
                elif key == "target_port":
                    where_clauses.append("f.target_port = %s")
                    params.append(int(value))

            cur.execute(
                """
                SELECT
                    fe.finding_id,
                    f.id,
                    f.mission_id,
                    f.agent_name,
                    f.finding_type,
                    f.severity,
                    f.target_ip,
                    f.target_port,
                    f.title,
                    f.description,
                    f.data,
                    f.created_at,
                    1 - (fe.embedding <=> %s::vector) AS similarity
                FROM findings_embeddings fe
                JOIN findings f ON fe.finding_id = f.id
                WHERE """ + " AND ".join(where_clauses) + """
                ORDER BY fe.embedding <=> %s::vector
                LIMIT %s;
                """,
                [embedding_vector, *params, embedding_vector, limit],
            )
            return cur.fetchall()
    finally:
        conn.close()


def agent_log_exists_by_persistence_key(mission_id: str, persistence_key: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM agent_logs
                WHERE mission_id = %s
                  AND details->>'persistence_key' = %s
                LIMIT 1;
                """,
                (mission_id, persistence_key),
            )
            return cur.fetchone() is not None
    finally:
        conn.close()


def get_finding_embedding(finding_id):
    """
    Get embedding for a specific finding

    Args:
        finding_id: ID from findings table

    Returns:
        Embedding record (dict) or None
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM findings_embeddings WHERE finding_id = %s;",
                (finding_id,),
            )
            return cur.fetchone()
    finally:
        conn.close()


def update_finding_embedding(finding_id, embedding_vector, embedded_text):
    """
    Update existing finding's embedding

    Args:
        finding_id: ID from findings table
        embedding_vector: New embedding vector
        embedded_text: New source text

    Returns:
        Updated record (dict)
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE findings_embeddings
                SET embedding = %s, embedded_text = %s, updated_at = NOW()
                WHERE finding_id = %s
                RETURNING *;
                """,
                (embedding_vector, embedded_text, finding_id),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def delete_finding_embedding(finding_id):
    """
    Delete embedding for a finding

    Args:
        finding_id: ID from findings table

    Returns:
        Deleted record (dict)
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM findings_embeddings WHERE finding_id = %s RETURNING *;",
                (finding_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_all_findings_embeddings():
    """
    Get all findings embeddings

    Returns:
        List of all embeddings
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings_embeddings ORDER BY created_at DESC;")
            return cur.fetchall()
    finally:
        conn.close()


# ===== TARGET/SERVICE UPSERTS =====
def get_target_by_mission_ip(mission_id, ip_address):
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


def upsert_target(mission_id, ip_address, mac_address=None, os_guess=None, hostname=None, discovered_at=None):
    existing = get_target_by_mission_ip(mission_id, ip_address)
    if existing is None:
        return create_target(
            mission_id=mission_id,
            ip_address=ip_address,
            mac_address=mac_address,
            os_guess=os_guess,
            hostname=hostname,
            discovered_at=discovered_at,
        )
    return update_target(
        existing["id"],
        mission_id=mission_id,
        ip_address=ip_address,
        mac_address=mac_address if mac_address is not None else existing.get("mac_address"),
        os_guess=os_guess if os_guess is not None else existing.get("os_guess"),
        hostname=hostname if hostname is not None else existing.get("hostname"),
        discovered_at=discovered_at,
    )


def replace_services_for_target(target_id: int, services: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    delete_services_by_target(target_id)
    created: List[Dict[str, Any]] = []
    for service in services:
        created.append(
            create_service(
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


# ===== SESSION PERSISTENCE =====
def get_session_by_mission_and_session_id(mission_id: str, session_id: int):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM sessions
                WHERE mission_id = %s AND session_id = %s
                ORDER BY established_at DESC NULLS LAST, id DESC
                LIMIT 1;
                """,
                (mission_id, session_id),
            )
            return cur.fetchone()
    finally:
        conn.close()


def upsert_session(
    mission_id: str,
    session_id: int,
    target_ip: str,
    *,
    target_port: Optional[int] = None,
    user_context: Optional[str] = None,
    session_type: Optional[str] = None,
    exploit_used: Optional[str] = None,
    established_at: Optional[str] = None,
    notes: Optional[str] = None,
):
    existing = get_session_by_mission_and_session_id(mission_id, session_id)
    if existing is None:
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO sessions (
                        mission_id, session_id, target_ip, target_port, user_context,
                        session_type, exploit_used, established_at, notes
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, COALESCE(%s, NOW()), %s)
                    RETURNING *;
                    """,
                    (
                        mission_id,
                        session_id,
                        target_ip,
                        target_port,
                        user_context,
                        session_type,
                        exploit_used,
                        established_at,
                        notes,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
            return row
        finally:
            conn.close()

    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE sessions
                SET
                    target_ip = %s,
                    target_port = COALESCE(%s, target_port),
                    user_context = COALESCE(%s, user_context),
                    session_type = COALESCE(%s, session_type),
                    exploit_used = COALESCE(%s, exploit_used),
                    established_at = COALESCE(%s, established_at),
                    closed_at = NULL,
                    notes = COALESCE(%s, notes)
                WHERE id = %s
                RETURNING *;
                """,
                (
                    target_ip,
                    target_port,
                    user_context,
                    session_type,
                    exploit_used,
                    established_at,
                    notes,
                    existing["id"],
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_sessions_by_mission(mission_id: str, include_closed: bool = True):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if include_closed:
                cur.execute(
                    "SELECT * FROM sessions WHERE mission_id = %s ORDER BY established_at DESC NULLS LAST, id DESC;",
                    (mission_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT *
                    FROM sessions
                    WHERE mission_id = %s AND closed_at IS NULL
                    ORDER BY established_at DESC NULLS LAST, id DESC;
                    """,
                    (mission_id,),
                )
            return cur.fetchall()
    finally:
        conn.close()


def close_session(mission_id: str, session_id: int, notes: Optional[str] = None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE sessions
                SET
                    closed_at = NOW(),
                    notes = COALESCE(%s, notes)
                WHERE mission_id = %s AND session_id = %s AND closed_at IS NULL
                RETURNING *;
                """,
                (notes, mission_id, session_id),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def sync_sessions_for_mission(
    mission_id: str,
    active_sessions: Dict[str, Dict[str, Any]],
    *,
    target_ports: Optional[Dict[str, int]] = None,
):
    target_ports = dict(target_ports or {})
    current_session_ids = set()
    for target_ip, info in (active_sessions or {}).items():
        if not isinstance(info, dict):
            continue
        session_id = info.get("session_id")
        if session_id is None:
            continue
        current_session_ids.add(int(session_id))
        notes_parts = []
        for key in ("privilege", "os_info", "post_exploitation_at"):
            value = info.get(key)
            if value:
                notes_parts.append(f"{key}={value}")
        upsert_session(
            mission_id=mission_id,
            session_id=int(session_id),
            target_ip=target_ip,
            target_port=target_ports.get(target_ip),
            user_context=info.get("user_context") or info.get("user") or info.get("privilege"),
            session_type=info.get("session_type"),
            exploit_used=info.get("module") or info.get("exploit_used"),
            established_at=info.get("established_at") or info.get("established"),
            notes="; ".join(notes_parts) or None,
        )

    open_sessions = get_sessions_by_mission(mission_id, include_closed=False)
    for session in open_sessions:
        if int(session["session_id"]) not in current_session_ids:
            close_session(mission_id, int(session["session_id"]), notes="Closed by state sync")


# ===== ATTACK CHAIN =====
def create_attack_chain_step(
    mission_id: str,
    agent_name: str,
    action: str,
    *,
    target: Optional[str] = None,
    outcome: Optional[str] = None,
    timestamp: Optional[str] = None,
):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                WITH next_step AS (
                    SELECT COALESCE(MAX(step_number), 0) + 1 AS step_number
                    FROM attack_chain
                    WHERE mission_id = %s
                )
                INSERT INTO attack_chain (
                    mission_id, step_number, agent_name, action, target, outcome, timestamp
                )
                SELECT
                    %s,
                    next_step.step_number,
                    %s,
                    %s,
                    %s,
                    %s,
                    COALESCE(%s, NOW())
                FROM next_step
                RETURNING *;
                """,
                (mission_id, mission_id, agent_name, action, target, outcome, timestamp),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_attack_chain_by_mission(mission_id: str):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM attack_chain
                WHERE mission_id = %s
                ORDER BY step_number ASC, timestamp ASC NULLS LAST;
                """,
                (mission_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()
