import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from pgvector.psycopg2 import register_vector


DB_USER = os.getenv("DB_USER", "vtsaiber")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "vtsaiber")


# ===== CONNECTION =====
def get_connection():
    conn  = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
    )
    register_vector(conn)
    return conn


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
                   title, description, data=None, auto_embed=True):
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
def create_finding_embedding(finding_id, embedding_vector, embedded_text, embedding_model='text-embedding-3-small'):
    """
    Store finding's embedding vector

    Args:
        finding_id: ID from findings table
        embedding_vector: 1536-dimensional embedding vector (list or array)
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


def search_similar_findings(embedding_vector, limit=5, threshold=0.7):
    """
    Vector similarity search - Find findings most similar to given embedding
    Uses cosine similarity (1 - cosine_distance)
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                WITH scored AS (
                    SELECT
                        finding_id,
                        (1 - (embedding <=> %s::vector)) AS similarity
                    FROM findings_embeddings
                )
                SELECT
                    scored.finding_id,
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
                    scored.similarity
                FROM scored
                JOIN findings f ON scored.finding_id = f.id
                WHERE scored.similarity > %s
                ORDER BY scored.similarity DESC
                LIMIT %s;
                """,
                (embedding_vector, threshold, limit),
            )
            return cur.fetchall()
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
