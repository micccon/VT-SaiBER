-- ===== ENUM TYPES =====

CREATE TYPE severity_level AS ENUM (
  'critical',
  'high',
  'medium',
  'low',
  'info'
);

-- ===== TABLES =====

CREATE TABLE targets (
  id            SERIAL PRIMARY KEY,
  mission_id    VARCHAR,     
  ip_address    VARCHAR,
  mac_address   VARCHAR,
  os_guess      VARCHAR,
  hostname      VARCHAR,
  discovered_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS targets_mission_ip_idx
  ON targets (mission_id, ip_address);

CREATE TABLE services (
  id              SERIAL PRIMARY KEY,
  target_id       INTEGER NOT NULL REFERENCES targets(id),
  port            INTEGER,
  protocol        VARCHAR,      -- 'tcp', 'udp'
  service_name    VARCHAR,
  service_version VARCHAR,
  banner          TEXT,         -- raw banner
  discovered_at   TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS services_target_port_idx
  ON services (target_id, port);

CREATE TABLE findings (
  id           SERIAL PRIMARY KEY,
  mission_id   VARCHAR,
  agent_name   VARCHAR,          -- scout / fuzzer / striker ...
  finding_type VARCHAR,          -- 'vulnerable_service', 'web_directory', ...
  severity     severity_level,  
  target_ip    VARCHAR,
  target_port  INTEGER,
  title        VARCHAR,
  description  TEXT,
  data         JSONB,            -- agent-specific data
  created_at   TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS findings_mission_target_created_idx
  ON findings (mission_id, target_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS findings_mission_agent_created_idx
  ON findings (mission_id, agent_name, created_at DESC);
CREATE INDEX IF NOT EXISTS findings_persistence_key_idx
  ON findings ((data->>'persistence_key'))
  WHERE data ? 'persistence_key';

CREATE TABLE agent_logs (
  id             SERIAL PRIMARY KEY,
  mission_id     VARCHAR,
  agent_name     VARCHAR,
  action         VARCHAR,   -- 'nmap_scan', 'run_exploit', 'route_decision', ...
  reasoning      TEXT,      -- LLM explanation
  result_summary TEXT,      -- brief outcome
  details        JSONB,     -- full details
  created_at     TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS agent_logs_mission_created_idx
  ON agent_logs (mission_id, created_at DESC);
CREATE INDEX IF NOT EXISTS agent_logs_persistence_key_idx
  ON agent_logs ((details->>'persistence_key'))
  WHERE details ? 'persistence_key';

CREATE TABLE sessions (
  id             SERIAL PRIMARY KEY,
  mission_id     VARCHAR,
  session_id     INTEGER,       -- Metasploit session ID
  target_ip      VARCHAR,
  target_port    INTEGER,
  user_context   VARCHAR,       -- 'www-data', 'root', ...
  session_type   VARCHAR,       -- 'shell', 'meterpreter', ...
  exploit_used   VARCHAR,       -- module path
  established_at TIMESTAMP,
  closed_at      TIMESTAMP,     -- NULL if still active
  notes          TEXT
);
CREATE INDEX IF NOT EXISTS sessions_mission_session_idx
  ON sessions (mission_id, session_id);
CREATE INDEX IF NOT EXISTS sessions_mission_target_open_idx
  ON sessions (mission_id, target_ip, closed_at, established_at DESC);


CREATE TABLE attack_chain (
  id          SERIAL PRIMARY KEY,
  mission_id  VARCHAR,
  step_number INTEGER,
  agent_name  VARCHAR,
  action      VARCHAR,    -- e.g. 'nmap_scan', 'web_enum', 'run_exploit'
  target      VARCHAR,    -- e.g. '192.168.1.50', 'port 80', 'vsftpd 2.3.4'
  outcome     VARCHAR,    -- 'success', 'failed'
  timestamp   TIMESTAMP
);
CREATE INDEX IF NOT EXISTS attack_chain_mission_step_idx
  ON attack_chain (mission_id, step_number);
CREATE INDEX IF NOT EXISTS attack_chain_mission_time_idx
  ON attack_chain (mission_id, timestamp DESC);


-- ===== KNOWLEDGE BASE TABLE =====
CREATE EXTENSION IF NOT EXISTS vector;
-- data is from external sources (e.g. pdf documents)
CREATE TABLE knowledge_base (
  id         SERIAL PRIMARY KEY,
  doc_name   VARCHAR,
  chunk_text TEXT,
  embedding  VECTOR(1024),
  metadata   JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX knowledge_base_embedding_idx
  ON knowledge_base
  USING ivfflat (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS knowledge_base_source_path_idx
  ON knowledge_base ((metadata->>'source_path'));
CREATE INDEX IF NOT EXISTS knowledge_base_tool_idx
  ON knowledge_base ((metadata->>'tool'));
CREATE INDEX IF NOT EXISTS knowledge_base_metadata_gin_idx
  ON knowledge_base
  USING gin (metadata);

CREATE TABLE findings_embeddings (
  id              SERIAL PRIMARY KEY,
  finding_id      INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
  embedding       VECTOR(1024),
  embedding_model VARCHAR DEFAULT 'BAAI/bge-large-en-v1.5',
  embedded_text   TEXT,
  created_at      TIMESTAMP DEFAULT NOW(),
  updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX findings_embeddings_idx
  ON findings_embeddings
  USING hnsw (embedding vector_cosine_ops);
