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


-- ===== KNOWLEDGE BASE TABLE =====
CREATE EXTENSION IF NOT EXISTS vector;
-- data is from external sources (e.g. pdf documents)
CREATE TABLE knowledge_base (
  id         SERIAL PRIMARY KEY,
  doc_name   VARCHAR,
  chunk_text TEXT,
  embedding  VECTOR(1536), -- change based on the model used
  metadata   JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX knowledge_base_embedding_idx
  ON knowledge_base
  USING ivfflat (embedding vector_cosine_ops);


-- ===== FINDINGS EMBEDDINGS TABLE =====
--data is from findings table, used for RAG
CREATE TABLE findings_embeddings (
  id                SERIAL PRIMARY KEY,
  finding_id        INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
  embedding         VECTOR(1536),
  embedding_model   VARCHAR DEFAULT 'text-embedding-3-small', -- based on what model is used
  embedded_text     TEXT,
  created_at        TIMESTAMP DEFAULT NOW(),
  updated_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX findings_embeddings_idx
  ON findings_embeddings
  USING hnsw (embedding vector_cosine_ops);
