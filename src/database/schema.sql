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
  discovered_at   TIMESTAMP DEFAULT NOW(),
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

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE knowledge_base (
  id         SERIAL PRIMARY KEY,
  doc_name   VARCHAR,
  chunk_text TEXT,
  embedding  VECTOR(1536),
  metadata   JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX knowledge_base_embedding_idx
  ON knowledge_base
  USING ivfflat (embedding vector_cosine_ops);

CREATE TABLE checkpoints (
  thread_id       VARCHAR NOT NULL,
  checkpoint_id   VARCHAR NOT NULL,
  parent_id       VARCHAR,
  checkpoint_data JSONB,            -- Serialized CyberState
  created_at      TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (thread_id, checkpoint_id)
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
