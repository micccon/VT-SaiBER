-- ===== ENUM TYPES =====

CREATE TYPE target_status AS ENUM (
  'active',
  'inactive',
  'retired'
);

CREATE TYPE report_status AS ENUM (
  'draft',
  'completed',
  'archived'
);

CREATE TYPE severity_level AS ENUM (
  'critical',
  'high',
  'medium',
  'low',
  'info'
);

CREATE TYPE finding_status AS ENUM (
  'open',
  'in_review',
  'accepted',
  'fixed'
);

CREATE TYPE log_level AS ENUM (
  'debug',
  'info',
  'warning',
  'error'
);

-- ===== TABLES =====

CREATE TABLE targets (
  id           SERIAL PRIMARY KEY,
  name         VARCHAR,
  target_type  VARCHAR,
  target_url   VARCHAR,
  status       target_status,
  created_at   TIMESTAMP DEFAULT NOW(),
  updated_at   TIMESTAMP DEFAULT NOW(),
  description  TEXT
);

CREATE TABLE reports (
  id           SERIAL PRIMARY KEY,
  target_id    INTEGER NOT NULL REFERENCES targets(id),
  title        VARCHAR,
  summary      TEXT,
  status       report_status,
  created_at   TIMESTAMP DEFAULT NOW(),
  generated_at TIMESTAMP
);

CREATE TABLE findings (
  id           SERIAL PRIMARY KEY,
  report_id    INTEGER NOT NULL REFERENCES reports(id),
  severity     severity_level,
  title        VARCHAR,
  description  TEXT,
  status       finding_status,
  created_at   TIMESTAMP DEFAULT NOW()
);

CREATE TABLE agent_logs (
  id           SERIAL PRIMARY KEY,
  target_id    INTEGER NOT NULL REFERENCES targets(id),
  report_id    INTEGER REFERENCES reports(id),
  agent_name   VARCHAR,
  action       VARCHAR,
  message      TEXT,
  level        log_level,
  created_at   TIMESTAMP DEFAULT NOW()
);
