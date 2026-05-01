CREATE EXTENSION IF NOT EXISTS vector;

CREATE INDEX IF NOT EXISTS targets_mission_ip_idx
  ON targets (mission_id, ip_address);

CREATE INDEX IF NOT EXISTS services_target_port_idx
  ON services (target_id, port);

CREATE INDEX IF NOT EXISTS findings_mission_target_created_idx
  ON findings (mission_id, target_ip, created_at DESC);

CREATE INDEX IF NOT EXISTS findings_mission_agent_created_idx
  ON findings (mission_id, agent_name, created_at DESC);

CREATE INDEX IF NOT EXISTS findings_persistence_key_idx
  ON findings ((data->>'persistence_key'))
  WHERE data ? 'persistence_key';

CREATE INDEX IF NOT EXISTS agent_logs_mission_created_idx
  ON agent_logs (mission_id, created_at DESC);

CREATE INDEX IF NOT EXISTS agent_logs_persistence_key_idx
  ON agent_logs ((details->>'persistence_key'))
  WHERE details ? 'persistence_key';

CREATE INDEX IF NOT EXISTS sessions_mission_session_idx
  ON sessions (mission_id, session_id);

CREATE INDEX IF NOT EXISTS sessions_mission_target_open_idx
  ON sessions (mission_id, target_ip, closed_at, established_at DESC);

CREATE INDEX IF NOT EXISTS attack_chain_mission_step_idx
  ON attack_chain (mission_id, step_number);

CREATE INDEX IF NOT EXISTS attack_chain_mission_time_idx
  ON attack_chain (mission_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS knowledge_base_source_path_idx
  ON knowledge_base ((metadata->>'source_path'));

CREATE INDEX IF NOT EXISTS knowledge_base_embedding_idx
  ON knowledge_base
  USING ivfflat (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS knowledge_base_tool_idx
  ON knowledge_base ((metadata->>'tool'));

CREATE INDEX IF NOT EXISTS knowledge_base_metadata_gin_idx
  ON knowledge_base
  USING gin (metadata);

CREATE INDEX IF NOT EXISTS findings_embeddings_idx
  ON findings_embeddings
  USING hnsw (embedding vector_cosine_ops);
