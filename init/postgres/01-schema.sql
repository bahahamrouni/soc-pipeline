CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    severity SMALLINT NOT NULL CHECK (severity BETWEEN 0 AND 3),
    category VARCHAR(64) NOT NULL DEFAULT 'Unknown',
    confidence FLOAT CHECK (confidence BETWEEN 0 AND 1),
    source_ips INET[],
    target_hosts TEXT[],
    event_count INTEGER NOT NULL DEFAULT 0,
    event_ids UUID[],
    feature_vector FLOAT[],
    ai_summary TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    assigned_to VARCHAR(128),
    analyst_notes TEXT,
    label SMALLINT CHECK (label BETWEEN 0 AND 3),
    raw_incident JSONB NOT NULL
);

CREATE INDEX idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX idx_incidents_severity ON incidents (severity);
CREATE INDEX idx_incidents_status ON incidents (status);

CREATE TABLE IF NOT EXISTS cmdb_assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    os VARCHAR(64),
    role VARCHAR(64),
    site VARCHAR(64),
    criticality SMALLINT NOT NULL DEFAULT 1,
    owner VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_cmdb_ip ON cmdb_assets (ip_address);
CREATE INDEX idx_cmdb_hostname ON cmdb_assets (hostname);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now()
);