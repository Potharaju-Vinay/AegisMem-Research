from typing import Any
from sqlalchemy import text


CREATE_OUTBOX_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS memory_outbox (
    id BIGSERIAL PRIMARY KEY,
    memory_id VARCHAR(128) NOT NULL,
    version INT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp(),
    processed BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_outbox_unprocessed ON memory_outbox (id) WHERE processed = FALSE;
"""

CREATE_TRIGGER_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION notify_memory_change() RETURNS TRIGGER AS $$
DECLARE
    notification_payload text;
BEGIN
    INSERT INTO memory_outbox (memory_id, version, event_type, payload, created_at)
    VALUES (
        NEW.memory_id,
        NEW.version,
        TG_OP,
        json_build_object(
            'id', NEW.id,
            'revision_id', NEW.revision_id,
            'status', NEW.status,
            'content_hash', NEW.content_hash
        )::jsonb,
        clock_timestamp()
    );

    notification_payload := json_build_object(
        'memory_id', NEW.memory_id,
        'version', NEW.version,
        'event_type', TG_OP,
        't_write', extract(epoch from clock_timestamp())
    )::text;

    PERFORM pg_notify('aegismem_memory_changes', notification_payload);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

CREATE_TABLE_TRIGGER_SQL = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'memories') THEN
        DROP TRIGGER IF EXISTS trg_memory_change ON memories;
        CREATE TRIGGER trg_memory_change
        AFTER INSERT OR UPDATE ON memories
        FOR EACH ROW EXECUTE FUNCTION notify_memory_change();
    END IF;
END $$;
"""


def setup_postgres_event_pipeline(engine: Any) -> bool:
    """
    Applies transactional outbox and notification triggers to a PostgreSQL backend.
    Enables sub-millisecond event-driven detection without polling delays.
    """
    if engine is None:
        return False

    try:
        with engine.begin() as conn:
            conn.execute(text(CREATE_OUTBOX_TABLE_SQL))
            conn.execute(text(CREATE_TRIGGER_FUNCTION_SQL))
            conn.execute(text(CREATE_TABLE_TRIGGER_SQL))
        return True
    except Exception as exc:
        print(f"[PostgreSQL Trigger Setup Warning] Failed to configure triggers: {exc}")
        return False
