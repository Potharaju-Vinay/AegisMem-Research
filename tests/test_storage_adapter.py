import os
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.store import (
    MemoryStore,
    SQLiteMemoryStore,
    PostgreSQLMemoryStore,
    get_memory_store,
)
from core.memory.repository import MemoryRepository
from core.security.owner_signing_client import (
    load_signing_key,
    sign_http_request,
    encode_json_body,
)
from core.security.owner_approval import canonical_owner_approval
from cryptography.hazmat.primitives import serialization


from tests.owner_approval_test_utils import sign_test_approval


@pytest.fixture
def test_db_session(tmp_path):
    db_file = tmp_path / "test_store.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS authorization_nonces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nonce TEXT NOT NULL UNIQUE,
                    authorization_id TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                )
            """)
        )
        conn.commit()
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return Session


def test_sqlite_memory_store_crud_and_hooks(test_db_session):
    store = SQLiteMemoryStore(session_factory=test_db_session)
    notifications = []

    def on_change(memory_id: str, version: int):
        notifications.append((memory_id, version))

    store.register_change_hook(on_change)

    # 1. Create initial version
    rec1 = store.create_version(
        memory_id="POLICY-SLA-001",
        content="Initial 24-hour response SLA.",
        source="admin-portal",
        source_type="policy_init",
    )
    assert rec1.version == 1
    assert rec1.memory_id == "POLICY-SLA-001"
    assert rec1.content == "Initial 24-hour response SLA."
    assert rec1.status == "active"
    assert len(notifications) == 1
    assert notifications[0] == ("POLICY-SLA-001", 1)

    # 2. Create second version
    rec2 = store.create_version(
        memory_id="POLICY-SLA-001",
        content="Updated 12-hour priority SLA.",
        source="admin-portal",
        source_type="policy_update",
    )
    assert rec2.version == 2
    assert rec2.previous_hash == rec1.content_hash
    assert len(notifications) == 2
    assert notifications[1] == ("POLICY-SLA-001", 2)

    # 3. Read queries
    latest = store.get_latest("POLICY-SLA-001")
    assert latest is not None
    assert latest.version == 2
    assert latest.content == "Updated 12-hour priority SLA."

    v1 = store.get_version("POLICY-SLA-001", 1)
    assert v1 is not None
    assert v1.version == 1
    assert v1.content == "Initial 24-hour response SLA."

    history = store.get_history("POLICY-SLA-001")
    assert len(history) == 2
    assert [r.version for r in history] == [1, 2]


def test_sqlite_memory_store_owner_authorized_write(test_db_session, tmp_path):
    manifest_store = MagicMock()
    manifest_store._path.return_value = tmp_path / "dummy.json"
    vault = MagicMock()

    store = SQLiteMemoryStore(
        session_factory=test_db_session,
        manifest_store=manifest_store,
        vault_store=vault,
    )
    notifications = []
    store.register_change_hook(lambda m, v: notifications.append((m, v)))

    memory_id = "POLICY-REFUND-AUTH"
    content = "Authentic refund window is exactly 30 days."
    authorization_id = "AUTH-ADAPTER-001"
    nonce = "NONCE-ADAPTER-001"

    signature_hex = sign_test_approval(
        memory_id=memory_id,
        content=content,
        expected_parent_revision_id=None,
        authorization_id=authorization_id,
        nonce=nonce,
    )

    record = store.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="enterprise_admin",
        authorization_id=authorization_id,
        nonce=nonce,
        authorization_signature=signature_hex,
        expected_revision_id=None,
    )

    assert record.version == 1
    assert record.authorization_state == "AUTHORIZED"
    assert record.authorization_signature == signature_hex
    assert len(notifications) == 1
    assert notifications[0] == (memory_id, 1)

    # Attacker attempts a new write using the already-used nonce
    sig_replay = sign_test_approval(
        memory_id=memory_id,
        content="New authorized update",
        expected_parent_revision_id=record.revision_id,
        authorization_id="AUTH-ADAPTER-002",
        nonce=nonce,  # replayed nonce
    )

    with pytest.raises(ValueError, match="already used"):
        store.create_owner_authorized(
            memory_id=memory_id,
            content="New authorized update",
            source="enterprise_admin",
            authorization_id="AUTH-ADAPTER-002",
            nonce=nonce,
            authorization_signature=sig_replay,
            expected_revision_id=record.revision_id,
        )


def test_adapter_factory_backend_selection():
    # Explicit backend argument
    sqlite_store = get_memory_store(backend="sqlite")
    assert isinstance(sqlite_store, SQLiteMemoryStore)

    pg_store = get_memory_store(backend="postgresql")
    assert isinstance(pg_store, PostgreSQLMemoryStore)
    assert isinstance(pg_store, MemoryStore)
    pg_store.close()

    # Environment-driven selection
    with patch.dict(os.environ, {"AEGISMEM_STORAGE_BACKEND": "postgresql"}):
        env_pg = get_memory_store()
        assert isinstance(env_pg, PostgreSQLMemoryStore)
        env_pg.close()

    with patch.dict(os.environ, {"AEGISMEM_STORAGE_BACKEND": "sqlite"}):
        env_sqlite = get_memory_store()
        assert isinstance(env_sqlite, SQLiteMemoryStore)


def test_postgresql_store_event_dispatch():
    # Test that PostgreSQL append_event issues notification and fires hooks
    pg_store = PostgreSQLMemoryStore(
        db_url="sqlite:///:memory:",  # Use in-memory dialect for unit test without external PG daemon
    )
    # Create tables
    Base.metadata.create_all(bind=pg_store.engine)

    events_fired = []
    pg_store.register_change_hook(lambda m, v: events_fired.append((m, v)))

    rec = pg_store.create_version(
        memory_id="PG-TEST-001",
        content="PostgreSQL adapter test content",
    )
    assert rec.version == 1
    assert len(events_fired) == 1

    # append_event should trigger notification hooks
    pg_store.append_event("EXTERNAL_WRITE", "PG-TEST-001")
    assert len(events_fired) == 2
    assert events_fired[-1] == ("PG-TEST-001", 1)

    pg_store.close()


def test_memory_repository_store_hook_integration(test_db_session):
    store = SQLiteMemoryStore(session_factory=test_db_session)
    hook_events = []
    store.register_change_hook(lambda m, v: hook_events.append((m, v)))

    session = test_db_session()
    repo = MemoryRepository(session=session, store=store)

    rec = repo.create(
        memory_id="REPO-STORE-001",
        content="Testing repo store integration",
        source="system",
        source_type="test",
    )
    session.close()

    assert rec.version == 1
    assert len(hook_events) == 1
    assert hook_events[0] == ("REPO-STORE-001", 1)
