from unittest.mock import patch

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.security import authorization
from tests.owner_approval_test_utils import sign_test_approval


def test_failed_memory_write_rolls_back_nonce():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE authorization_nonces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce VARCHAR(128) NOT NULL UNIQUE,
                authorization_id VARCHAR(128) NOT NULL,
                created_at DATETIME NOT NULL
            )
        """))

    TestSessionLocal = sessionmaker(bind=engine)

    try:
        with patch.object(authorization, "SessionLocal", TestSessionLocal):
            with TestSessionLocal() as session:
                repository = MemoryRepository(session)
                signature = sign_test_approval(
                    "TEST-FAILED-WRITE",
                    "Test content",
                    "TEST-FAILED-AUTH",
                    "TEST-FAILED-NONCE",
                )

                with patch.object(
                    session,
                    "commit",
                    side_effect=RuntimeError("simulated commit failure"),
                ):
                    try:
                        repository.create_owner_authorized(
                            memory_id="TEST-FAILED-WRITE",
                            content="Test content",
                            source="test",
                            authorization_id="TEST-FAILED-AUTH",
                            nonce="TEST-FAILED-NONCE",
                            authorization_signature=signature,
                            expected_revision_id=None,
                        )
                    except RuntimeError:
                        session.rollback()
                    else:
                        raise AssertionError("Expected simulated commit failure")

            with TestSessionLocal() as verification_session:
                record = verification_session.execute(
                    text("""
                        SELECT 1 FROM memories
                        WHERE memory_id = :memory_id
                    """),
                    {"memory_id": "TEST-FAILED-WRITE"},
                ).first()

                nonce = verification_session.execute(
                    text("""
                        SELECT 1 FROM authorization_nonces
                        WHERE nonce = :nonce
                    """),
                    {"nonce": "TEST-FAILED-NONCE"},
                ).first()

                assert record is None
                assert nonce is None
    finally:
        engine.dispose()

