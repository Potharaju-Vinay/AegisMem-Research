
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.security import authorization


def create_nonce_test_database(database_url="sqlite:///:memory:", **kwargs):
    engine = create_engine(database_url, **kwargs)
    TestSessionLocal = sessionmaker(bind=engine)

    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE authorization_nonces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce VARCHAR(128) NOT NULL UNIQUE,
                authorization_id VARCHAR(128) NOT NULL,
                created_at DATETIME NOT NULL
            )
        """))

    return engine, TestSessionLocal


def test_nonce_registration_rejects_replay():
    engine, TestSessionLocal = create_nonce_test_database()

    with patch.object(authorization, "SessionLocal", TestSessionLocal):
        first = authorization.verify_and_register_nonce(
            "TEST-NONCE-001",
            "TEST-AUTH-001"
        )

        replay = authorization.verify_and_register_nonce(
            "TEST-NONCE-001",
            "TEST-AUTH-002"
        )

    assert first is True
    assert replay is False

    with TestSessionLocal() as session:
        count = session.execute(
            text("""
                SELECT COUNT(*)
                FROM authorization_nonces
                WHERE nonce = :nonce
            """),
            {"nonce": "TEST-NONCE-001"}
        ).scalar_one()

    assert count == 1
    engine.dispose()


def test_concurrent_nonce_registration_allows_only_one_success(tmp_path):
    engine, TestSessionLocal = create_nonce_test_database(
        f"sqlite:///{tmp_path / 'nonce_test.db'}",
        connect_args={"check_same_thread": False, "timeout": 10}
    )

    barrier = Barrier(2)

    def register(authorization_id):
        barrier.wait()
        return authorization.verify_and_register_nonce(
            "TEST-CONCURRENT-NONCE",
            authorization_id
        )

    with patch.object(authorization, "SessionLocal", TestSessionLocal):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                register,
                ["TEST-CONCURRENT-AUTH-1", "TEST-CONCURRENT-AUTH-2"]
            ))

    assert results.count(True) == 1
    assert results.count(False) == 1

    with TestSessionLocal() as session:
        count = session.execute(
            text("""
                SELECT COUNT(*)
                FROM authorization_nonces
                WHERE nonce = :nonce
            """),
            {"nonce": "TEST-CONCURRENT-NONCE"}
        ).scalar_one()

    assert count == 1
    engine.dispose()

def test_nonce_registration_rejects_invalid_inputs():
    assert authorization.verify_and_register_nonce("", "TEST-AUTH") is False
    assert authorization.verify_and_register_nonce("TEST-NONCE", "") is False
    assert authorization.verify_and_register_nonce("N" * 129, "TEST-AUTH") is False
    assert authorization.verify_and_register_nonce("TEST-NONCE", "A" * 129) is False


def test_verify_authorization_rejects_malformed_signature():
    assert authorization.verify_authorization(
        "TEST-PAYLOAD",
        "not-valid-hex"
    ) is False


def test_verify_authorization_rejects_wrong_signature():
    with patch.object(
        authorization,
        "load_public_key",
        side_effect=RuntimeError("simulated key loading failure"),
    ):
        assert authorization.verify_authorization(
            "TEST-PAYLOAD",
            "00"
        ) is False


def test_register_nonce_returns_false_on_database_failure():
    with patch.object(
        authorization,
        "SessionLocal",
        side_effect=RuntimeError("simulated database failure"),
    ):
        assert authorization.register_nonce(
            "TEST-NONCE-DB-FAIL",
            "TEST-AUTH-DB-FAIL"
        ) is False


def test_nonce_exists_closes_session():
    engine, TestSessionLocal = create_nonce_test_database()
    session = TestSessionLocal()

    with (
        patch.object(authorization, "SessionLocal", return_value=session),
        patch.object(session, "close", wraps=session.close) as close_session,
    ):
        assert authorization.nonce_exists("NONEXISTENT-NONCE") is False
        close_session.assert_called_once()

    engine.dispose()
