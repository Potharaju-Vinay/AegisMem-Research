from unittest.mock import patch
from fastapi.testclient import TestClient
from api.main import app

def test_chat_rejects_unauthenticated_request_before_database_access():
    with patch("api.main.get_session", side_effect=AssertionError("Database accessed")):
        response = TestClient(app).post("/chat", json={"question": "What is the refund policy?"})
    assert response.status_code == 401

def test_refund_decision_rejects_unauthenticated_request_before_database_access():
    with patch("api.main.get_session", side_effect=AssertionError("Database accessed")):
        response = TestClient(app).post("/refund-decision", json={"customer_days": 10})
    assert response.status_code == 401
