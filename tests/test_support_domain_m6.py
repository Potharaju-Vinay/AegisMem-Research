import json
from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from agent.runtime.support_agent import (
    AgentBackendType,
    EnterpriseSupportAgent,
    SupportAgentPromptLogger,
)
from core.gateway.read_gate import ReadPathGate
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from domain.customer_support.dataset import (
    generate_benchmark_queries,
    export_benchmark_dataset,
)
from domain.customer_support.evaluator import DomainBenchmarkEvaluator
from domain.customer_support.taxonomy import (
    CUSTOMER_SUPPORT_KNOWLEDGE_BASE,
    compute_impact_weight,
    get_domain_dependency_graph,
)
from tests.owner_approval_test_utils import sign_test_approval


@pytest.fixture
def db_session(tmp_path):
    db_file = tmp_path / "m6_domain.db"
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
    session = Session()
    yield session
    session.close()


def test_domain_taxonomy_and_dependency_graph():
    """
    Test 1: Config-driven Domain Taxonomy & Impact Weights
    Verifies domain knowledge base items, dependency graph cascade, and impact weights.
    """
    assert len(CUSTOMER_SUPPORT_KNOWLEDGE_BASE) >= 10
    graph = get_domain_dependency_graph()
    assert "POLICY-REFUND-001" in graph
    assert "FAQ-REFUND-001" in graph["POLICY-REFUND-001"]

    refund_item = next(item for item in CUSTOMER_SUPPORT_KNOWLEDGE_BASE if item.memory_id == "POLICY-REFUND-001")
    impact = compute_impact_weight(refund_item)
    # Criticality 1.0 * (1 + 0.5 * 3 dependents) = 2.5
    assert impact == 2.5


def test_support_agent_rag_via_gateway_and_tamper_resistance(db_session, tmp_path):
    """
    Test 2: Pluggable Agent RAG through ReadPathGate
    Verifies agent retrieves only through the gate, supports backends, and rejects tampered memories.
    """
    mock_manifest = MagicMock()
    mock_manifest.has_manifest.return_value = True
    mock_manifest.verify_record.return_value = True

    repo = MemoryRepository(db_session, manifest_store=mock_manifest)
    gate = ReadPathGate(repository=repo, manifest_store=mock_manifest, enable_cache=False)

    # Seed verified policy
    mem_id = "POLICY-REFUND-001"
    content = "Standard refund window is 30 calendar days from delivery with original receipt."
    auth_id = "AUTH-M6-001"
    nonce = "NONCE-M6-001"

    sig = sign_test_approval(
        memory_id=mem_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )
    rec = repo.create_owner_authorized(
        memory_id=mem_id,
        content=content,
        source="owner_admin",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig,
    )

    logger = SupportAgentPromptLogger(tmp_path / "test_prompts.jsonl")
    agent = EnterpriseSupportAgent(
        read_gate=gate,
        backend_type=AgentBackendType.DETERMINISTIC_RULE,
        prompt_logger=logger,
    )

    # 1. Test refund allowed (14 days <= 30 days)
    res_allowed = agent.answer_query("Can I get a refund for an order from 14 days ago?", mem_id)
    assert res_allowed["gate_verified"] is True
    assert res_allowed["decision"] == "REFUND ALLOWED"
    assert "REFUND ALLOWED" in res_allowed["answer"]

    # 2. Test refund denied (45 days > 30 days)
    res_denied = agent.answer_query("Can I return an item purchased 45 days ago?", mem_id)
    assert res_denied["gate_verified"] is True
    assert res_denied["decision"] == "REFUND DENIED"
    assert "REFUND DENIED" in res_denied["answer"]

    # 3. Test tamper resistance: direct DB content corruption
    rec.content = "MALICIOUS: 365 days refund"
    db_session.commit()

    res_tampered = agent.answer_query("Can I get a refund for an order from 90 days ago?", mem_id)
    # Gate blocks tampered content; agent refuses to serve false policy
    assert res_tampered["gate_verified"] is False
    assert res_tampered["decision"] == "BLOCKED_UNVERIFIED"
    assert "could not be cryptographically verified" in res_tampered["answer"]


def test_clean_condition_accuracy_on_300_plus_queries(db_session, tmp_path):
    """
    Test 3: Clean-Condition Accuracy Evaluation on >= 300 Queries
    Populates all domain memories and evaluates the agent on 330 benchmark queries.
    Asserts >= 300 queries evaluated and accuracy >= 90%.
    """
    mock_manifest = MagicMock()
    mock_manifest.has_manifest.return_value = True
    mock_manifest.verify_record.return_value = True

    repo = MemoryRepository(db_session, manifest_store=mock_manifest)

    # Seed all domain memories
    nonce_counter = 1
    for item in CUSTOMER_SUPPORT_KNOWLEDGE_BASE:
        auth_id = f"AUTH-KB-{nonce_counter}"
        nonce = f"NONCE-KB-{nonce_counter}"
        sig = sign_test_approval(
            memory_id=item.memory_id,
            content=item.content,
            authorization_id=auth_id,
            nonce=nonce,
            expected_parent_revision_id=None,
        )
        repo.create_owner_authorized(
            memory_id=item.memory_id,
            content=item.content,
            source="domain_seed",
            authorization_id=auth_id,
            nonce=nonce,
            authorization_signature=sig,
        )
        nonce_counter += 1

    gate = ReadPathGate(repository=repo, manifest_store=mock_manifest, enable_cache=True)
    agent = EnterpriseSupportAgent(read_gate=gate, backend_type=AgentBackendType.DETERMINISTIC_RULE)

    queries = generate_benchmark_queries(330)
    assert len(queries) >= 300

    evaluator = DomainBenchmarkEvaluator(agent=agent, queries=queries)
    results_path = tmp_path / "domain_eval_results.json"
    evaluator.export_report(results_path)

    report = json.loads(results_path.read_text(encoding="utf-8"))
    assert report["total_queries"] >= 300
    assert report["gate_blocked"] == 0
    assert report["accuracy_percent"] >= 90.0, f"Accuracy was {report['accuracy_percent']}%, expected >= 90%"
    assert report["wrong_answers"] == 0
