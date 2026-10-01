from core.memory.database import Base, engine, get_session
from core.memory.service import MemoryService


Base.metadata.create_all(bind=engine)


session = get_session()

try:
    memory = MemoryService(session)

    existing = memory.get_memory("POLICY-001")

    if existing is None:
        memory.create_memory(
            memory_id="POLICY-001",
            content=(
                "Customers may request refunds within 30 calendar days "
                "of purchase."
            ),
            source="customer_refund_policy",
            source_type="policy",
            actor="system"
        )

        memory.create_memory(
            memory_id="POLICY-002",
            content=(
                "Refund requests beyond 30 calendar days require "
                "manual review."
            ),
            source="refund_review_policy",
            source_type="policy",
            actor="system"
        )

        memory.create_memory(
            memory_id="SOP-003",
            content=(
                "Customer support must verify the purchase date before "
                "processing a refund."
            ),
            source="refund_support_sop",
            source_type="sop",
            actor="system"
        )

        print("AegisMem demo memories initialized.")

    else:
        print("Demo memories already exist.")

finally:
    session.close()