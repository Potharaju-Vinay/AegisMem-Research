from core.memory.database import Base, engine
from core.security.dashboard_session import DashboardSession
from core.memory.models import MemoryRecord
from core.provenance.models import ProvenanceEvent
from core.graph.dependency.models import MemoryDependency
from attack_lab.models import AttackEvent
from core.recovery.audit import RecoveryEvent
from core.security.access import MemoryAccessEvent
from core.soc.models import SOCAlert
from core.soc.session_audit import SessionAuditEvent
from core.security.dashboard_operation_approval import DashboardOperationApproval


def initialize_database():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    initialize_database()
    print("AegisMem database initialized.")




