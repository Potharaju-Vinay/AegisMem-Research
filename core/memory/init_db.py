from core.memory.database import Base, engine
from core.memory.models import MemoryRecord
from core.provenance.models import ProvenanceEvent
from core.graph.dependency.models import MemoryDependency
from attack_lab.models import AttackEvent

from core.recovery.audit import RecoveryEvent

def initialize_database():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    initialize_database()
    print("AegisMem database initialized.")