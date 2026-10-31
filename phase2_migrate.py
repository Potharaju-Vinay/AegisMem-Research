import sqlite3
from uuid import uuid4

DB_PATH = "data/aegismem.db"

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

columns = {
    row[1]
    for row in cursor.execute("PRAGMA table_info(memories)").fetchall()
}

if "revision_id" not in columns:
    cursor.execute(
        "ALTER TABLE memories ADD COLUMN revision_id VARCHAR(36)"
    )

if "parent_revision_id" not in columns:
    cursor.execute(
        "ALTER TABLE memories ADD COLUMN parent_revision_id VARCHAR(36)"
    )

rows = cursor.execute(
    """
    SELECT id, memory_id, version, previous_version_id
    FROM memories
    ORDER BY memory_id, version
    """
).fetchall()

revision_map = {}

for row_id, memory_id, version, previous_version_id in rows:
    revision_id = str(uuid4())
    revision_map[row_id] = revision_id

for row_id, memory_id, version, previous_version_id in rows:
    parent_revision_id = revision_map.get(previous_version_id)

    cursor.execute(
        """
        UPDATE memories
        SET revision_id = ?,
            parent_revision_id = ?
        WHERE id = ?
        """,
        (
            revision_id,
            parent_revision_id,
            row_id
        )
    )

connection.commit()

cursor.execute(
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_memories_revision_id "
    "ON memories(revision_id)"
)

cursor.execute(
    "CREATE INDEX IF NOT EXISTS ix_memories_parent_revision_id "
    "ON memories(parent_revision_id)"
)

connection.commit()
connection.close()

print("Phase 2 revision lineage migration completed.")