import sqlite3
from uuid import uuid4

DB_PATH = "data/aegismem.db"

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

rows = cursor.execute("""
SELECT id, memory_id, version, previous_version_id
FROM memories
ORDER BY id
""").fetchall()

revision_map = {}

for row_id, memory_id, version, previous_version_id in rows:
    revision_map[row_id] = str(uuid4())

for row_id, memory_id, version, previous_version_id in rows:
    parent_revision_id = revision_map.get(previous_version_id)

    cursor.execute("""
    UPDATE memories
    SET revision_id = ?,
        parent_revision_id = ?
    WHERE id = ?
    """, (
        revision_map[row_id],
        parent_revision_id,
        row_id
    ))

cursor.execute("""
CREATE UNIQUE INDEX IF NOT EXISTS ix_memories_revision_id
ON memories(revision_id)
""")

cursor.execute("""
CREATE INDEX IF NOT EXISTS ix_memories_parent_revision_id
ON memories(parent_revision_id)
""")

connection.commit()
connection.close()

print("Phase 2 revision lineage repaired successfully.")