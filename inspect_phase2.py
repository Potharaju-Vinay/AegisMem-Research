import sqlite3

c = sqlite3.connect("data/aegismem.db")

print("=== POLICY-001 v131+ ===")
rows = c.execute("""
SELECT id, memory_id, version, revision_id,
       parent_revision_id, previous_version_id
FROM memories
WHERE memory_id = 'POLICY-001'
AND version >= 131
ORDER BY version
""").fetchall()

for row in rows:
    print(row)

print("\n=== FIRST 10 MEMORY ROWS ===")
rows = c.execute("""
SELECT id, memory_id, version, revision_id,
       parent_revision_id, previous_version_id
FROM memories
ORDER BY id
LIMIT 10
""").fetchall()

for row in rows:
    print(row)

c.close()