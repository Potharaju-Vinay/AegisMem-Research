"""
Sync SQLite persistent memory and audit tables into PostgreSQL container.
Ensures all enterprise memories (e.g. ENT-ACCESS-001, ENT-INCIDENT-002, etc.)
are fully loaded into the live PostgreSQL database.
"""

import sqlite3
from pathlib import Path
from sqlalchemy import text
from core.memory.database import engine

SQLITE_PATH = Path("data/aegismem.db")

TABLES_TO_SYNC = [
    "memories",
    "provenance_events",
    "memory_dependencies",
    "attack_events",
    "recovery_events",
    "memory_access_events",
    "soc_alerts",
    "dashboard_sessions",
    "session_audit_events",
    "dashboard_operation_approvals",
    "authorization_events",
    "authorization_nonces",
]

BOOLEAN_COLUMNS = {
    "integrity_compromised",
    "verified",
    "compromised",
    "confirmed",
    "is_active",
    "success",
}


def sync():
    if not SQLITE_PATH.is_file():
        print(f"Error: {SQLITE_PATH} not found.")
        return

    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row

    with engine.connect() as pg_conn:
        # Disable foreign key triggers temporarily during import
        pg_conn.execute(text("SET session_replication_role = 'replica';"))
        pg_conn.commit()

        for table in TABLES_TO_SYNC:
            cur = sqlite_conn.cursor()
            try:
                cur.execute(f"SELECT * FROM {table}")
                rows = cur.fetchall()
            except sqlite3.OperationalError:
                continue

            if not rows:
                continue

            col_names = [col[0] for col in cur.description]
            cols_str = ", ".join(f'"{c}"' for c in col_names)
            params_str = ", ".join(f":{c}" for c in col_names)

            try:
                pg_conn.execute(text(f'TRUNCATE TABLE "{table}" CASCADE;'))
                insert_stmt = text(f'INSERT INTO "{table}" ({cols_str}) VALUES ({params_str})')

                batch = []
                for row in rows:
                    row_dict = dict(row)
                    for k, v in row_dict.items():
                        if k in BOOLEAN_COLUMNS and v is not None:
                            row_dict[k] = bool(v)
                    batch.append(row_dict)

                pg_conn.execute(insert_stmt, batch)
                pg_conn.commit()
                print(f"Synced {len(batch)} rows into table '{table}'.")

                # Update PostgreSQL sequence to match MAX(id) if serial
                if "id" in col_names and rows and isinstance(rows[0]["id"], int):
                    try:
                        seq_query = text(f"""
                            SELECT setval(
                                pg_get_serial_sequence('{table}', 'id'),
                                COALESCE(MAX(id), 1),
                                true
                            ) FROM "{table}";
                        """)
                        pg_conn.execute(seq_query)
                        pg_conn.commit()
                    except Exception:
                        pg_conn.rollback()

            except Exception as e:
                pg_conn.rollback()
                print(f"Error syncing {table}: {e}")

        # Re-enable foreign key triggers
        pg_conn.execute(text("SET session_replication_role = 'origin';"))
        pg_conn.commit()

    sqlite_conn.close()
    print("Database sync from SQLite to PostgreSQL completed successfully!")


def auto_sync_if_needed():
    try:
        with engine.connect() as conn:
            cnt = conn.execute(text("SELECT COUNT(*) FROM memories;")).scalar()
            if cnt and cnt >= 10:
                return
        sync()
    except Exception as e:
        print(f"[AegisMem Sync Notice] Auto-sync skipped or error: {e}")


if __name__ == "__main__":
    sync()
