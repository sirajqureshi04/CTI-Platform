from pathlib import Path
from backend.db.connection import get_connection


def create_tables():
    """
    Creates all database tables for the CTI platform
    using the schema.sql file as source of truth.
    """

    conn = get_connection()
    cursor = conn.cursor()

    schema_file = Path(__file__).parent / "schema.sql"

    if not schema_file.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_file}")

    with open(schema_file, "r", encoding="utf-8") as f:
        sql_commands = f.read()

    # MySQL connector does not allow multiple statements in execute()
    for statement in sql_commands.split(";"):
        stmt = statement.strip()
        if stmt:
            cursor.execute(stmt)

    conn.commit()
    cursor.close()
    conn.close()

    print("[DB] All tables created successfully.")