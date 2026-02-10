from pathlib import Path

def create_tables():
    """
    Creates all database tables for the CTI platform
    using the schema.sql file as source of truth.
    """
    # Import the 'db' instance specifically to access its connection method
    from backend.db.connection import db 

    try:
        # Get a connection from the pool managed in connection.py
        conn = db.get_connection()
        if not conn:
            raise ConnectionError("Could not establish a database connection.")
            
        cursor = conn.cursor()

        # Resolve path to schema.sql relative to this file
        schema_file = Path(__file__).parent / "schema.sql"

        if not schema_file.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_file}")

        with open(schema_file, "r", encoding="utf-8") as f:
            sql_commands = f.read()

        # MySQL connector does not allow multiple statements in execute()
        # Splitting by semicolon to run each command individually
        print("[DB] Executing schema.sql...")
        for statement in sql_commands.split(";"):
            stmt = statement.strip()
            if stmt:
                cursor.execute(stmt)

        # Note: If connection.py has autocommit=True, commit() is redundant but safe
        conn.commit()
        print("[DB] All tables created successfully.")
        
    except Exception as e:
        print(f"[ERROR] Failed to create tables: {e}")
        raise
    finally:
        if 'cursor' in locals() and cursor: 
            cursor.close()
        if 'conn' in locals() and conn: 
            conn.close() # In a pool, this returns the connection to the pool