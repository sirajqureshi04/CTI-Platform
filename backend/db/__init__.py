"""Database modules for the CTI platform."""

# Explicit exports for easier importing
from backend.db.connection import DatabaseConnection
from backend.db.schema import create_tables

__all__ = [
    "DatabaseConnection",
    "create_tables"
]       
