import os
from typing import Optional
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class DatabaseConnection:
    """
    Database connection manager.
    Now implements REAL connection pooling for high-frequency CTI feeds.
    """
    
    def __init__(self):
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", "3306"))
        self.user = os.getenv("DB_USER", "cti_user")
        self.password = os.getenv("DB_PASSWORD", "cti_password")
        self.database = os.getenv("DB_NAME", "cti_platform")
        
        self._pool = None
        self._connection = None
        logger.info("Initialized database connection manager")

    def connect(self):
        """Establish connection or initialize pool."""
        try:
            import mysql.connector
            from mysql.connector import pooling
            
            # Create a pool of 5 connections (perfect for parallel scrapers)
            self._pool = pooling.MySQLConnectionPool(
                pool_name="cti_pool",
                pool_size=5,
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                autocommit=True
            )
            logger.info("Database Connection Pool established (mysql-connector-python)")
            return self._pool.get_connection()
            
        except ImportError:
            try:
                import pymysql
                # pymysql doesn't have a built-in pooler, so we fallback to a single connection
                self._connection = pymysql.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.database,
                    autocommit=True
                )
                logger.info("Fallback: Single database connection established (pymysql)")
                return self._connection
            except ImportError:
                logger.error("No MySQL drivers found. Install mysql-connector-python.")
                return None
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return None

    def get_connection(self):
        """Returns a connection from the pool or the fallback connection."""
        if self._pool:
            return self._pool.get_connection()
        if self._connection is None:
            return self.connect()
        return self._connection

    def close(self):
        """Close the active connection or pool."""
        if self._connection:
            self._connection.close()
            logger.info("Database connection closed")
        # Note: Pooled connections returned via .close() go back to the pool automatically.

db = DatabaseConnection()
