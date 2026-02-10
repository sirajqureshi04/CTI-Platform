import os
from typing import Optional
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

class DatabaseConnection:
    """
    Database connection manager.
    Implements connection pooling for high-frequency CTI feeds.
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
        """Establish connection pool or fallback to single connection."""
        try:
            import mysql.connector
            from mysql.connector import pooling
            
            # Initialize the pool
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
                # Fallback to a single connection if mysql-connector is missing
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
        # 1. If neither pool nor fallback exists, try to connect/initialize
        if self._pool is None and self._connection is None:
            return self.connect()

        # 2. If pool exists, get a connection from it
        if self._pool:
            try:
                return self._pool.get_connection()
            except Exception as e:
                logger.error(f"Error getting connection from pool: {e}")
                # Re-attempting initialization if pool is exhausted or broken
                return self.connect()

        # 3. Otherwise return the single fallback connection
        return self._connection

    def close(self):
        """Close the active fallback connection or clean up pool."""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("Fallback database connection closed")
        
        # Note: In pooling, you don't 'close' the pool itself usually, 
        # but you close individual connections returned by get_connection()
        # to return them to the pool.

# Instantiate the manager so other modules can import 'db'
db = DatabaseConnection()