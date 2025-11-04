"""
Database connection and session management
Implements secure database operations with connection pooling
"""

import os
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
import logging

from .models import Base

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages database connections, sessions, and initialization
    Implements singleton pattern for connection pooling
    """
    
    _instance = None
    _engine = None
    _session_factory = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._engine is None:
            self._initialize_engine()
    
    def _initialize_engine(self):
        """Initialize database engine with security settings"""
        
        # Get database URL from environment or config
        database_url = os.getenv(
            "DATABASE_URL", 
            "sqlite:///./data/threateye.db"
        )
        
        # SQLite specific settings
        if database_url.startswith("sqlite"):
            connect_args = {
                "check_same_thread": False,  # Allow multiple threads
                "timeout": 30.0  # Connection timeout
            }
            
            # For in-memory testing
            if ":memory:" in database_url:
                self._engine = create_engine(
                    database_url,
                    connect_args=connect_args,
                    poolclass=StaticPool,
                    echo=os.getenv("DATABASE_ECHO", "false").lower() == "true"
                )
            else:
                self._engine = create_engine(
                    database_url,
                    connect_args=connect_args,
                    pool_pre_ping=True,  # Verify connections before use
                    echo=os.getenv("DATABASE_ECHO", "false").lower() == "true"
                )
            
            # Enable foreign keys for SQLite
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
                cursor.execute("PRAGMA synchronous=NORMAL")  # Balance between safety and speed
                cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache
                cursor.close()
        
        else:
            # PostgreSQL/MySQL settings (for future production use)
            self._engine = create_engine(
                database_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=3600,  # Recycle connections after 1 hour
                echo=os.getenv("DATABASE_ECHO", "false").lower() == "true"
            )
        
        # Create session factory
        self._session_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self._engine
        )
        
        logger.info(f"Database engine initialized: {database_url}")
    
    def create_tables(self):
        """
        Create all database tables
        Should be called once during application initialization
        """
        try:
            Base.metadata.create_all(bind=self._engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            raise
    
    def drop_tables(self):
        """
        Drop all database tables
        WARNING: This will delete all data!
        Use only for testing or complete reset
        """
        try:
            Base.metadata.drop_all(bind=self._engine)
            logger.warning("All database tables dropped")
        except Exception as e:
            logger.error(f"Error dropping database tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """
        Get a new database session
        Returns:
            Session: SQLAlchemy session
        """
        if self._session_factory is None:
            self._initialize_engine()
        return self._session_factory()
    
    @contextmanager
    def session_scope(self):
        """
        Provide a transactional scope for database operations
        Automatically commits on success, rolls back on error
        
        Usage:
            with db_manager.session_scope() as session:
                session.add(new_indicator)
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database transaction error: {e}")
            raise
        finally:
            session.close()
    
    def get_engine(self):
        """Get database engine"""
        return self._engine
    
    def health_check(self) -> bool:
        """
        Check database health
        Returns:
            bool: True if database is accessible
        """
        try:
            from sqlalchemy import text
            with self.session_scope() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Global database manager instance
db_manager = DatabaseManager()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI routes
    Provides database session for request handling
    
    Usage in FastAPI:
        @app.get("/indicators")
        def get_indicators(db: Session = Depends(get_db)):
            return db.query(ThreatIndicator).all()
    """
    session = db_manager.get_session()
    try:
        yield session
    finally:
        session.close()


def init_database():
    """
    Initialize database (create tables, ensure directory exists)
    Call this during application startup
    """
    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)
    
    # Create tables
    db_manager.create_tables()
    
    logger.info("Database initialized successfully")


def reset_database():
    """
    Reset database (drop and recreate all tables)
    WARNING: This deletes all data!
    """
    logger.warning("Resetting database - all data will be lost!")
    db_manager.drop_tables()
    db_manager.create_tables()
    logger.info("Database reset complete")


# ============================================
# Database Utilities
# ============================================

def get_or_create(session: Session, model, defaults=None, **kwargs):
    """
    Get an existing record or create a new one
    Thread-safe implementation
    
    Args:
        session: Database session
        model: SQLAlchemy model class
        defaults: Default values for new record
        **kwargs: Filter criteria
    
    Returns:
        tuple: (instance, created_flag)
    """
    instance = session.query(model).filter_by(**kwargs).first()
    
    if instance:
        return instance, False
    else:
        params = kwargs.copy()
        if defaults:
            params.update(defaults)
        instance = model(**params)
        session.add(instance)
        session.flush()
        return instance, True


def bulk_insert(session: Session, model, data_list: list):
    """
    Efficiently insert multiple records
    
    Args:
        session: Database session
        model: SQLAlchemy model class
        data_list: List of dictionaries with record data
    """
    try:
        session.bulk_insert_mappings(model, data_list)
        session.commit()
        logger.info(f"Bulk inserted {len(data_list)} {model.__name__} records")
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk insert failed: {e}")
        raise


def bulk_update(session: Session, model, data_list: list):
    """
    Efficiently update multiple records
    
    Args:
        session: Database session
        model: SQLAlchemy model class
        data_list: List of dictionaries with record data (must include id)
    """
    try:
        session.bulk_update_mappings(model, data_list)
        session.commit()
        logger.info(f"Bulk updated {len(data_list)} {model.__name__} records")
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk update failed: {e}")
        raise


def execute_raw_sql(query: str, params: dict = None):
    """
    Execute raw SQL query (use with caution)
    
    Args:
        query: SQL query string
        params: Query parameters (for safe parameterization)
    
    Returns:
        Result of query execution
    """
    with db_manager.session_scope() as session:
        result = session.execute(query, params or {})
        return result.fetchall()
