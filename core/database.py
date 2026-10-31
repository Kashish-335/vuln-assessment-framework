"""
Database session and initialization management using SQLAlchemy.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
from core.config import Config

engine = create_engine(
    Config.SQLALCHEMY_DATABASE_URI,
    connect_args={"check_same_thread": False} if "sqlite" in Config.SQLALCHEMY_DATABASE_URI else {}
)

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()

def init_db():
    """Create all tables in the database if they do not exist."""
    import core.models # noqa: F401
    Base.metadata.create_all(bind=engine)

def get_db():
    """Context-friendly generator for DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
