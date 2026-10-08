
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DATABASE_URL


engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    },
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def create_database():

    # Import every model before create_all().
    # This registers both the original seven tables
    # and the new resource execution tables.

    from app.database import models
    from app.database import execution_models

    Base.metadata.create_all(
        bind=engine
    )
