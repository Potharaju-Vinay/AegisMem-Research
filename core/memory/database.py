import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def get_database_url() -> str:
    backend = os.getenv("AEGISMEM_STORAGE_BACKEND", "").lower().strip()
    if backend in ("postgresql", "postgres", "pg"):
        return os.getenv(
            "AEGISMEM_PG_URL",
            os.getenv("DATABASE_URL", "postgresql://aegis:aegis_secret@localhost:5432/aegismem"),
        )
    return os.getenv("AEGISMEM_DATABASE_URL", os.getenv("DATABASE_URL", "sqlite:///./data/aegismem.db"))


DATABASE_URL = get_database_url()


def create_configured_engine(url: str):
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True)


engine = create_configured_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


class Base(DeclarativeBase):
    pass


def get_session():
    return SessionLocal()
