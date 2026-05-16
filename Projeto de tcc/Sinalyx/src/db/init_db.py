"""
Inicializacao das tabelas do PostgreSQL da API.
"""

from __future__ import annotations

from src.db.database import Base, DATABASE_INIT_ERROR, SessionLocal, engine


def create_tables() -> None:
    """
    Cria as tabelas ORM quando o banco e as dependencias estiverem disponiveis.
    """
    if Base is None or engine is None or SessionLocal is None:
        raise RuntimeError(
            DATABASE_INIT_ERROR
            or "A camada de banco nao esta pronta para criar as tabelas."
        )

    from src.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
