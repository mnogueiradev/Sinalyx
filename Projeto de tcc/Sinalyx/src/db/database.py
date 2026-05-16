"""
Configuracao central do PostgreSQL para a API do Sinalyx.

A URL do banco pode ser definida via DATABASE_URL. Quando nao for
informada, usamos o fallback documentado para facilitar testes locais:

postgresql://sinalyx:sinalyx@localhost:5432/sinalyx
"""

from __future__ import annotations

import os

DEFAULT_DATABASE_URL = "postgresql://sinalyx:sinalyx@localhost:5432/sinalyx"

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()

DATABASE_ENABLED = os.getenv("DATABASE_ENABLED", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

SQLALCHEMY_INSTALLED = False
DATABASE_INIT_ERROR: str | None = None
engine = None
SessionLocal = None
Base = None

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker
except Exception as exc:
    DATABASE_INIT_ERROR = (
        "Dependencias de banco indisponiveis. "
        "Instale SQLAlchemy, psycopg2-binary e python-dotenv. "
        f"Motivo: {exc}"
    )
else:
    SQLALCHEMY_INSTALLED = True
    Base = declarative_base()

    try:
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            future=True,
        )
        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine,
            future=True,
        )
    except Exception as exc:
        DATABASE_INIT_ERROR = (
            "Nao foi possivel inicializar o engine SQLAlchemy para o PostgreSQL. "
            f"Motivo: {exc}"
        )
