"""
Seed controlado do PostgreSQL do Sinalyx.

O seed oficial cria somente o administrador inicial configurado por variaveis
de ambiente e evita duplicacao quando o email ja existe.
"""

from __future__ import annotations

from typing import Any

from src.db.init_db import create_tables
from src.db.repository import seed_initial_admin


def run_seed() -> dict[str, Any]:
    """
    Prepara tabelas e executa o seed do administrador inicial.

    Returns:
        Dicionario com o resultado da criacao ou o motivo de nao criar.
    """
    create_tables()
    return seed_initial_admin()


def main() -> None:
    """
    Executa o seed pela linha de comando.
    """
    result = run_seed()
    if result.get("created"):
        print("Administrador inicial criado com sucesso.")
    else:
        reason = result.get("reason", "nenhuma acao necessaria")
        print(f"Seed concluido: {reason}.")


if __name__ == "__main__":
    main()
