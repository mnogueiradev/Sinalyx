"""
Utilitario de limpeza de arquivos legados do Sinalyx.

Este script remove estruturas antigas que ficaram de versoes anteriores do
projeto e que podem causar confusao durante manutencao e demonstracoes.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

# Diretorio raiz do projeto, usado para montar os caminhos legados.
BASE_DIR = Path(__file__).resolve().parent

# Lista central de arquivos e pastas antigas que nao fazem mais parte da
# arquitetura atual do projeto.
LEGACY_PATHS = [
    BASE_DIR / "models",
    BASE_DIR / "reports",
    BASE_DIR / "scripts",
    BASE_DIR / "test_detection.py",
    BASE_DIR / "test_features.py",
    BASE_DIR / "src" / "api" / "server.py",
    BASE_DIR / "src" / "data",
    BASE_DIR / "src" / "ingest",
    BASE_DIR / "src" / "features" / "build_features.py",
    BASE_DIR / "src" / "features" / "feature_engineer.py",
    BASE_DIR / "src" / "features" / "features.py",
    BASE_DIR / "src" / "models" / "avaliar_deteccao_ataques.py",
    BASE_DIR / "src" / "models" / "infer_and_act.py",
    BASE_DIR / "src" / "models" / "run_inference.py",
    BASE_DIR / "src" / "models" / "train_autoencoder.py",
    BASE_DIR / "src" / "models" / "train_detection.py",
    BASE_DIR / "src" / "models" / "train_isolation_forest.py",
]

def iter_targets() -> list[Path]:
    """
    Retorna apenas os caminhos legados que ainda existem no disco.
    """
    return [path for path in LEGACY_PATHS if path.exists()]

def remove_path(path: Path, dry_run: bool) -> None:
    """
    Remove um arquivo ou pasta, respeitando o modo de simulacao.
    """
    if dry_run:
        print(f"[dry-run] remover: {path}")
        return

    # Pastas e arquivos exigem funcoes diferentes de remocao.
    if path.is_dir():
        shutil.rmtree(path)
        print(f"[ok] pasta removida: {path}")
    else:
        path.unlink(missing_ok=True)
        print(f"[ok] arquivo removido: {path}")

def main() -> None:
    """
    Ponto de entrada do utilitario de limpeza.
    """
    parser = argparse.ArgumentParser(
        description="Remove arquivos legados que causam conflito no projeto Sinalyx."
    )
    parser.add_argument("--dry-run", action="store_true", help="Somente mostra o que será removido.")
    args = parser.parse_args()

    targets = iter_targets()
    if not targets:
        print("Nenhum arquivo legado encontrado.")
        return

    print("Alvos encontrados:")
    for target in targets:
        print(f" - {target}")

    print()
    for target in targets:
        remove_path(target, dry_run=args.dry_run)

    print("\\nConcluído." if not args.dry_run else "\\nDry-run concluído.")

if __name__ == "__main__":
    main()
