"""
Pipeline oficial live/quase em tempo real do pfSense para o Sinalyx.

Fluxo:
1. coleta opcional do /var/log/filter.log via SSH/SFTP
2. atualiza data/runtime/pfsense/live/filter.log
3. processa apenas linhas novas desde o ultimo offset
4. agrega eventos em janelas de 1 minuto
5. executa Isolation Forest, Autoencoder, heuristica, ensemble e decision engine
6. persiste janelas no PostgreSQL
7. imprime um resumo JSON da execucao

Modos:
- padrao continuo: preserva a ultima janela aberta para execucao periodica
- --finite-file: fecha a ultima janela para replay/teste local de arquivos finitos
"""

from __future__ import annotations

import argparse
import json
from typing import Any


DEFAULT_LIVE_WINDOW = "1min"


def parse_args() -> argparse.Namespace:
    """
    Resolve argumentos da execucao manual do fluxo live.
    """
    parser = argparse.ArgumentParser(
        description="Executa o fluxo live pfSense do Sinalyx.",
    )
    parser.add_argument(
        "--skip-collect",
        action="store_true",
        help="Nao coleta via SSH/SFTP; processa apenas o arquivo local atual.",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Executa inferencia sem salvar janelas no PostgreSQL.",
    )
    parser.add_argument(
        "--window",
        default=DEFAULT_LIVE_WINDOW,
        help="Janela de agregacao. Padrao: 1min.",
    )
    parser.add_argument(
        "--finite-file",
        action="store_true",
        help=(
            "Modo oficial de replay/teste local: fecha a ultima janela pendente "
            "ao final do arquivo."
        ),
    )
    parser.add_argument(
        "--flush-pending",
        action="store_true",
        help=(
            "Compatibilidade: fecha a janela mais recente ainda aberta. "
            "Para novas validacoes locais, prefira --finite-file."
        ),
    )
    parser.add_argument(
        "--runtime-profile",
        default=None,
        help="Perfil opcional do ensemble/decision engine.",
    )
    return parser.parse_args()


def _json_default(value: Any) -> Any:
    """
    Fallback simples para impressao JSON.
    """
    if hasattr(value, "item"):
        return value.item()
    return str(value)


def main() -> None:
    """
    Executa a pipeline e imprime o resumo final.
    """
    args = parse_args()
    from src.services.pfsense_live_service import process_live_pfsense

    response = process_live_pfsense(
        collect=not args.skip_collect,
        persist=not args.no_persist,
        window=args.window,
        finite_file=args.finite_file,
        flush_pending=args.flush_pending,
        runtime_profile=args.runtime_profile,
    )
    print(json.dumps(response, ensure_ascii=False, indent=2, default=_json_default))


if __name__ == "__main__":
    main()
