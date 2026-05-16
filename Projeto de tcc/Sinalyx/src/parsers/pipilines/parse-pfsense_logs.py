"""
Wrapper legada para a pipeline oficial de parsing do pfSense.

Este arquivo existe apenas para manter compatibilidade com caminhos antigos.
Toda a implementacao oficial agora mora em `src.pipelines.parse_pfsense_logs`.
"""

from __future__ import annotations

from src.pipelines.parse_pfsense_logs import (
    build_sinalyx_features,
    main,
    parse_args,
    run_pipeline,
)

__all__ = [
    "build_sinalyx_features",
    "main",
    "parse_args",
    "run_pipeline",
]


if __name__ == "__main__":
    main()
