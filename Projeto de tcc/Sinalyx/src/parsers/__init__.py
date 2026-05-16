"""
Parsers de entrada de logs do Sinalyx.

Este pacote concentra adaptadores para transformar fontes reais de log em
estruturas que o restante do projeto consiga consumir.
"""

from .pfsense_parser import ParsedPfSenseEvent, PfSenseLogParser

__all__ = ["ParsedPfSenseEvent", "PfSenseLogParser"]
