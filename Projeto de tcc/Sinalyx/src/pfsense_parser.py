"""
Compatibilidade legada para o parser de logs do pfSense.

O parser oficial do projeto agora mora em `src.parsers.pfsense_parser`.
Este arquivo permanece apenas para nao quebrar imports antigos.
"""

from src.parsers.pfsense_parser import ParsedPfSenseEvent, PfSenseLogParser

__all__ = ["ParsedPfSenseEvent", "PfSenseLogParser"]
