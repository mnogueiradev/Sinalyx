"""
Coletores externos usados pelo Sinalyx.
"""

from src.collectors.pfsense_collector import (
    PfSenseCollectorConfig,
    collect_filter_log,
    read_collector_state,
)

__all__ = [
    "PfSenseCollectorConfig",
    "collect_filter_log",
    "read_collector_state",
]
