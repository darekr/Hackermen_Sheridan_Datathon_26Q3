"""
CSV Compare Agent - Multi-CSV Comparative Analysis Agent.
Accepts multiple CSV files and performs structural, content, and statistical comparisons.
Includes version-aware weighting for EPSS (v3 vs v4).
"""

from .agent import CSVCompareAgent
from .epss_weighting import EPSSWeightingConfig, weighted_epss

__all__ = ["CSVCompareAgent", "EPSSWeightingConfig", "weighted_epss"]
