"""
EPSS (Exploit Prediction Scoring System) Version-Aware Weighting Module.

Rule:
Any EPSS values recorded prior to the release of EPSS v4 in early 2025 (e.g. pre-2025-03 or pre-2025-01)
are weighted less than EPSS values recorded using EPSS v4 following its release.
"""

from typing import Union, Optional, Dict, Any


class EPSSWeightingConfig:
    """Configuration for EPSS version weighting."""

    def __init__(
        self,
        v4_release_month: str = "2025-03",
        pre_v4_weight: float = 0.6,
        v4_weight: float = 1.0
    ):
        """
        :param v4_release_month: Month string (YYYY-MM) marking EPSS v4 release.
        :param pre_v4_weight: Weight applied to pre-v4 EPSS values (0.0 to 1.0).
        :param v4_weight: Weight applied to v4+ EPSS values.
        """
        self.v4_release_month = v4_release_month
        self.pre_v4_weight = float(pre_v4_weight)
        self.v4_weight = float(v4_weight)

    def is_v4_or_later(self, date_or_month: str) -> bool:
        """Determines if a given month or date string is in the EPSS v4 era."""
        if not date_or_month:
            return False
        # Normalize to YYYY-MM
        val = str(date_or_month).strip()[:7]
        return val >= self.v4_release_month

    def get_version(self, date_or_month: str) -> str:
        """Returns 'v4' or 'pre-v4' (e.g. v3)."""
        return "v4" if self.is_v4_or_later(date_or_month) else "pre-v4"

    def get_weight(self, date_or_month: str) -> float:
        """Returns the multiplier weight for the given month/date."""
        return self.v4_weight if self.is_v4_or_later(date_or_month) else self.pre_v4_weight

    def weight_score(self, epss_score: Union[float, int, str], date_or_month: str) -> float:
        """Computes weighted EPSS score: epss * weight."""
        try:
            score = float(epss_score)
        except (ValueError, TypeError):
            return 0.0

        weight = self.get_weight(date_or_month)
        return round(score * weight, 6)


# Default global instance
DEFAULT_EPSS_CONFIG = EPSSWeightingConfig()


def weighted_epss(
    epss_score: Union[float, int, str],
    date_or_month: str,
    pre_v4_weight: float = 0.6,
    v4_release_month: str = "2025-03"
) -> float:
    """Helper function to calculate weighted EPSS score directly."""
    config = EPSSWeightingConfig(
        v4_release_month=v4_release_month,
        pre_v4_weight=pre_v4_weight
    )
    return config.weight_score(epss_score, date_or_month)

