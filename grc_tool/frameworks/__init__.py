"""
Compliance framework registry – returns control catalogue for each framework.
"""

from __future__ import annotations
from typing import Callable

# ── framework loaders ─────────────────────────────────────────────────────────
from .nist_csf   import get_controls as _nist_csf
from .nist_ai_rmf import get_controls as _nist_ai_rmf
from .iso27001   import get_controls as _iso27001
from .soc2       import get_controls as _soc2
from .csa_ccm    import get_controls as _csa_ccm

FRAMEWORKS: dict[str, Callable] = {
    "NIST CSF":      _nist_csf,
    "NIST AI RMF":   _nist_ai_rmf,
    "ISO 27001":     _iso27001,
    "SOC 2":         _soc2,
    "CSA CCM":       _csa_ccm,
}


def available_frameworks() -> list[str]:
    return list(FRAMEWORKS.keys())


def get_framework_controls(framework: str) -> list[dict]:
    """Return the list of control dicts for the given framework name."""
    loader = FRAMEWORKS.get(framework)
    if loader is None:
        raise ValueError(f"Unknown framework '{framework}'. "
                         f"Available: {available_frameworks()}")
    return loader()
