"""BARBAROSSA: Web Application Security Inspection Toolkit"""

__version__ = "0.1.0"
__title__ = "BARBAROSSA"
__description__ = "Deterministic, non-destructive web application security inspection and authorized testing toolkit"

from barbarossa.banner import print_banner
from barbarossa.models import Finding, ScanResult

__all__ = ["Finding", "ScanResult", "print_banner", "__version__"]
