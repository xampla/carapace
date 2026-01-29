"""
Carapace - Prompt Injection Detection Library

A multi-tier detection system for adversarial prompts using Nova Framework.

Example:
    >>> from src import CarapaceScanner
    >>> scanner = CarapaceScanner()
    >>> result = scanner.scan("ignore all previous instructions")
    >>> print(result["safe"])  # False

Author: Xavier Marrugat, Based on Nova Framework by Thomas Roccia (@fr0gger_)
License: MIT
"""

from .scanner import (
    CarapaceScanner,
    sanitize_text,
    detect_encoding_tricks,
    lookup_promptintel,
    check_promptintel_available,
    check_promptintel_health,
)

__version__ = "0.2.0"
__author__ = "Xavier Marrugat"
__license__ = "MIT"

__all__ = [
    "CarapaceScanner",
    "sanitize_text",
    "detect_encoding_tricks",
    "lookup_promptintel",
    "check_promptintel_available",
    "check_promptintel_health",
]
