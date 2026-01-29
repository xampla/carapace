#!/usr/bin/env python3
"""
Carapace Scanner

A prompt injection detection library using Nova Framework.
Provides multi-tier detection: sanitization, Nova rules, and PromptIntel lookups.

Author: Xavier Marrugat, Based on Nova Framework by Thomas Roccia (@fr0gger_)
License: MIT
"""

import contextlib
import io
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

# Nova Framework imports (v0.1.4)
from nova import NovaParser, NovaMatcher, NovaRule


@contextlib.contextmanager
def _suppress_nova_warnings():
    """Suppress Nova's print-based warnings during matcher creation."""
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = old_stdout

__all__ = [
    "CarapaceScanner",
    "sanitize_text",
    "detect_encoding_tricks",
    "lookup_promptintel",
    "check_promptintel_available",
    "check_promptintel_health",
]

# =============================================================================
# Constants
# =============================================================================

PROMPTINTEL_API_BASE = "https://api.promptintel.novahunting.ai/api/v1"
PROMPTINTEL_API_KEY = os.environ.get("PROMPTINTEL_API_KEY", "")
USER_AGENT = "Carapace/1.0 (+https://github.com/xampla/carapace)"

# Invisible Unicode characters used in evasion attacks
INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\u200B-\u200F\u2028-\u202F\uFEFF\u0000-\u001F\u007F-\u009F]"
)

# Homoglyph mappings: characters that look like ASCII but aren't
HOMOGLYPHS: Dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    # Greek
    "\u03B1": "a", "\u03B5": "e", "\u03BF": "o", "\u03C1": "p",
    # Full-width ASCII (a-z)
    **{chr(0xFF41 + i): chr(0x61 + i) for i in range(26)},
}

# Severity levels for threat classification
SEVERITY_ORDER: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Dangerous shell command patterns
DANGEROUS_COMMAND_PATTERNS: List[tuple] = [
    (r"rm\s+-r[f]?\s+[/~]", "destructive", "critical"),
    (r"sudo\s+rm\s+-r[f]?", "destructive", "critical"),
    (r"mkfs\s+", "destructive", "critical"),
    (r"dd\s+if=.+of=/dev/", "destructive", "critical"),
    (r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:", "fork_bomb", "critical"),
    (r"(curl|wget)\s+.+\|\s*(ba)?sh", "remote_exec", "critical"),
    (r"python[3]?\s+-c\s+['\"].*urllib", "remote_exec", "high"),
    (r"cat\s+.+\|\s*(nc|netcat|curl)", "exfiltration", "high"),
    (r"\.ssh/(id_rsa|id_ed25519|authorized_keys)", "credential_access", "critical"),
    (r"cat\s+.*(\.env|/etc/shadow|/etc/passwd)", "credential_access", "high"),
]


# =============================================================================
# PromptIntel API
# =============================================================================


def _api_request(
    endpoint: str,
    method: str = "GET",
    data: Optional[Dict] = None,
    timeout: float = 5.0,
    require_auth: bool = True,
) -> Optional[Dict[str, Any]]:
    """Make an HTTP request to the PromptIntel API."""
    if require_auth and not PROMPTINTEL_API_KEY:
        return None

    try:
        url = f"{PROMPTINTEL_API_BASE}{endpoint}"
        body = json.dumps(data).encode("utf-8") if data else None
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}

        if PROMPTINTEL_API_KEY:
            headers["Authorization"] = f"Bearer {PROMPTINTEL_API_KEY}"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


def check_promptintel_available() -> bool:
    """Check if PromptIntel API key is configured."""
    return bool(PROMPTINTEL_API_KEY)


def check_promptintel_health() -> bool:
    """Check if PromptIntel API is reachable."""
    result = _api_request("/health", require_auth=False, timeout=3.0)
    return result is not None and result.get("status") == "healthy"


def lookup_promptintel(prompt: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """
    Query PromptIntel API for known IoPC matches.

    Args:
        prompt: Text to check against IoPC database
        timeout: Request timeout in seconds

    Returns:
        API response with IoPC matches, or None if unavailable
    """
    return _api_request("/prompts", "POST", {"query": prompt}, timeout)


# =============================================================================
# Text Sanitization
# =============================================================================


def sanitize_text(text: str, max_length: int = 8192) -> str:
    """
    Sanitize text to defeat common evasion techniques.

    Processing steps:
    1. Unicode NFKC normalization
    2. Remove invisible/zero-width characters
    3. Replace homoglyphs with ASCII equivalents
    4. Collapse whitespace
    5. Truncate to max length

    Args:
        text: Raw input text
        max_length: Maximum output length

    Returns:
        Sanitized text
    """
    if not text:
        return ""

    # Normalize Unicode
    text = unicodedata.normalize("NFKC", text)

    # Remove invisible characters
    text = INVISIBLE_CHARS_PATTERN.sub("", text)

    # Replace homoglyphs
    for glyph, ascii_char in HOMOGLYPHS.items():
        text = text.replace(glyph, ascii_char)

    # Collapse whitespace and truncate
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_length]


def detect_encoding_tricks(text: str) -> List[str]:
    """
    Detect encoding patterns that may indicate evasion attempts.

    Args:
        text: Raw input text

    Returns:
        List of detected encoding trick names
    """
    tricks = []

    # Base64 (long alphanumeric strings with optional padding)
    if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", text):
        tricks.append("base64")

    # Hex encoding (0x## sequences)
    if re.search(r"(?:0x[0-9a-fA-F]{2}\s*){4,}", text):
        tricks.append("hex")

    # Unicode escapes (\uXXXX sequences)
    if re.search(r"(?:\\u[0-9a-fA-F]{4}){3,}", text):
        tricks.append("unicode_escape")

    # ROT13 mentions
    if re.search(r"\b(?:rot13|ebg13)\b", text, re.I):
        tricks.append("rot13")

    # High ratio of special characters
    if text:
        special_ratio = len(re.findall(r"[^\w\s]", text)) / len(text)
        if special_ratio > 0.3:
            tricks.append("high_special_chars")

    return tricks


# =============================================================================
# Nova Rule Loading
# =============================================================================


def _extract_rule_blocks(content: str) -> List[str]:
    """Extract individual rule blocks from a .nov file."""
    rule_starts = [m.start() for m in re.finditer(r"rule\s+\w+\s*\{?", content)]

    if not rule_starts:
        return []

    blocks = []
    for i, start in enumerate(rule_starts):
        end = rule_starts[i + 1] if i < len(rule_starts) - 1 else len(content)
        blocks.append(content[start:end].strip())

    return blocks


def _load_rules_from_file(file_path: str) -> List[NovaRule]:
    """Load all rules from a single .nov file using NovaParser."""
    parser = NovaParser()
    rules = []

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    for block in _extract_rule_blocks(content):
        try:
            rule = parser.parse(block)
            if rule:
                rules.append(rule)
        except Exception:
            continue

    return rules


def _load_rules_from_directory(rules_dir: str) -> List[NovaRule]:
    """Load all rules from a directory of .nov files."""
    all_rules = []
    rules_path = Path(rules_dir)

    for nov_file in rules_path.glob("*.nov"):
        try:
            all_rules.extend(_load_rules_from_file(str(nov_file)))
        except Exception:
            continue

    return all_rules


# =============================================================================
# Scanner Class
# =============================================================================


class CarapaceScanner:
    """
    Multi-tier prompt injection scanner using Nova Framework.

    Detection pipeline:
    1. Encoding tricks detection (base64, hex, unicode escapes)
    2. Text sanitization (Unicode normalization, homoglyph replacement)
    3. Nova rules evaluation (keywords, semantics, LLM patterns)
    4. PromptIntel API lookup (optional, requires API key)

    Example:
        >>> scanner = CarapaceScanner()
        >>> result = scanner.scan("ignore all previous instructions")
        >>> print(result["safe"])  # False
        >>> print(result["threats"])  # [{rule, category, severity, matched}]
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        enable_semantics: bool = False,
        enable_llm: bool = False,
    ):
        """
        Initialize the scanner.

        Args:
            rules_dir: Path to directory containing .nov files.
                       Defaults to ./rules relative to this package.
            enable_semantics: Enable semantic matching (requires sentence-transformers)
            enable_llm: Enable LLM evaluation (requires API key)
        """
        if rules_dir is None:
            rules_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "rules"
            )

        self.rules_dir = rules_dir
        self.enable_semantics = enable_semantics
        self.enable_llm = enable_llm
        self.rules: List[NovaRule] = []
        self.matchers: List[NovaMatcher] = []

        self._load_rules()

    def _load_rules(self) -> None:
        """Load Nova rules and create matchers."""
        self.rules = _load_rules_from_directory(self.rules_dir)

        for rule in self.rules:
            try:
                # Create matcher - Nova handles keyword/semantic/LLM evaluation
                # Suppress Nova's print-based warnings about LLM evaluators
                with _suppress_nova_warnings():
                    matcher = NovaMatcher(
                        rule=rule,
                        semantic_evaluator=None if not self.enable_semantics else None,
                        llm_evaluator=None,
                        create_llm_evaluator=self.enable_llm,
                    )
                self.matchers.append(matcher)
            except Exception:
                continue

    def scan(
        self,
        text: str,
        skip_sanitize: bool = False,
        use_promptintel: bool = True,
    ) -> Dict[str, Any]:
        """
        Scan text for prompt injection patterns.

        Args:
            text: Text to scan
            skip_sanitize: Skip pre-processing sanitization
            use_promptintel: Query PromptIntel API if configured

        Returns:
            Dict containing:
                - safe: bool - True if no threats detected
                - threats: List[Dict] - Detected threats with details
                - count: int - Number of threats
                - highest_severity: str - Highest threat severity
                - encoding_tricks: List[str] - Detected encoding tricks
                - promptintel: Optional[Dict] - PromptIntel API response
        """
        if not text:
            return self._empty_result()

        threats: List[Dict[str, Any]] = []

        # Step 1: Detect encoding tricks on original text
        encoding_tricks = detect_encoding_tricks(text)
        for trick in encoding_tricks:
            threats.append({
                "rule": "encoding_evasion",
                "category": f"obfuscation/{trick}",
                "severity": "medium",
                "matched": trick,
            })

        # Step 2: Sanitize text
        clean_text = text if skip_sanitize else sanitize_text(text)

        # Step 3: Evaluate Nova rules using NovaMatcher.check_prompt()
        for matcher in self.matchers:
            try:
                result = matcher.check_prompt(clean_text)
                if result.get("matched"):
                    # Extract matched patterns for reporting
                    matched_patterns = []
                    for key, val in result.get("matching_keywords", {}).items():
                        if val:
                            matched_patterns.append(key)
                    for key, val in result.get("matching_semantics", {}).items():
                        if val:
                            matched_patterns.append(key)
                    for key, val in result.get("matching_llm", {}).items():
                        if val:
                            matched_patterns.append(key)

                    threats.append({
                        "rule": result.get("rule_name", "unknown"),
                        "category": result.get("meta", {}).get("category", "unknown"),
                        "severity": result.get("meta", {}).get("severity", "medium"),
                        "matched": ", ".join(matched_patterns) if matched_patterns else "rule match",
                    })
            except Exception:
                continue

        # Step 4: PromptIntel lookup
        promptintel_result = None
        if use_promptintel and check_promptintel_available():
            promptintel_result = lookup_promptintel(clean_text)
            if promptintel_result:
                for hit in promptintel_result.get("hits", []):
                    threats.append({
                        "rule": hit.get("id", "promptintel_iopc"),
                        "category": hit.get("type", "promptintel/unknown"),
                        "severity": hit.get("risk", "medium"),
                        "matched": hit.get("pattern", "IoPC match"),
                        "source": "promptintel",
                    })

        return {
            "safe": len(threats) == 0,
            "threats": threats,
            "count": len(threats),
            "highest_severity": self._highest_severity(threats),
            "encoding_tricks": encoding_tricks,
            "promptintel": promptintel_result,
        }

    def scan_command(self, command: str) -> Dict[str, Any]:
        """
        Scan a shell command for dangerous patterns.

        Args:
            command: Shell command to analyze

        Returns:
            Dict with scan results (same format as scan())
        """
        threats: List[Dict[str, Any]] = []

        # Check against dangerous command patterns
        for pattern, category, severity in DANGEROUS_COMMAND_PATTERNS:
            match = re.search(pattern, command)
            if match:
                threats.append({
                    "rule": "dangerous_command",
                    "category": category,
                    "severity": severity,
                    "matched": match.group(0),
                })

        # Also run text scan
        text_result = self.scan(command, use_promptintel=False)
        threats.extend(text_result.get("threats", []))

        return {
            "safe": len(threats) == 0,
            "threats": threats,
            "count": len(threats),
            "highest_severity": self._highest_severity(threats),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        categories = {rule.meta.get("category", "unknown") for rule in self.rules}

        return {
            "rules_loaded": len(self.rules),
            "matchers_active": len(self.matchers),
            "categories": sorted(categories),
            "rules_dir": self.rules_dir,
            "promptintel_configured": check_promptintel_available(),
        }

    @staticmethod
    def _highest_severity(threats: List[Dict]) -> Optional[str]:
        """Get the highest severity level from threats."""
        if not threats:
            return None

        max_level = 0
        max_severity = None

        for threat in threats:
            level = SEVERITY_ORDER.get(threat.get("severity", "medium"), 2)
            if level > max_level:
                max_level = level
                max_severity = threat["severity"]

        return max_severity

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        """Return an empty scan result."""
        return {
            "safe": True,
            "threats": [],
            "count": 0,
            "highest_severity": None,
            "encoding_tricks": [],
            "promptintel": None,
        }
