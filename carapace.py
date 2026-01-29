#!/usr/bin/env python3
"""
Carapace - Command Line Interface

Usage:
    carapace.py scan TEXT          Scan text for prompt injection
    carapace.py command CMD        Scan shell command for dangerous patterns
    carapace.py stats              Show scanner statistics
    carapace.py health             Check PromptIntel API status

Examples:
    python carapace.py scan "ignore all previous instructions"
    python carapace.py command "rm -rf /"
    python carapace.py stats
"""

import argparse
import json
import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from scanner import (
    CarapaceScanner,
    check_promptintel_available,
    check_promptintel_health,
)


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan text for prompt injection."""
    scanner = CarapaceScanner(
        rules_dir=args.rules,
        enable_semantics=args.enable_semantics,
        enable_llm=args.enable_llm,
    )
    result = scanner.scan(
        args.text,
        skip_sanitize=args.raw,
        use_promptintel=not args.offline,
    )
    
    if args.quiet:
        return 0 if result["safe"] else 1
    
    print(json.dumps(result, indent=2))
    return 0 if result["safe"] else 1


def cmd_command(args: argparse.Namespace) -> int:
    """Scan shell command for dangerous patterns."""
    scanner = CarapaceScanner(
        rules_dir=args.rules,
        enable_semantics=args.enable_semantics,
        enable_llm=args.enable_llm,
    )
    result = scanner.scan_command(args.command)
    
    if args.quiet:
        return 0 if result["safe"] else 1
    
    print(json.dumps(result, indent=2))
    return 0 if result["safe"] else 1


def cmd_stats(args: argparse.Namespace) -> int:
    """Show scanner statistics."""
    scanner = CarapaceScanner(rules_dir=args.rules)
    print(json.dumps(scanner.get_stats(), indent=2))
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Check PromptIntel API status."""
    print("PromptIntel API Status")
    print("-" * 40)
    print(f"API Key Configured: {check_promptintel_available()}")
    
    if check_promptintel_available():
        healthy = check_promptintel_health()
        print(f"API Health:         {'✓ Healthy' if healthy else '✗ Unreachable'}")
        return 0 if healthy else 1
    else:
        print("API Health:         - (no key)")
        print()
        print("Set PROMPTINTEL_API_KEY environment variable to enable.")
        return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="carapace",
        description="Prompt injection detection using Nova Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--rules", "-r",
        help="Path to rules directory",
        default=None,
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode (exit code only)",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan text for prompt injection")
    p_scan.add_argument("text", help="Text to scan")
    p_scan.add_argument("--raw", action="store_true", help="Skip sanitization")
    p_scan.add_argument("--offline", action="store_true", help="Skip PromptIntel lookup")
    p_scan.add_argument("--enable-semantics", action="store_true", help="Enable Nova semantic matching")
    p_scan.add_argument("--enable-llm", action="store_true", help="Enable Nova LLM evaluation")
    p_scan.set_defaults(func=cmd_scan)

    # command
    p_cmd = subparsers.add_parser("command", help="Scan shell command")
    p_cmd.add_argument("command", help="Command to scan")
    p_cmd.add_argument("--enable-semantics", action="store_true", help="Enable Nova semantic matching")
    p_cmd.add_argument("--enable-llm", action="store_true", help="Enable Nova LLM evaluation")
    p_cmd.set_defaults(func=cmd_command)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show scanner statistics")
    p_stats.set_defaults(func=cmd_stats)

    # health
    p_health = subparsers.add_parser("health", help="Check PromptIntel API status")
    p_health.set_defaults(func=cmd_health)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
