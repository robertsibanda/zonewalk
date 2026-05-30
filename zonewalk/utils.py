"""
Terminal styling and display helpers for zonewalk.

Provides ANSI colour constants and convenience printers so every
module can produce consistent, colour-coded terminal output without
pulling in an external library like ``rich`` or ``colorama``.
"""

import sys
from datetime import datetime
from typing import Optional


class Style:
    """ANSI escape codes for terminal colours and status badges."""

    # Basic colours
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    MAGENTA = "\033[1;35m"
    WHITE = "\033[1;37m"
    GRAY = "\033[0;90m"
    NC = "\033[0m"  # reset / no colour

    # Composite status badges used throughout the output
    OK = f"{GREEN}OK{NC}"
    FAIL = f"{RED}FAIL{NC}"
    WARN = f"{YELLOW}WARN{NC}"
    INFO = f"{CYAN}INFO{NC}"


# ---------------------------------------------------------------------------
# Section printers – each wraps content in a consistent visual frame
# ---------------------------------------------------------------------------


def header(title: str) -> None:
    """Print a major section header (blue, full-width)."""
    print(f"\n{Style.BLUE}{'=' * 50}{Style.NC}")
    print(f"{Style.WHITE}  {title}{Style.NC}")
    print(f"{Style.BLUE}{'=' * 50}{Style.NC}")


def section(title: str) -> None:
    """Print a sub-section header (magenta, half-width)."""
    print(f"\n{Style.MAGENTA}>> {title}{Style.NC}")
    print(f"{Style.MAGENTA}{'-' * 50}{Style.NC}")


def subsection(title: str) -> None:
    """Print a smaller grouping level (cyan, indented)."""
    print(f"\n  {Style.CYAN}* {title}{Style.NC}")


# ---------------------------------------------------------------------------
# Inline status printers – one-liners for individual check results
# ---------------------------------------------------------------------------


def note(msg: str) -> None:
    """Print a dimmed informational note."""
    print(f"  {Style.GRAY}-> {msg}{Style.NC}")


def ok(msg: str) -> None:
    """Print a passing check result."""
    print(f"  {Style.OK} {msg}")


def fail(msg: str) -> None:
    """Print a failing check result."""
    print(f"  {Style.FAIL} {msg}")


def warn(msg: str) -> None:
    """Print a warning-level check result."""
    print(f"  {Style.WARN} {msg}")


def info(msg: str) -> None:
    """Print an informational (non-pass/non-fail) result."""
    print(f"  {Style.INFO} {msg}")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def days_until(date_str: str) -> Optional[int]:
    """Calculate calendar days between *now* and *date_str* (ISO format).

    Returns ``None`` when the string cannot be parsed.
    Used by the whois expiry check to determine urgency.
    """
    try:
        exp = datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        return (exp - datetime.now()).days
    except (ValueError, IndexError):
        return None


def plural(n: int, word: str) -> str:
    """Simple pluraliser – appends an ``s`` when *n* != 1."""
    return f"{n} {word}{'s' if n != 1 else ''}"
