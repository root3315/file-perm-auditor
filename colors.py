"""
Terminal color support for file-perm-auditor.
"""

import sys


class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_MAGENTA = "\033[95m"

    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"

    @classmethod
    def disable(cls):
        """Disable all colors by setting codes to empty strings."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.BLACK = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BRIGHT_RED = ""
        cls.BRIGHT_YELLOW = ""
        cls.BRIGHT_MAGENTA = ""
        cls.BG_RED = ""
        cls.BG_YELLOW = ""


def supports_color():
    """Check if the terminal supports color output."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False

    term = os.environ.get("TERM", "").lower()
    if term in ("dumb", "unknown"):
        return False

    return True


import os


def init_colors(force_color=False):
    """Initialize color support based on terminal capabilities."""
    if not force_color and not supports_color():
        Colors.disable()
        return False
    return True


def get_severity_color(severity):
    """Get the appropriate color for a severity level."""
    severity_colors = {
        "CRITICAL": Colors.BRIGHT_RED + Colors.BOLD,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.BRIGHT_YELLOW,
        "LOW": Colors.CYAN,
    }
    return severity_colors.get(severity, Colors.WHITE)


def colorize(text, color_code):
    """Wrap text with color codes."""
    return f"{color_code}{text}{Colors.RESET}"


def format_header(text):
    """Format a header line with bold styling."""
    return colorize(text, Colors.BOLD + Colors.CYAN)


def format_section(text):
    """Format a section divider with dim styling."""
    return colorize(text, Colors.DIM)


def format_severity(severity):
    """Format severity level with appropriate color."""
    color = get_severity_color(severity)
    return colorize(f"[{severity}]", color)
