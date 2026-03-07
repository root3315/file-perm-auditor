#!/usr/bin/env python3
"""
File Permission Auditor - CLI tool to audit file permissions and find security issues.
"""

import argparse
import os
import stat
import sys
from pathlib import Path
from datetime import datetime

from colors import (
    Colors,
    init_colors,
    format_header,
    format_section,
    format_severity,
    colorize,
)


SECURITY_ISSUES = {
    "world_writable": {
        "mask": stat.S_IWOTH,
        "severity": "HIGH",
        "description": "File is writable by anyone (world-writable)"
    },
    "world_executable": {
        "mask": stat.S_IXOTH,
        "severity": "MEDIUM",
        "description": "File is executable by anyone (world-executable)"
    },
    "suid_bit": {
        "mask": stat.S_ISUID,
        "severity": "CRITICAL",
        "description": "SUID bit set - runs with owner privileges"
    },
    "sgid_bit": {
        "mask": stat.S_ISGID,
        "severity": "HIGH",
        "description": "SGID bit set - runs with group privileges"
    },
    "group_writable": {
        "mask": stat.S_IWGRP,
        "severity": "MEDIUM",
        "description": "File is writable by group members"
    }
}

SENSITIVE_PATTERNS = [
    ".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".gnupg", "shadow", "passwd", "sudoers", ".env",
    "credentials", "secret", "private_key"
]


def get_permission_octal(mode):
    """Convert file mode to octal permission string."""
    return oct(mode)[-3:]


def get_permission_symbolic(mode):
    """Convert file mode to symbolic permission string."""
    perms = ""
    for who in ["USR", "GRP", "OTH"]:
        for what in ["R", "W", "X"]:
            flag = getattr(stat, f"S_I{what}{who}")
            if mode & flag:
                perms += what.lower()
            else:
                perms += "-"
    return perms


def check_sensitive_file(filepath):
    """Check if file path matches sensitive patterns."""
    path_lower = filepath.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in path_lower:
            return True
    return False


def audit_file(filepath, base_path):
    """Audit a single file for permission issues."""
    issues = []

    try:
        file_stat = os.stat(filepath)
    except (OSError, PermissionError) as e:
        return {
            "path": filepath,
            "error": str(e),
            "issues": []
        }

    mode = file_stat.st_mode

    if stat.S_ISREG(mode) or stat.S_ISDIR(mode):
        for issue_name, issue_info in SECURITY_ISSUES.items():
            if mode & issue_info["mask"]:
                rel_path = os.path.relpath(filepath, base_path)
                issues.append({
                    "type": issue_name,
                    "severity": issue_info["severity"],
                    "description": issue_info["description"],
                    "path": rel_path
                })

        if stat.S_ISREG(mode) and check_sensitive_file(filepath):
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                rel_path = os.path.relpath(filepath, base_path)
                issues.append({
                    "type": "sensitive_exposed",
                    "severity": "CRITICAL",
                    "description": "Sensitive file has loose permissions",
                    "path": rel_path
                })

    return {
        "path": filepath,
        "mode_octal": get_permission_octal(mode),
        "mode_symbolic": get_permission_symbolic(mode),
        "uid": file_stat.st_uid,
        "gid": file_stat.st_gid,
        "issues": issues
    }


def scan_directory(target_path, recursive=True, extensions=None):
    """Scan directory for files and audit permissions."""
    results = []
    target = Path(target_path)

    if not target.exists():
        print(f"Error: Path '{target_path}' does not exist", file=sys.stderr)
        return results

    if target.is_file():
        result = audit_file(str(target), str(target.parent))
        return [result]

    if recursive:
        file_iterator = target.rglob("*")
    else:
        file_iterator = target.glob("*")

    for filepath in file_iterator:
        try:
            if extensions:
                if filepath.suffix not in extensions:
                    continue

            if filepath.is_symlink():
                continue

            result = audit_file(str(filepath), str(target))
            if result.get("issues") or not result.get("error"):
                results.append(result)

        except (OSError, PermissionError):
            continue

    return results


def format_report(results, output_format="text"):
    """Format audit results for output."""
    if output_format == "json":
        import json
        return json.dumps(results, indent=2)

    lines = []
    lines.append(format_header("=" * 70))
    lines.append(format_header("FILE PERMISSION AUDIT REPORT"))
    lines.append(
        format_section(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    )
    lines.append(format_header("=" * 70))

    total_files = len(results)
    files_with_issues = sum(1 for r in results if r.get("issues"))
    total_issues = sum(len(r.get("issues", [])) for r in results)

    lines.append("")
    summary_text = (
        f"Summary: {total_files} files scanned, {files_with_issues} with issues"
    )
    if files_with_issues > 0:
        lines.append(colorize(summary_text, Colors.BOLD + Colors.YELLOW))
    else:
        lines.append(colorize(summary_text, Colors.GREEN))

    lines.append(colorize(f"Total security issues found: {total_issues}", Colors.BOLD))
    lines.append("")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_issues = []

    for result in results:
        for issue in result.get("issues", []):
            all_issues.append(issue)

    all_issues.sort(key=lambda x: severity_order.get(x["severity"], 99))

    if all_issues:
        lines.append(format_section("-" * 70))
        lines.append(format_header("SECURITY ISSUES (sorted by severity)"))
        lines.append(format_section("-" * 70))

        for issue in all_issues:
            lines.append("")
            severity_formatted = format_severity(issue["severity"])
            lines.append(f"{severity_formatted} {colorize(issue['type'], Colors.BOLD)}")
            lines.append(f"  {colorize('Path:', Colors.CYAN)} {issue['path']}")
            lines.append(f"  {colorize('Description:', Colors.CYAN)} {issue['description']}")
    else:
        lines.append("")
        lines.append(colorize("No security issues detected!", Colors.GREEN + Colors.BOLD))

    lines.append("")
    lines.append(format_section("=" * 70))
    lines.append(format_header("END OF REPORT"))
    lines.append(format_section("=" * 70))

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Audit file permissions and find security issues"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target file or directory to audit (default: current directory)"
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        default=True,
        help="Recursively scan directories (default: True)"
    )
    parser.add_argument(
        "-n", "--no-recursive",
        action="store_true",
        help="Disable recursive scanning"
    )
    parser.add_argument(
        "-e", "--extensions",
        nargs="+",
        help="Filter by file extensions (e.g., .py .sh .conf)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only show files with issues"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color output"
    )

    args = parser.parse_args()

    init_colors(force_color=not args.no_color)

    recursive = not args.no_recursive if args.no_recursive else args.recursive

    extensions = None
    if args.extensions:
        extensions = [ext if ext.startswith(".") else f".{ext}" for ext in args.extensions]

    results = scan_directory(args.path, recursive=recursive, extensions=extensions)

    if args.quiet:
        results = [r for r in results if r.get("issues")]

    report = format_report(results, output_format=args.format)
    print(report)

    issues_count = sum(len(r.get("issues", [])) for r in results)
    sys.exit(0 if issues_count == 0 else 1)


if __name__ == "__main__":
    main()
