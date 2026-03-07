#!/usr/bin/env python3
"""Unit tests for file-perm-auditor."""

import os
import stat
import tempfile
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from colors import (
    Colors,
    init_colors,
    get_severity_color,
    colorize,
    format_header,
    format_section,
    format_severity,
    supports_color,
)

from file_perm_auditor import (
    SECURITY_ISSUES,
    SENSITIVE_PATTERNS,
    get_permission_octal,
    get_permission_symbolic,
    check_sensitive_file,
    audit_file,
    scan_directory,
    format_report,
)


class TestPermissionConversion(unittest.TestCase):
    """Tests for permission conversion functions."""

    def test_get_permission_octal_standard(self):
        """Test octal conversion for standard permissions."""
        self.assertEqual(get_permission_octal(0o755), "755")
        self.assertEqual(get_permission_octal(0o644), "644")
        self.assertEqual(get_permission_octal(0o777), "777")

    def test_get_permission_octal_with_special_bits(self):
        """Test octal conversion with SUID/SGID/sticky bits."""
        self.assertEqual(get_permission_octal(0o4755), "755")
        self.assertEqual(get_permission_octal(0o2755), "755")
        self.assertEqual(get_permission_octal(0o644), "644")

    def test_get_permission_symbolic_basic(self):
        """Test symbolic conversion for basic permissions."""
        mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # rwx------
        mode |= stat.S_IRGRP | stat.S_IXGRP  # r-x
        mode |= stat.S_IROTH | stat.S_IXOTH  # r-x
        self.assertEqual(get_permission_symbolic(mode), "rwxr-xr-x")

    def test_get_permission_symbolic_no_permissions(self):
        """Test symbolic conversion with no permissions."""
        mode = 0o000
        self.assertEqual(get_permission_symbolic(mode), "---------")

    def test_get_permission_symbolic_all_permissions(self):
        """Test symbolic conversion with all permissions."""
        mode = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
        self.assertEqual(get_permission_symbolic(mode), "rwxrwxrwx")


class TestSensitiveFileDetection(unittest.TestCase):
    """Tests for sensitive file pattern detection."""

    def test_ssh_patterns(self):
        """Test SSH-related patterns are detected."""
        self.assertTrue(check_sensitive_file("/home/user/.ssh/id_rsa"))
        self.assertTrue(check_sensitive_file("/home/user/.ssh/authorized_keys"))
        self.assertTrue(check_sensitive_file("id_ecdsa"))
        self.assertTrue(check_sensitive_file("id_ed25519"))

    def test_gnupg_pattern(self):
        """Test GnuPG pattern detection."""
        self.assertTrue(check_sensitive_file("/home/user/.gnupg/secring.gpg"))

    def test_system_file_patterns(self):
        """Test system file pattern detection."""
        self.assertTrue(check_sensitive_file("/etc/shadow"))
        self.assertTrue(check_sensitive_file("/etc/passwd"))
        self.assertTrue(check_sensitive_file("/etc/sudoers"))

    def test_env_and_credentials(self):
        """Test environment and credentials patterns."""
        self.assertTrue(check_sensitive_file("/app/.env"))
        self.assertTrue(check_sensitive_file("/app/credentials.json"))
        self.assertTrue(check_sensitive_file("/app/secret.txt"))
        self.assertTrue(check_sensitive_file("/app/private_key.pem"))

    def test_case_insensitive(self):
        """Test pattern matching is case insensitive."""
        self.assertTrue(check_sensitive_file("/HOME/USER/.SSH/ID_RSA"))
        self.assertTrue(check_sensitive_file("CREDENTIALS.TXT"))

    def test_non_sensitive_files(self):
        """Test non-sensitive files are not flagged."""
        self.assertFalse(check_sensitive_file("/home/user/document.txt"))
        self.assertFalse(check_sensitive_file("/var/log/syslog"))
        self.assertFalse(check_sensitive_file("/tmp/cache.dat"))


class TestAuditFile(unittest.TestCase):
    """Tests for file auditing functionality."""

    def setUp(self):
        """Create temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_audit_file_no_issues(self):
        """Test auditing a file with secure permissions."""
        test_file = os.path.join(self.test_dir, "secure.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.chmod(test_file, 0o644)

        result = audit_file(test_file, self.test_dir)

        self.assertEqual(result["path"], test_file)
        self.assertEqual(result["mode_octal"], "644")
        self.assertEqual(len(result["issues"]), 0)
        self.assertIsNone(result.get("error"))

    def test_audit_file_world_writable(self):
        """Test detection of world-writable files."""
        test_file = os.path.join(self.test_dir, "world_writable.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.chmod(test_file, 0o666)

        result = audit_file(test_file, self.test_dir)

        self.assertEqual(result["mode_octal"], "666")
        issue_types = [i["type"] for i in result["issues"]]
        self.assertIn("world_writable", issue_types)
        self.assertIn("group_writable", issue_types)

    def test_audit_file_world_executable(self):
        """Test detection of world-executable files."""
        test_file = os.path.join(self.test_dir, "script.sh")
        with open(test_file, "w") as f:
            f.write("#!/bin/bash")
        os.chmod(test_file, 0o755)

        result = audit_file(test_file, self.test_dir)

        issues = [i for i in result["issues"] if i["type"] == "world_executable"]
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "MEDIUM")

    def test_audit_file_suid_bit(self):
        """Test detection of SUID bit."""
        test_file = os.path.join(self.test_dir, "suid_binary")
        with open(test_file, "w") as f:
            f.write("binary")
        os.chmod(test_file, 0o4755)

        result = audit_file(test_file, self.test_dir)

        suid_issues = [i for i in result["issues"] if i["type"] == "suid_bit"]
        self.assertEqual(len(suid_issues), 1)
        self.assertEqual(suid_issues[0]["severity"], "CRITICAL")

    def test_audit_file_sgid_bit(self):
        """Test detection of SGID bit."""
        test_file = os.path.join(self.test_dir, "sgid_binary")
        with open(test_file, "w") as f:
            f.write("binary")
        os.chmod(test_file, 0o2755)

        result = audit_file(test_file, self.test_dir)

        sgid_issues = [i for i in result["issues"] if i["type"] == "sgid_bit"]
        self.assertEqual(len(sgid_issues), 1)
        self.assertEqual(sgid_issues[0]["severity"], "HIGH")

    def test_audit_file_group_writable(self):
        """Test detection of group-writable files."""
        test_file = os.path.join(self.test_dir, "group_writable.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.chmod(test_file, 0o664)

        result = audit_file(test_file, self.test_dir)

        gw_issues = [i for i in result["issues"] if i["type"] == "group_writable"]
        self.assertEqual(len(gw_issues), 1)
        self.assertEqual(gw_issues[0]["severity"], "MEDIUM")

    def test_audit_sensitive_file_exposed(self):
        """Test detection of exposed sensitive files."""
        test_file = os.path.join(self.test_dir, ".env")
        with open(test_file, "w") as f:
            f.write("SECRET=value")
        os.chmod(test_file, 0o666)

        result = audit_file(test_file, self.test_dir)

        sensitive_issues = [i for i in result["issues"] if i["type"] == "sensitive_exposed"]
        self.assertEqual(len(sensitive_issues), 1)
        self.assertEqual(sensitive_issues[0]["severity"], "CRITICAL")

    def test_audit_nonexistent_file(self):
        """Test auditing a non-existent file."""
        result = audit_file("/nonexistent/path/file.txt", self.test_dir)

        self.assertIsNotNone(result.get("error"))
        self.assertEqual(result["issues"], [])

    def test_audit_directory(self):
        """Test auditing a directory."""
        test_dir = os.path.join(self.test_dir, "testdir")
        os.makedirs(test_dir)
        os.chmod(test_dir, 0o777)

        result = audit_file(test_dir, self.test_dir)

        world_writable = [i for i in result["issues"] if i["type"] == "world_writable"]
        self.assertEqual(len(world_writable), 1)


class TestScanDirectory(unittest.TestCase):
    """Tests for directory scanning functionality."""

    def setUp(self):
        """Create temporary directory structure for testing."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_scan_nonexistent_path(self):
        """Test scanning a non-existent path."""
        results = scan_directory("/nonexistent/path")
        self.assertEqual(results, [])

    def test_scan_single_file(self):
        """Test scanning a single file."""
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.chmod(test_file, 0o644)

        results = scan_directory(test_file)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["path"], test_file)

    def test_scan_directory_non_recursive(self):
        """Test non-recursive directory scanning."""
        subdir = os.path.join(self.test_dir, "subdir")
        os.makedirs(subdir)

        with open(os.path.join(self.test_dir, "file1.txt"), "w") as f:
            f.write("test")
        with open(os.path.join(subdir, "file2.txt"), "w") as f:
            f.write("test")

        results = scan_directory(self.test_dir, recursive=False)

        paths = [r["path"] for r in results]
        self.assertTrue(any("file1.txt" in p for p in paths))
        self.assertFalse(any("file2.txt" in p for p in paths))

    def test_scan_directory_recursive(self):
        """Test recursive directory scanning."""
        subdir = os.path.join(self.test_dir, "subdir")
        os.makedirs(subdir)

        with open(os.path.join(self.test_dir, "file1.txt"), "w") as f:
            f.write("test")
        with open(os.path.join(subdir, "file2.txt"), "w") as f:
            f.write("test")

        results = scan_directory(self.test_dir, recursive=True)

        paths = [r["path"] for r in results]
        self.assertTrue(any("file1.txt" in p for p in paths))
        self.assertTrue(any("file2.txt" in p for p in paths))

    def test_scan_with_extension_filter(self):
        """Test scanning with extension filter."""
        with open(os.path.join(self.test_dir, "file1.py"), "w") as f:
            f.write("test")
        with open(os.path.join(self.test_dir, "file2.txt"), "w") as f:
            f.write("test")
        with open(os.path.join(self.test_dir, "file3.py"), "w") as f:
            f.write("test")

        results = scan_directory(self.test_dir, extensions=[".py"])

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertTrue(result["path"].endswith(".py"))

    def test_scan_skips_symlinks(self):
        """Test that symlinks are skipped during scanning."""
        test_file = os.path.join(self.test_dir, "real_file.txt")
        symlink_path = os.path.join(self.test_dir, "link.txt")

        with open(test_file, "w") as f:
            f.write("test")
        os.symlink(test_file, symlink_path)

        results = scan_directory(self.test_dir)

        paths = [r["path"] for r in results]
        self.assertTrue(any("real_file.txt" in p for p in paths))
        self.assertFalse(any("link.txt" in p for p in paths))


class TestFormatReport(unittest.TestCase):
    """Tests for report formatting functionality."""

    def test_format_report_json(self):
        """Test JSON output format."""
        results = [
            {
                "path": "/test/file.txt",
                "mode_octal": "644",
                "issues": []
            }
        ]

        report = format_report(results, output_format="json")

        import json
        parsed = json.loads(report)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["path"], "/test/file.txt")

    def test_format_report_text_with_issues(self):
        """Test text output with security issues."""
        results = [
            {
                "path": "/test/insecure.txt",
                "mode_octal": "666",
                "issues": [
                    {
                        "type": "world_writable",
                        "severity": "HIGH",
                        "description": "File is writable by anyone",
                        "path": "insecure.txt"
                    }
                ]
            }
        ]

        report = format_report(results, output_format="text")

        self.assertIn("FILE PERMISSION AUDIT REPORT", report)
        self.assertIn("world_writable", report)
        self.assertIn("HIGH", report)

    def test_format_report_text_no_issues(self):
        """Test text output with no security issues."""
        results = [
            {
                "path": "/test/secure.txt",
                "mode_octal": "644",
                "issues": []
            }
        ]

        report = format_report(results, output_format="text")

        self.assertIn("No security issues detected", report)

    def test_format_report_summary(self):
        """Test report summary statistics."""
        results = [
            {"path": "/test/file1.txt", "mode_octal": "644", "issues": []},
            {"path": "/test/file2.txt", "mode_octal": "666", "issues": [{"type": "world_writable", "severity": "HIGH", "description": "test", "path": "file2.txt"}]},
        ]

        report = format_report(results, output_format="text")

        self.assertIn("2 files scanned", report)
        self.assertIn("1 with issues", report)
        self.assertIn("Total security issues found: 1", report)


class TestColorsModule(unittest.TestCase):
    """Tests for colors module functions."""

    def test_colorize(self):
        """Test colorize function adds color codes."""
        result = colorize("test", Colors.RED)
        self.assertIn("test", result)
        self.assertTrue(result.startswith("\033["))

    def test_colorize_with_reset(self):
        """Test colorize function includes reset code."""
        result = colorize("test", Colors.GREEN)
        self.assertTrue(result.endswith(Colors.RESET))

    def test_format_header(self):
        """Test header formatting."""
        result = format_header("Test Header")
        self.assertIn("Test Header", result)

    def test_format_section(self):
        """Test section formatting."""
        result = format_section("Test Section")
        self.assertIn("Test Section", result)

    def test_format_severity_critical(self):
        """Test CRITICAL severity formatting."""
        result = format_severity("CRITICAL")
        self.assertIn("CRITICAL", result)

    def test_format_severity_high(self):
        """Test HIGH severity formatting."""
        result = format_severity("HIGH")
        self.assertIn("HIGH", result)

    def test_format_severity_medium(self):
        """Test MEDIUM severity formatting."""
        result = format_severity("MEDIUM")
        self.assertIn("MEDIUM", result)

    def test_format_severity_low(self):
        """Test LOW severity formatting."""
        result = format_severity("LOW")
        self.assertIn("LOW", result)

    def test_get_severity_color_critical(self):
        """Test severity color for CRITICAL."""
        color = get_severity_color("CRITICAL")
        self.assertIn(Colors.BRIGHT_RED, color)

    def test_get_severity_color_high(self):
        """Test severity color for HIGH."""
        color = get_severity_color("HIGH")
        self.assertEqual(color, Colors.RED)

    def test_get_severity_color_unknown(self):
        """Test severity color for unknown level."""
        color = get_severity_color("UNKNOWN")
        self.assertEqual(color, Colors.WHITE)

    def test_init_colors_returns_bool(self):
        """Test init_colors returns boolean."""
        result = init_colors(force_color=True)
        self.assertIsInstance(result, bool)

    @patch.dict(os.environ, {"TERM": "dumb"})
    def test_supports_color_dumb_term(self):
        """Test supports_color returns False for dumb terminal."""
        result = supports_color()
        self.assertFalse(result)


class TestSecurityIssuesConfiguration(unittest.TestCase):
    """Tests for security issue configuration."""

    def test_security_issues_has_required_keys(self):
        """Test SECURITY_ISSUES has all required keys."""
        required_keys = ["mask", "severity", "description"]
        for issue_name, issue_info in SECURITY_ISSUES.items():
            for key in required_keys:
                self.assertIn(key, issue_info, f"Missing key '{key}' in '{issue_name}'")

    def test_security_issues_severity_values(self):
        """Test all severity values are valid."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for issue_name, issue_info in SECURITY_ISSUES.items():
            self.assertIn(
                issue_info["severity"],
                valid_severities,
                f"Invalid severity '{issue_info['severity']}' in '{issue_name}'"
            )

    def test_sensitive_patterns_not_empty(self):
        """Test SENSITIVE_PATTERNS is not empty."""
        self.assertGreater(len(SENSITIVE_PATTERNS), 0)

    def test_sensitive_patterns_are_strings(self):
        """Test all sensitive patterns are strings."""
        for pattern in SENSITIVE_PATTERNS:
            self.assertIsInstance(pattern, str)


if __name__ == "__main__":
    unittest.main()
