# file-perm-auditor

CLI tool to audit file permissions and find security issues. I wrote this because I kept forgetting to check for world-writable files and SUID bits before deploying stuff.

## Why

Ever deployed something only to realize later that your config files were `777`? Or forgot to check if some random script has the SUID bit set? Yeah, me too. This tool scans a directory and tells you what's sketchy.

## Quick Start

```bash
python file_perm_auditor.py /path/to/scan
```

That's it. It'll show you all the permission issues it finds.

## What It Checks

- **World-writable files** (HIGH) - Anyone can modify these
- **World-executable files** (MEDIUM) - Anyone can run these
- **SUID bit** (CRITICAL) - Runs with owner privileges, potential escalation
- **SGID bit** (HIGH) - Runs with group privileges
- **Group-writable files** (MEDIUM) - Group members can modify
- **Sensitive files with loose perms** (CRITICAL) - SSH keys, .env files, etc.

## Usage Examples

Scan current directory recursively:
```bash
python file_perm_auditor.py
```

Scan a specific directory:
```bash
python file_perm_auditor.py /etc/myapp
```

Non-recursive scan (top level only):
```bash
python file_perm_auditor.py -n /var/www
```

Filter by file extension:
```bash
python file_perm_auditor.py -e .py .sh /home/user/scripts
```

JSON output for piping to other tools:
```bash
python file_perm_auditor.py -f json /opt > audit.json
```

Quiet mode (only show files with issues):
```bash
python file_perm_auditor.py -q /large/directory
```

## Exit Codes

- `0` - No issues found
- `1` - Security issues detected

Useful for CI/CD pipelines:
```bash
python file_perm_auditor.py /deploy && echo "All good" || echo "Fix permissions!"
```

## Output

The report shows:
- Summary of files scanned
- Issues sorted by severity (CRITICAL > HIGH > MEDIUM)
- File path relative to scan target
- Permission details

## Notes

- Symlinks are skipped (don't follow them by default)
- Sensitive patterns include: `.ssh`, `id_rsa`, `.env`, `credentials`, `shadow`, etc.
- Works on Linux and macOS (uses standard `stat` module)

## License

Do whatever you want with it.
