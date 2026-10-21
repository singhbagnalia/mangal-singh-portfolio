#!/usr/bin/env python3
"""Local portfolio publication guard. Never prints file contents or secret values.
Default: inspect every tracked file in the Git index. --staged: changed index files.
No network, package installation, hooks installation, or repository writes.
"""
import argparse
import pathlib
import re
import subprocess
import sys

ALLOWED = {
    'README.md', 'index.html', 'PUBLISHING_GUIDE.md', 'SECURITY.md', '.gitignore',
    '.github/scripts/upload_guard.py', '.github/workflows/publication-guard.yml',
    '.githooks/pre-commit',
}
MAX_BYTES = 256 * 1024
RULES = {
    'private key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    'GitHub token': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b'),
    'AWS access key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'Google API key': re.compile(rb'\bAIza[A-Za-z0-9_-]{30,}\b'),
    'API secret token': re.compile(rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b'),
    'credential assignment': re.compile(rb'''(?i)(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*["'][^"'\r\n]{6,}["']'''),
    'HDL source signature': re.compile(rb'(?mi)^\s*(?:(?:module|endmodule)\b|entity\s+\w+\s+is\b|architecture\s+\w+\s+of\b)'),
    'archive/binary signature': re.compile(rb'\A(?:PK\x03\x04|\x1f\x8b|7z\xbc\xaf\x27\x1c|Rar!|%PDF-|SQLite format 3\x00)'),
}
def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE)

def inspect(repo, staged=False):
    problems = []
    if staged:
        paths = git(repo, 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z').split(b'\0')
    else:
        paths = git(repo, 'ls-files', '-z').split(b'\0')
    seen = set()
    for raw in paths:
        if not raw:
            continue
        path = raw.decode('utf-8', 'surrogateescape')
        if path in seen:
            continue
        seen.add(path)
        # repr escapes newlines/control characters in malicious filenames.
        label = repr(path)
        if path not in ALLOWED:
            problems.append((label, 'file is outside the approved public portfolio allowlist'))
            continue
        entry = git(repo, 'ls-files', '--stage', '-z', '--', path).split(b'\0')[0]
        mode = entry.split(b' ', 1)[0]
        if mode != b'100644' and not (path == '.githooks/pre-commit' and mode == b'100755'):
            problems.append((label, 'symlink, submodule, executable, or unsupported index mode'))
            continue
        data = git(repo, 'show', ':' + path)
        if len(data) > MAX_BYTES:
            problems.append((label, 'file exceeds public portfolio size limit'))
            continue
        if b'\0' in data:
            problems.append((label, 'binary data is not permitted'))
            continue
        try:
            data.decode('utf-8')
        except UnicodeDecodeError:
            problems.append((label, 'non-UTF-8 data requires owner review'))
            continue
        for category, rule in RULES.items():
            match = rule.search(data)
            if match:
                line = data[:match.start()].count(b'\n') + 1
                problems.append((label, f'{category} warning at line {line}; value withheld'))
    return problems, len(seen)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path('.'))
    parser.add_argument('--staged', action='store_true')
    args = parser.parse_args()
    try:
        problems, count = inspect(args.repo.resolve(), args.staged)
    except (OSError, subprocess.CalledProcessError) as error:
        print('BLOCKED: could not inspect the Git index safely; no file contents printed.', file=sys.stderr)
        return 2
    if problems:
        print('BLOCKED: do not publish. Review these warnings with the repository owner:')
        for path, warning in problems:
            print(f'- {path}: {warning}')
        return 1
    print(f'PASS: {count} indexed files checked. This is not a guarantee that content is safe or approved.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
