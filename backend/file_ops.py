"""
Aegis ReWrite — File Operations
Encoding-preserving read, atomic write with backup chain, diff preview.
Cross-platform. No external dependencies.
"""
import os
import re
import shutil
import difflib
from datetime import datetime


def safe_read_file(filepath):
    """Read a file preserving encoding metadata.
    Returns (lines: list[str], meta: dict).
    """
    original_size = os.path.getsize(filepath)

    with open(filepath, 'rb') as f:
        raw_head = f.read(4)

    bom = ''
    encoding = 'utf-8'
    if raw_head[:3] == b'\xef\xbb\xbf':
        bom = 'utf-8-sig'
        encoding = 'utf-8-sig'
    elif raw_head[:2] == b'\xff\xfe':
        bom = 'utf-16-le'
        encoding = 'utf-16-le'
    elif raw_head[:2] == b'\xfe\xff':
        bom = 'utf-16-be'
        encoding = 'utf-16-be'

    with open(filepath, 'r', encoding=encoding, errors='replace') as f:
        content = f.read()

    crlf_count = content.count('\r\n')
    lf_count = content.count('\n') - crlf_count
    newline_style = '\r\n' if crlf_count > lf_count else '\n'

    lines = content.splitlines(True)

    return lines, {
        'encoding': encoding,
        'bom': bom,
        'newline_style': newline_style,
        'original_size': original_size,
    }


# ═══════════════════════════════════════════
# BACKUP CHAIN CONFIG
# ═══════════════════════════════════════════
DEFAULT_BACKUP_DEPTH = 3
MIN_BACKUP_DEPTH = 1
MAX_BACKUP_DEPTH = 10

_config = {'backup_chain_depth': DEFAULT_BACKUP_DEPTH}


def get_backup_depth():
    return _config['backup_chain_depth']


def set_backup_depth(depth):
    _config['backup_chain_depth'] = max(MIN_BACKUP_DEPTH, min(MAX_BACKUP_DEPTH, int(depth)))


def safe_write_file(filepath, lines, meta):
    """Atomic write with encoding preservation and backup chain rotation.
    Returns dict: {backup_path, chain_depth}.
    """
    depth = _config['backup_chain_depth']

    # Rotate backup chain: .bak.N → .bak.N+1 (delete oldest)
    for i in range(depth - 1, 0, -1):
        src = f"{filepath}.bak.{i}" if i > 1 else f"{filepath}.bak"
        dst = f"{filepath}.bak.{i + 1}"
        if os.path.exists(src):
            if i + 1 > depth:
                os.remove(src)
            else:
                shutil.copy2(src, dst)

    # Create primary backup
    backup_path = f"{filepath}.bak"
    if os.path.exists(filepath):
        shutil.copy2(filepath, backup_path)

    # Write with preserved encoding and newline style
    encoding = meta.get('encoding', 'utf-8')
    newline_style = meta.get('newline_style', '\n')

    content = ''
    for line in lines:
        stripped = line.rstrip('\r\n')
        content += stripped + newline_style

    # Atomic write: temp file + rename
    tmp_path = filepath + '.tmp'
    with open(tmp_path, 'w', encoding=encoding, newline='') as f:
        f.write(content)

    os.replace(tmp_path, filepath)

    return {'backup_path': backup_path, 'chain_depth': depth}


def preview_diff(filepath, original_lines, modified_lines):
    """Generate a unified diff between original and modified lines."""
    orig = [l.rstrip('\r\n') + '\n' for l in original_lines]
    mod = [l.rstrip('\r\n') + '\n' for l in modified_lines]

    diff = list(difflib.unified_diff(
        orig, mod,
        fromfile=f"a/{os.path.basename(filepath)}",
        tofile=f"b/{os.path.basename(filepath)}",
        lineterm='\n'
    ))
    return ''.join(diff)
