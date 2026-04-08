"""
Aegis ReWrite — Flask Backend
Lightweight API for scanner, remediation, AI explain, and file operations.
Cross-platform. No psutil, no WMI, no Windows-specific imports.
"""
import os
import re
import json
import subprocess
import requests as _requests
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

from scanner import scan_project, scan_project_streaming, scan_single_file, _scan_file_content, SCAN_EXTENSIONS
from remediation import suggest_fix
from resolution_db import finding_hash, get_resolution, set_resolution, get_resolutions
from file_ops import safe_read_file, safe_write_file, preview_diff, get_backup_depth, set_backup_depth, create_snapshot, restore_snapshot, delete_snapshot
from ai_explain import explain_finding, explain_fix, check_ollama, generate_fix, OLLAMA_URL

AEGIS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def is_safe_path(project_path, target_path):
    """Validate target_path is strictly inside project_path.
    Uses os.path.commonpath to prevent traversal on Windows paths.
    """
    if not project_path or not target_path:
        return False
    try:
        base = os.path.realpath(os.path.abspath(project_path))
        target = os.path.realpath(os.path.abspath(target_path))
        
        # Target Boundary Invariant: self-shielding logic unless explicitly in DEV_MODE
        if target.startswith(AEGIS_ROOT):
            if os.environ.get('AEGIS_DEV_MODE') != '1':
                return False
                
        return os.path.commonpath([base, target]) == base
    except (ValueError, OSError):
        # ValueError on Windows when paths are on different drives
        return False


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB request limit
CORS(app, origins=["http://127.0.0.1", "http://localhost"])


# ═══════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'app': 'aegis-rewrite'})


# ═══════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════

def _enrich_findings(findings, project_path):
    """Add backend-computed _hash to each finding so frontend never hashes locally."""
    for f in findings:
        f['_hash'] = finding_hash(project_path, f)
    return findings


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    path = data.get('path', '')
    if not path or not os.path.isdir(path):
        return jsonify({'error': 'Invalid path'}), 400
    result = scan_project(path)
    result['findings'] = _enrich_findings(result.get('findings', []), path)
    return jsonify(result)

@app.route('/api/scan/stream', methods=['GET'])
def scan_stream():
    path = request.args.get('path', '')
    if not path or not os.path.isdir(path):
        return Response(
            f"data: {json.dumps({'type': 'error', 'message': 'Invalid path'})}\n\n",
            mimetype='text/event-stream'
        )

    def generate():
        for event in scan_project_streaming(path):
            # Enrich findings in the complete event so frontend gets _hash values
            if event.get('type') == 'complete':
                event['findings'] = _enrich_findings(event.get('findings', []), path)
            yield f"data: {json.dumps(event)}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


# ═══════════════════════════════════════════
# REMEDIATION
# ═══════════════════════════════════════════

@app.route('/api/suggest', methods=['POST'])
@app.route('/api/remediation/suggest', methods=['POST'])
def suggest():
    finding = request.get_json() or {}
    result = suggest_fix(finding)
    return jsonify(result)


# ═══════════════════════════════════════════
# AI EXPLAIN (optional — graceful fallback)
# ═══════════════════════════════════════════

@app.route('/api/ai/status')
def ai_status():
    return jsonify({'available': check_ollama()})


@app.route('/api/ai/models')
def ai_models():
    """Return list of Ollama models actually installed on this machine."""
    try:
        r = _requests.get(f'{OLLAMA_URL}/api/tags', timeout=3)
        if r.status_code == 200:
            models_raw = r.json().get('models', [])
            model_names = [m['name'] for m in models_raw]
            return jsonify({'models': model_names, 'available': True})
    except Exception:
        pass
    return jsonify({'models': [], 'available': False})


@app.route('/api/ai/explain', methods=['POST'])
def explain():
    finding = request.get_json() or {}
    result = explain_finding(finding)
    return jsonify(result)


@app.route('/api/ai/explain_fix', methods=['POST'])
def explain_fix_endpoint():
    data = request.get_json() or {}
    result = explain_fix(data.get('finding', {}), data.get('suggestion', ''))
    return jsonify(result)


# ═══════════════════════════════════════════
# RESOLUTION PERSISTENCE
# ═══════════════════════════════════════════

@app.route('/api/resolution', methods=['POST'])
@app.route('/api/resolutions/set', methods=['POST'])
def set_resolution_endpoint():
    data = request.get_json() or {}
    finding      = data.get('finding', {})
    status       = data.get('status', 'OPEN')
    project_path = data.get('project_path', '')
    finding_hash_val = data.get('finding_hash', '')

    if not finding_hash_val:
        finding_hash_val = finding_hash(project_path, finding)
    set_resolution(finding_hash_val, project_path, finding, status)
    return jsonify({'ok': True, 'finding_hash': finding_hash_val, 'status': status})


@app.route('/api/resolutions', methods=['GET'])
def get_resolutions_endpoint():
    project_path = request.args.get('project_path',
                   request.args.get('project', ''))  # accept both param names
    results = get_resolutions(project_path)
    # Return flat array (v2 renderer expects list of {finding_hash, status})
    return jsonify(results if isinstance(results, list) else [])


# ═══════════════════════════════════════════
# GIT OPERATIONS
# ═══════════════════════════════════════════

@app.route('/api/git/status', methods=['POST'])
def git_status():
    data = request.get_json() or {}
    path = data.get('path', '')
    if not os.path.isdir(path) or not os.path.isdir(os.path.join(path, '.git')):
        return jsonify({'is_git': False, 'is_clean': True})
    
    try:
        res = subprocess.run(['git', 'status', '--porcelain'], cwd=path, capture_output=True, text=True, check=True)
        is_clean = len(res.stdout.strip()) == 0
        return jsonify({'is_git': True, 'is_clean': is_clean, 'output': res.stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/git/checkpoint', methods=['POST'])
def git_checkpoint():
    data = request.get_json() or {}
    path = data.get('path', '')
    if not os.path.isdir(os.path.join(path, '.git')):
        return jsonify({'success': False, 'error': 'Not a git repo'})
    
    try:
        subprocess.run(['git', 'add', '.'], cwd=path, check=True)
        subprocess.run(['git', 'commit', '-m', '[AEGIS] Pre-remediation auto-checkpoint'], cwd=path, check=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/git/rollback', methods=['POST'])
def git_rollback():
    data = request.get_json() or {}
    path = data.get('path', '')
    if not os.path.isdir(os.path.join(path, '.git')):
        return jsonify({'success': False, 'error': 'Not a git repo'})
    
    try:
        res = subprocess.run(['git', 'log', '-1', '--pretty=%s'], cwd=path, capture_output=True, text=True, check=True)
        msg = res.stdout.strip()
        if msg == '[AEGIS] Pre-remediation auto-checkpoint':
            subprocess.run(['git', 'reset', '--hard', 'HEAD~1'], cwd=path, check=True)
            return jsonify({'success': True, 'rolled_back': True})
        else:
            return jsonify({'success': False, 'error': 'HEAD is not an AEGIS auto-checkpoint.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ═══════════════════════════════════════════
# FILE OPERATIONS
# ═══════════════════════════════════════════

@app.route('/api/read_file', methods=['POST'])
@app.route('/api/file/read', methods=['POST'])
def read_file():
    data = request.get_json() or {}
    project_path = data.get('project_path', '')
    rel_file     = data.get('file', data.get('path', ''))

    # Build absolute path safely
    if os.path.isabs(rel_file):
        filepath = os.path.abspath(rel_file)
    else:
        filepath = os.path.abspath(os.path.join(project_path, rel_file))

    if not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404

    if not is_safe_path(project_path, filepath):
        return jsonify({'error': 'Path traversal blocked'}), 403

    try:
        lines, meta = safe_read_file(filepath)
        return jsonify({
            'lines': [l.rstrip('\r\n') for l in lines],
            'total_lines': len(lines),
            'encoding': meta['encoding'],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({'backup_chain_depth': get_backup_depth()})


@app.route('/api/config', methods=['POST'])
def set_config():
    data = request.get_json() or {}
    if 'backup_chain_depth' in data:
        set_backup_depth(data['backup_chain_depth'])
    return jsonify({'ok': True, 'backup_chain_depth': get_backup_depth()})


# ═══════════════════════════════════════════
# DIFF PREVIEW + FIX APPLICATION
# ═══════════════════════════════════════════

# ═══════════════════════════════════════════
# TIER 1: DETERMINISTIC PATTERN FIX ENGINE
# ═══════════════════════════════════════════
# Dispatch-table architecture. Every scanner finding type has a registered
# handler. Handlers receive (line, finding, context) and return the fixed
# line or None if they can't fix it.

def _fix_eval(line, finding, ctx):
    """Replace eval() with ast.literal_eval()."""
    if re.search(r'\beval\s*\(', line):
        return re.sub(r'\beval(\s*)\(', r'ast.literal_eval\1(', line)
    return None


def _fix_exec(line, finding, ctx):
    """Comment out exec() with dispatch-dict guidance."""
    if re.search(r'\bexec\s*\(', line):
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        return f"{indent}# FIXME [AEGIS]: Replace exec() with a dispatch dict\n{indent}# {stripped}"
    return None


def _fix_os_system(line, finding, ctx):
    """Replace os.system() with subprocess.run()."""
    if re.search(r'\bos\.system\s*\(', line):
        return re.sub(r'\bos\.system(\s*)\(', r'subprocess.run\1(', line)
    return None


def _fix_import(line, finding, ctx):
    """Replace __import__() with importlib.import_module()."""
    if re.search(r'\b__import__\s*\(', line):
        return re.sub(r'\b__import__\s*\(', 'importlib.import_module(', line)
    return None


def _fix_subprocess_shell(line, finding, ctx):
    """Set shell=False in subprocess calls."""
    if re.search(r'shell\s*=\s*True', line):
        return re.sub(r'shell\s*=\s*True', 'shell=False', line)
    return None


def _fix_innerhtml(line, finding, ctx):
    """Replace innerHTML with textContent."""
    if '.innerHTML' in line:
        return line.replace('.innerHTML', '.textContent')
    return None


def _fix_document_write(line, finding, ctx):
    """Comment out document.write()."""
    if re.search(r'document\.write\s*\(', line):
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        return f"{indent}// FIXME [AEGIS]: Replace with DOM manipulation\n{indent}// {stripped}"
    return None


def _fix_new_function(line, finding, ctx):
    """Comment out new Function()."""
    if re.search(r'\bnew\s+Function\s*\(', line):
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        return f"{indent}// FIXME [AEGIS]: Replace new Function() with a dispatch map\n{indent}// {stripped}"
    return None


def _fix_binding_0000(line, finding, ctx):
    """Replace 0.0.0.0 with 127.0.0.1."""
    if '0.0.0.0' in line:
        return line.replace('0.0.0.0', '127.0.0.1')
    return None


def _fix_cors_unrestricted(line, finding, ctx):
    """Add origin restriction to bare CORS(app)."""
    if re.search(r'CORS\s*\(\s*\w+\s*\)', line):
        return re.sub(r'CORS(\s*)\((\s*)(\w+)(\s*)\)', r'CORS\1(\2\3, origins=["http://127.0.0.1"]\4)', line)
    return None


def _fix_cors_wildcard(line, finding, ctx):
    """Replace Access-Control-Allow-Origin * with localhost."""
    if re.search(r'Access-Control-Allow-Origin.*\*', line):
        return re.sub(r'(\*)', '"http://127.0.0.1"', line, count=1)
    return None


def _fix_debug_mode(line, finding, ctx):
    """Disable debug mode."""
    if re.search(r'debug\s*=\s*True', line, re.I):
        return re.sub(r'debug\s*=\s*True', 'debug=False', line, flags=re.I)
    return None


def _fix_hardcoded_secret(line, finding, ctx):
    """Extract variable name and replace value with os.environ.get() or process.env."""
    stripped = line.lstrip()
    indent = line[:len(line) - len(stripped)]

    if stripped.startswith('#') or stripped.startswith('//'):
        return None

    # Detect language context from file extension
    filepath = finding.get('file', '')
    is_js = any(filepath.endswith(ext) for ext in ('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'))

    # Python-style assignment: VAR_NAME = "value" or VAR_NAME: str = "value"
    py_match = re.match(
        r'''([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*\w+\s*)?=\s*(?:f?["'].*?["'])''',
        stripped
    )
    if py_match and not is_js:
        var_name = py_match.group(1)
        env_key = var_name.upper()
        return f'{indent}{var_name} = os.environ.get("{env_key}", "")'

    # JS-style: const/let/var VAR = "value" or export const VAR = "value"
    js_match = re.match(
        r'''(?:export\s+)?(const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'`].*?["'`])''',
        stripped
    )
    if js_match:
        decl = js_match.group(1)
        # Re-attach 'export' if it was part of the original assignment
        if stripped.startswith('export '):
            decl = f'export {decl}'
        var_name = js_match.group(2)
        env_key = re.sub(r'([a-z])([A-Z])', r'\1_\2', var_name).upper()
        return f'{indent}{decl} {var_name} = process.env.{env_key} || ""'

    # Dict/object style: "key": "value" or key: "value"
    dict_match = re.search(
        r'''(["']?)([A-Za-z_][A-Za-z0-9_]*)\1\s*:\s*["']([^"']{8,})["']''',
        stripped
    )
    if dict_match:
        key_name = dict_match.group(2)
        env_key = re.sub(r'([a-z])([A-Z])', r'\1_\2', key_name).upper()
        
        replacement = f'"{key_name}": process.env.{env_key} || ""' if is_js else f'"{key_name}": os.environ.get("{env_key}", "")'
        
        pattern = r'(["\']?)' + re.escape(key_name) + r'\1\s*:\s*["\'][^"\']{8,}["\']'
        return re.sub(pattern, replacement, line, count=1)

    # Private key block (-----BEGIN ... PRIVATE KEY-----) — can't fix inline
    if '-----BEGIN' in stripped and 'PRIVATE KEY' in stripped:
        return f"{indent}# FIXME [AEGIS]: Move private key to a file, load via os.environ['KEY_PATH']\n{indent}# {stripped}"

    # Fallback: comment out with env var guidance
    return f"{indent}# FIXME [AEGIS]: Move to environment variable\n{indent}# {stripped}"

def _fix_pinned_version(line, finding, project_path):
    """
    Looks up the actual version in package-lock.json if available and removes the caret.
    """
    import os
    import json
    
    file_path = finding.get('file', '')
    # The scanner provides absolute or relative paths. We can't easily guess the absolute root
    # here without the project_path argument. However, because this runs server-side locally,
    # and batch_fix provides project_path, we will try to resolve it.
    
    # Strip ^ and ~ from the version string as a fallback or explicit lock
    match = re.search(r'([\'"])([\^~])([0-9]+\.[0-9]+\.[0-9]+.*)([\'"])', line)
    if not match:
        return line
        
    quote1, caret, version, quote2 = match.groups()
    pkg_match = re.search(r'[\'"]([^\'"]+)[\'"]\s*:', line)
    if not pkg_match:
        return line
        
    pkg_name = pkg_match.group(1)
    
    # Optional logic: attempt to find package-lock.json in the CWD or parent if we can. 
    # Because app.py runs in the context, we will simply drop the caret, locking it
    # to the exact numeric version specified in the boundary (which matches `npm install` 
    # generation behavior for lockfiles).
    
    if project_path:
        lockfile = os.path.join(project_path, 'package-lock.json')
        if os.path.isfile(lockfile):
            try:
                with open(lockfile, 'r', encoding='utf-8') as f:
                    lock_data = json.load(f)
                deps = lock_data.get('dependencies', {})
                pkgs = lock_data.get('packages', {})
                # Look in packages first (npm v2/v3 lockfiles structure)
                resolved = pkgs.get(f"node_modules/{pkg_name}", {}).get("version")
                # Fallback to older lockfile structure
                if not resolved:
                    resolved = deps.get(pkg_name, {}).get("version")
                
                if resolved:
                    # Successfully pinned to exact resolved version
                    line = re.sub(r'([\'"])(?:[\^~])([0-9]+\.[0-9]+\.[0-9]+.*)([\'"])', rf'\1{resolved}\3', line)
                    return line
            except Exception:
                pass
                
    # If no lockfile or parsing failed, we fall back to just removing the caret
    # which pins it to the boundary version.
    line = re.sub(r'([\'"])(?:[\^~])([0-9]+\.[0-9]+\.[0-9]+.*)([\'"])', r'\1\2\3', line)
    return line


# ── DISPATCH TABLE ──
# Maps (category, title_keyword) → handler function.
# Checked in order; first match wins. Title keywords are lowercase.
_PATTERN_DISPATCH = [
    # Dangerous Functions — Python
    ('Dangerous Function', 'eval()',           _fix_eval),
    ('Dangerous Function', 'exec()',           _fix_exec),
    ('Dangerous Function', 'os.system()',      _fix_os_system),
    ('Dangerous Function', '__import__()',     _fix_import),
    ('Dangerous Function', 'subprocess shell', _fix_subprocess_shell),
    # Dangerous Functions — JavaScript
    ('Dangerous Function', 'innerhtml',        _fix_innerhtml),
    ('Dangerous Function', 'document.write()', _fix_document_write),
    ('Dangerous Function', 'new function()',   _fix_new_function),
    # Network Exposure
    ('Exposed Binding',    '0.0.0.0',         _fix_binding_0000),
    ('Exposed Binding',    'cors enabled',    _fix_cors_unrestricted),
    ('Exposed Binding',    'cors wildcard',   _fix_cors_wildcard),
    # Secrets
    ('Hardcoded Secret',   None,              _fix_hardcoded_secret),  # None = match all titles in category
    # Supply Chain
    ('Pinned Version Enforcement', None,      _fix_pinned_version),
]


def _apply_pattern_fix(line, finding, project_path=None):
    """Dispatch-table pattern fixer.
    Returns the fixed line if a pattern matched and produced a change, else None.
    """
    # Reject lines that are entirely commented out
    if re.match(r'^\s*(#|//|/\*|\*|<!--)', line):
        return None

    category = finding.get('category', '')
    title_lower = finding.get('title', '').lower()

    for dispatch_cat, dispatch_key, handler in _PATTERN_DISPATCH:
        if dispatch_cat != category:
            continue
        if dispatch_key is not None and dispatch_key not in title_lower:
            continue
        
        # Inject project_path if it's the pinned version logic
        if handler == _fix_pinned_version:
            result = handler(line, finding, project_path)
        else:
            result = handler(line, finding, None)
            
        if result is not None and result != line:
            return result

    # Debug mode — category-agnostic, check the line content directly
    if re.search(r'debug\s*=\s*True', line, re.I):
        result = _fix_debug_mode(line, finding, None)
        if result is not None and result != line:
            return result

    return None


def _find_target_line(lines, finding, recorded_line_num):
    """Line-shift mitigation: find the actual line containing the vulnerability.
    
    When prior fixes insert/remove lines, recorded line numbers become stale.
    Strategy:
      1. Check the recorded line first (fast path).
      2. If it doesn't contain the expected pattern, scan the FULL file for the
         first uncommented line matching the scanner's detection regex.
    
    Returns (0-indexed line index, line content) or (None, None) if not found.
    """
    title = finding.get('title', '').lower()
    category = finding.get('category', '')

    # Build a detection regex from the finding title to locate the vulnerable code
    detection_regex = _title_to_detection_regex(title, category)
    if detection_regex is None:
        # No regex available — trust the recorded line number
        if 1 <= recorded_line_num <= len(lines):
            return recorded_line_num - 1, lines[recorded_line_num - 1].rstrip('\r\n')
        return None, None

    # Fast path: check the recorded line
    if 1 <= recorded_line_num <= len(lines):
        candidate = lines[recorded_line_num - 1].rstrip('\r\n')
        stripped = candidate.strip()
        if not stripped.startswith('#') and not stripped.startswith('//'):
            if detection_regex.search(candidate):
                return recorded_line_num - 1, candidate

    # Full-file scan: find the first matching line that hasn't been commented out
    for i, raw_line in enumerate(lines):
        candidate = raw_line.rstrip('\r\n')
        stripped = candidate.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue
        # Skip lines already containing AEGIS fix markers
        if 'FIXME [AEGIS]' in candidate:
            continue
        if '#' in stripped and 'AEGIS' in stripped.split('#')[-1]:
            continue
        if detection_regex.search(candidate):
            return i, candidate

    return None, None


def _title_to_detection_regex(title, category):
    """Convert a scanner finding title back to a detection regex.
    Returns compiled regex or None.
    """
    title_lower = title.lower()

    # Dangerous Functions
    if 'eval()' in title_lower:
        return re.compile(r'\beval\s*\(')
    if 'exec()' in title_lower:
        return re.compile(r'\bexec\s*\(')
    if 'os.system()' in title_lower:
        return re.compile(r'\bos\.system\s*\(')
    if '__import__()' in title_lower:
        return re.compile(r'\b__import__\s*\(')
    if 'subprocess' in title_lower and 'shell' in title_lower:
        return re.compile(r'shell\s*=\s*True')
    if 'innerhtml' in title_lower:
        return re.compile(r'innerHTML\s*=')
    if 'document.write' in title_lower:
        return re.compile(r'document\.write\s*\(')
    if 'new function' in title_lower:
        return re.compile(r'\bnew\s+Function\s*\(')

    # Network Exposure
    if '0.0.0.0' in title_lower:
        return re.compile(r'0\.0\.0\.0')
    if 'cors' in title_lower and 'wildcard' in title_lower:
        return re.compile(r'Access-Control-Allow-Origin.*\*')
    if 'cors' in title_lower:
        return re.compile(r'CORS\s*\(\s*\w+\s*\)')

    # Secrets — match any quoted string assignment
    if category == 'Hardcoded Secret':
        return re.compile(r'''[:=]\s*["'][^"']{8,}["']''')

    return None


def _get_fixed_line(filepath, lines, finding, line_num, project_path=None):
    """Two-tier fix pipeline: deterministic pattern first, AI rewrite fallback.
    Returns (fixed_line, method, actual_line_num) where method is 'pattern' or 'ai'.
    actual_line_num is 1-indexed and may differ from the input if line-shift was detected.
    """
    category = finding.get('category', '')

    # Sensitive Files can't be fixed by editing content
    if category == 'Sensitive File':
        return lines[line_num - 1].rstrip('\r\n') if 1 <= line_num <= len(lines) else '', None, line_num

    # ── Line-shift mitigation: find the ACTUAL vulnerable line ──
    actual_idx, actual_line = _find_target_line(lines, finding, line_num)
    if actual_idx is None:
        # Can't find the vulnerability anywhere in the file
        original = lines[line_num - 1].rstrip('\r\n') if 1 <= line_num <= len(lines) else ''
        return original, None, line_num

    actual_line_num = actual_idx + 1  # 1-indexed

    # ── Tier 1: Deterministic pattern fix (instant) ──
    pattern_fix = _apply_pattern_fix(actual_line, finding, project_path)
    if pattern_fix is not None:
        return pattern_fix, 'pattern', actual_line_num

    # ── Tier 2: AI-powered rewrite (context-aware, handles complex cases) ──
    start = max(0, actual_idx - 5)
    end = min(len(lines), actual_idx + 6)
    context = [lines[i].rstrip('\r\n') for i in range(start, end)]

    ai_result = generate_fix(finding, context, actual_line)
    if ai_result.get('fixed_line'):
        return ai_result['fixed_line'], 'ai', actual_line_num

    return actual_line, None, actual_line_num


@app.route('/api/preview', methods=['POST'])
@app.route('/api/fix/preview', methods=['POST'])
def preview():
    data         = request.get_json() or {}
    finding      = data.get('finding', {})
    project_path = data.get('project_path', '')

    # Accept either explicit path or derive from project_path + finding.file
    filepath = data.get('path', '')
    if not filepath:
        rel = finding.get('file', '')
        if os.path.isabs(rel):
            filepath = os.path.abspath(rel)
        else:
            filepath = os.path.abspath(os.path.join(project_path, rel))

    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404

    if not is_safe_path(project_path, filepath):
        return jsonify({'error': 'Path traversal blocked'}), 403

    try:
        lines, meta = safe_read_file(filepath)
        line_num = finding.get('line', 0)

        # File-level findings (Sensitive File, Private Key Block) have line=0
        if line_num < 1 or line_num > len(lines):
            category = finding.get('category', '')
            if category == 'Sensitive File' or line_num == 0:
                return jsonify({
                    'diff': '',
                    'original_line': '',
                    'fixed_line': '',
                    'line_num': 0,
                    'method': None,
                    'message': 'File-level finding — add to .gitignore or remove from version control.',
                })
            return jsonify({'error': f'Line {line_num} out of range'}), 400

        original_line = lines[line_num - 1].rstrip('\r\n')
        fixed_line, method, actual_line_num = _get_fixed_line(filepath, lines, finding, line_num, project_path)

        if method is None:
            return jsonify({
                'diff': '',
                'original_line': original_line,
                'fixed_line': original_line,
                'line_num': line_num,
                'method': None,
                'message': 'Could not generate a fix for this finding.',
            })

        # Build diff with potentially multi-line fix (use actual_line_num for shifted lines)
        modified = list(lines)
        fix_lines = fixed_line.split('\n')
        modified[actual_line_num - 1] = fix_lines[0] + meta['newline_style']
        for i, extra_line in enumerate(fix_lines[1:], 1):
            modified.insert(actual_line_num - 1 + i, extra_line + meta['newline_style'])

        diff = preview_diff(filepath, lines, modified)

        return jsonify({
            'diff': diff,
            'original_line': lines[actual_line_num - 1].rstrip('\r\n') if actual_line_num != line_num else original_line,
            'fixed_line': fixed_line,
            'line_num': actual_line_num,
            'method': method,
            'line_shifted': actual_line_num != line_num,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/fix', methods=['POST'])
def apply_fix():
    data = request.get_json() or {}
    finding = data.get('finding', {})
    project_path = data.get('project_path', '')

    # Accept either explicit path or derive from project_path + finding.file
    filepath = data.get('path', '')
    if not filepath:
        rel = finding.get('file', '')
        if os.path.isabs(rel):
            filepath = os.path.abspath(rel)
        else:
            filepath = os.path.abspath(os.path.join(project_path, rel))

    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404

    if not is_safe_path(project_path, filepath):
        return jsonify({'error': 'Path traversal blocked'}), 403

    try:
        lines, meta = safe_read_file(filepath)
        line_num = finding.get('line', 0)

        # File-level findings (Sensitive File, Private Key Block) have line=0
        if line_num < 1 or line_num > len(lines):
            category = finding.get('category', '')
            if category == 'Sensitive File' or line_num == 0:
                return jsonify({'applied': False, 'reason': 'File-level finding — add to .gitignore or remove from version control.'})
            return jsonify({'error': f'Line {line_num} out of range'}), 400

        original_line = lines[line_num - 1].rstrip('\r\n')
        fixed_line, method, actual_line_num = _get_fixed_line(filepath, lines, finding, line_num, project_path)

        if method is None:
            return jsonify({'applied': False, 'reason': 'Could not generate a fix. Try again or fix manually.'})

        # Apply fix at actual_line_num (may differ from recorded line_num due to prior fixes)
        fix_lines = fixed_line.split('\n')
        lines[actual_line_num - 1] = fix_lines[0] + meta['newline_style']
        for i, extra_line in enumerate(fix_lines[1:], 1):
            lines.insert(actual_line_num - 1 + i, extra_line + meta['newline_style'])

        # Mutation Scope Invariant: In-Memory Verification Loop
        verification_failed = False
        _, ext = os.path.splitext(filepath)
        ext = ext.lower()
        if ext in SCAN_EXTENSIONS:
            rel_path = os.path.relpath(filepath, project_path)
            new_findings = _scan_file_content(lines, rel_path, ext)
            for nf in new_findings:
                if nf.get('category') == finding.get('category') and nf.get('title') == finding.get('title'):
                    # Only fail if vulnerability is within the lines we just mutated
                    if abs(nf.get('line', 0) - actual_line_num) <= len(fix_lines) + 1:
                        verification_failed = True
                        break

        if verification_failed:
            return jsonify({
                'applied': False,
                'method': method,
                'reason': 'Real-time Verification Failed: Vulnerability survived. Atomic commit aborted.',
            })

        # Commit phase (Snapshot -> Atomic Write -> Snapshot Cleanup)
        create_snapshot(filepath)
        try:
            result = safe_write_file(filepath, lines, meta)
            delete_snapshot(filepath)
        except Exception as e:
            restore_snapshot(filepath)
            delete_snapshot(filepath)
            raise e

        # Mark as FIXED
        if project_path:
            fhash = finding_hash(project_path, finding)
            set_resolution(fhash, project_path, finding, 'FIXED')

        return jsonify({
            'applied': True,
            'method': method,
            'lines_modified': len(fix_lines),
            'backup': result['backup_path'],
            'line_num': actual_line_num,
            'line_shifted': actual_line_num != line_num,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch_fix', methods=['POST'])
def batch_fix():
    data = request.get_json() or {}
    findings = data.get('findings', [])
    project_path = data.get('project_path', '')

    results = []
    files_modified = set()
    files_to_snapshot = set()

    # Pre-flight scope determination
    for finding in findings:
        raw_file = finding.get('file', '')
        if os.path.isabs(raw_file):
            filepath = os.path.abspath(raw_file)
        else:
            filepath = os.path.abspath(os.path.join(project_path, raw_file))
        files_to_snapshot.add(filepath)

    # Global Snapshot Transaction initialization
    for fp in files_to_snapshot:
        if os.path.exists(fp):
            create_snapshot(fp)

    batch_succeeded = True

    try:
        for finding in findings:
            raw_file = finding.get('file', '')
            if os.path.isabs(raw_file):
                filepath = os.path.abspath(raw_file)
            else:
                filepath = os.path.abspath(os.path.join(project_path, raw_file))
            
            if not is_safe_path(project_path, filepath):
                results.append({'file': finding.get('file'), 'applied': False, 'reason': 'Path traversal or Target Boundary blocked'})
                batch_succeeded = False
                continue

            if not os.path.isfile(filepath):
                results.append({'file': finding.get('file'), 'applied': False, 'reason': 'File not found'})
                batch_succeeded = False
                continue

            try:
                lines, meta = safe_read_file(filepath)
                line_num = finding.get('line', 0)
                if line_num < 1 or line_num > len(lines):
                    results.append({'file': finding.get('file'), 'applied': False, 'reason': 'File-level finding — needs .gitignore'})
                    continue

                fixed, method, actual_line_num = _get_fixed_line(filepath, lines, finding, line_num, project_path)

                if method is None:
                    results.append({'file': finding.get('file'), 'applied': False, 'reason': 'No fix available'})
                    continue

                # Apply at actual_line_num
                fix_lines = fixed.split('\n')
                lines[actual_line_num - 1] = fix_lines[0] + meta['newline_style']
                for i, extra in enumerate(fix_lines[1:], 1):
                    lines.insert(actual_line_num - 1 + i, extra + meta['newline_style'])

                # In-Memory Validation before writing
                verification_failed = False
                _, ext = os.path.splitext(filepath)
                ext = ext.lower()
                if ext in SCAN_EXTENSIONS:
                    rel_path = os.path.relpath(filepath, project_path)
                    new_findings = _scan_file_content(lines, rel_path, ext)
                    for nf in new_findings:
                        if nf.get('category') == finding.get('category') and nf.get('title') == finding.get('title'):
                            if abs(nf.get('line', 0) - actual_line_num) <= len(fix_lines) + 1:
                                verification_failed = True
                                break

                if verification_failed:
                    results.append({'file': finding.get('file'), 'applied': False, 'reason': 'In-Memory Verification Failed'})
                    batch_succeeded = False
                    continue

                # Temp atomic write (does not break snapshot rule)
                safe_write_file(filepath, lines, meta)

                files_modified.add(filepath)
                fhash = finding_hash(project_path, finding)
                set_resolution(fhash, project_path, finding, 'FIXED')

                results.append({
                    'file': finding.get('file'),
                    'line': actual_line_num,
                    'applied': True,
                    'method': method,
                })
            except Exception as e:
                results.append({'file': finding.get('file'), 'applied': False, 'reason': str(e)})
                batch_succeeded = False

        if batch_succeeded:
            for fp in files_to_snapshot:
                delete_snapshot(fp)
        else:
            for fp in files_to_snapshot:
                restore_snapshot(fp)
                delete_snapshot(fp)

    except Exception as e:
        for fp in files_to_snapshot:
            restore_snapshot(fp)
            delete_snapshot(fp)
        raise e

    return jsonify({
        'total': len(findings),
        'applied': sum(1 for r in results if r.get('applied')),
        'skipped': sum(1 for r in results if not r.get('applied')),
        'files_modified': len(files_modified),
        'results': results,
    })



@app.route('/api/export', methods=['POST'])
def export_findings():
    """Export findings as JSON or CSV for download."""
    import csv, io
    data = request.get_json() or {}
    findings = data.get('findings', [])
    project_path = data.get('project_path', '')
    fmt = data.get('format', 'json')

    if fmt == 'csv':
        output = io.StringIO()
        fields = ['severity', 'category', 'title', 'file', 'line', 'detail']
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(findings)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=aegis-report.csv'}
        )
    else:
        report = {
            'project': project_path,
            'exported_at': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': findings,
        }
        return jsonify(report)


if __name__ == '__main__':
    try:
        from waitress import serve
        print('Aegis ReWrite backend starting on http://127.0.0.1:5055 (waitress)')
        print(f'Routes registered: {len(app.url_map._rules)}')
        serve(app, host='127.0.0.1', port=5055, threads=4)
    except ImportError:
        # waitress not installed — fall back to Flask dev server
        print('Aegis ReWrite backend starting on http://127.0.0.1:5055 (flask dev)')
        app.run(host='127.0.0.1', port=5055, debug=False, use_reloader=False)
