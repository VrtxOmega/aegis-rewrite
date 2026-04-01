"""
Aegis ReWrite — Flask Backend
Lightweight API for scanner, remediation, AI explain, and file operations.
Cross-platform. No psutil, no WMI, no Windows-specific imports.
"""
import os
import re
import json
from flask import Flask, jsonify, request
from flask_cors import CORS

from scanner import scan_project, scan_project_streaming
from remediation import suggest_fix
from resolution_db import finding_hash, get_resolution, set_resolution, get_resolutions
from file_ops import safe_read_file, safe_write_file, preview_diff, get_backup_depth, set_backup_depth
from ai_explain import explain_finding, explain_fix, check_ollama, generate_fix


app = Flask(__name__)
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

import json
from flask import Flask, jsonify, request, Response

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    path = data.get('path', '')
    if not path or not os.path.isdir(path):
        return jsonify({'error': 'Invalid path'}), 400
    result = scan_project(path)
    return jsonify(result)

@app.route('/api/scan/stream', methods=['GET'])
def scan_stream():
    path = request.args.get('path', '')
    if not path or not os.path.isdir(path):
        return Response(f"data: {json.dumps({'type': 'error', 'message': 'Invalid path'})}\n\n", mimetype='text/event-stream')

    def generate():
        for event in scan_project_streaming(path):
            yield f"data: {json.dumps(event)}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')


# ═══════════════════════════════════════════
# REMEDIATION
# ═══════════════════════════════════════════

@app.route('/api/suggest', methods=['POST'])
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
def set_resolution_endpoint():
    data = request.get_json() or {}
    finding = data.get('finding', {})
    status = data.get('status', 'OPEN')
    project_path = data.get('project_path', '')

    fhash = finding_hash(project_path, finding)
    set_resolution(fhash, project_path, finding, status)
    return jsonify({'ok': True, 'finding_hash': fhash, 'status': status})


@app.route('/api/resolutions', methods=['GET'])
def get_resolutions_endpoint():
    project_path = request.args.get('project_path', '')
    results = get_resolutions(project_path)
    return jsonify({'resolutions': results})


# ═══════════════════════════════════════════
# FILE OPERATIONS
# ═══════════════════════════════════════════

@app.route('/api/read_file', methods=['POST'])
def read_file():
    data = request.get_json() or {}
    filepath = data.get('path', '')
    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404

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
        return re.sub(r'\beval\s*\(', 'ast.literal_eval(', line)
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
        return re.sub(r'\bos\.system\s*\(', 'subprocess.run(', line)
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
        return re.sub(r'CORS\s*\(\s*(\w+)\s*\)', r'CORS(\1, origins=["http://127.0.0.1"])', line)
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

    # JS-style: const/let/var VAR = "value"
    js_match = re.match(
        r'''(const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'].*?["']''',
        stripped
    )
    if js_match:
        decl = js_match.group(1)
        var_name = js_match.group(2)
        env_key = re.sub(r'([a-z])([A-Z])', r'\1_\2', var_name).upper()
        return f'{indent}{decl} {var_name} = process.env.{env_key} || ""'

    # Dict/object style: "key": "value" or key: "value"
    dict_match = re.match(
        r'''(["']?)([A-Za-z_][A-Za-z0-9_]*)\1\s*:\s*["']([^"']{8,})["']''',
        stripped
    )
    if dict_match:
        key_name = dict_match.group(2)
        env_key = key_name.upper()
        if is_js:
            return f'{indent}"{key_name}": process.env.{env_key} || ""'
        else:
            return f'{indent}"{key_name}": os.environ.get("{env_key}", "")'

    # Private key block (-----BEGIN ... PRIVATE KEY-----) — can't fix inline
    if '-----BEGIN' in stripped and 'PRIVATE KEY' in stripped:
        return f"{indent}# FIXME [AEGIS]: Move private key to a file, load via os.environ['KEY_PATH']\n{indent}# {stripped}"

    # Fallback: comment out with env var guidance
    return f"{indent}# FIXME [AEGIS]: Move to environment variable\n{indent}# {stripped}"


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
]


def _apply_pattern_fix(line, finding):
    """Dispatch-table pattern fixer.
    Returns the fixed line if a pattern matched and produced a change, else None.
    """
    category = finding.get('category', '')
    title_lower = finding.get('title', '').lower()

    for dispatch_cat, dispatch_key, handler in _PATTERN_DISPATCH:
        if dispatch_cat != category:
            continue
        if dispatch_key is not None and dispatch_key not in title_lower:
            continue
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


def _get_fixed_line(filepath, lines, finding, line_num):
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
    pattern_fix = _apply_pattern_fix(actual_line, finding)
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
def preview():
    data = request.get_json() or {}
    filepath = data.get('path', '')
    finding = data.get('finding', {})

    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404

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
        fixed_line, method, actual_line_num = _get_fixed_line(filepath, lines, finding, line_num)

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
    filepath = data.get('path', '')
    finding = data.get('finding', {})
    project_path = data.get('project_path', '')

    if not filepath or not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404

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
        fixed_line, method, actual_line_num = _get_fixed_line(filepath, lines, finding, line_num)

        if method is None:
            return jsonify({'applied': False, 'reason': 'Could not generate a fix. Try again or fix manually.'})

        # Apply fix at actual_line_num (may differ from recorded line_num due to prior fixes)
        fix_lines = fixed_line.split('\n')
        lines[actual_line_num - 1] = fix_lines[0] + meta['newline_style']
        for i, extra_line in enumerate(fix_lines[1:], 1):
            lines.insert(actual_line_num - 1 + i, extra_line + meta['newline_style'])

        result = safe_write_file(filepath, lines, meta)

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

    for finding in findings:
        filepath = os.path.join(project_path, finding.get('file', ''))
        if not os.path.isfile(filepath):
            results.append({'file': finding.get('file'), 'applied': False, 'reason': 'File not found'})
            continue

        try:
            lines, meta = safe_read_file(filepath)
            line_num = finding.get('line', 0)
            if line_num < 1 or line_num > len(lines):
                results.append({'file': finding.get('file'), 'applied': False, 'reason': 'File-level finding — needs .gitignore'})
                continue

            fixed, method, actual_line_num = _get_fixed_line(filepath, lines, finding, line_num)

            if method is None:
                results.append({'file': finding.get('file'), 'applied': False, 'reason': 'No fix available'})
                continue

            # Apply at actual_line_num (handles line-shift from prior fixes)
            fix_lines = fixed.split('\n')
            lines[actual_line_num - 1] = fix_lines[0] + meta['newline_style']
            for i, extra in enumerate(fix_lines[1:], 1):
                lines.insert(actual_line_num - 1 + i, extra + meta['newline_style'])

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

    return jsonify({
        'total': len(findings),
        'applied': sum(1 for r in results if r.get('applied')),
        'skipped': sum(1 for r in results if not r.get('applied')),
        'files_modified': len(files_modified),
        'results': results,
    })


if __name__ == '__main__':
    print("Aegis ReWrite backend starting on http://127.0.0.1:5055")
    print(f"Routes registered: {len(app.url_map._rules)}")
    app.run(host='127.0.0.1', port=5055, debug=False, use_reloader=False)
