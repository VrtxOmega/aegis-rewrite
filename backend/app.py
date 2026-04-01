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

from scanner import scan_project
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

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json() or {}
    path = data.get('path', '')
    if not path or not os.path.isdir(path):
        return jsonify({'error': 'Invalid path'}), 400
    result = scan_project(path)
    return jsonify(result)


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

def _apply_pattern_fix(line, category, title):
    """Deterministic regex-based line transforms.
    Every pattern the scanner detects MUST have a corresponding fix here.
    """
    title_lower = title.lower()

    # ── Network Exposure ──
    if 'cors' in title_lower:
        line = re.sub(r'CORS\s*\(\s*app\s*\)', 'CORS(app, origins=["http://127.0.0.1"])', line)
        return line
    if '0.0.0.0' in title_lower or '0.0.0.0' in line:
        line = line.replace('0.0.0.0', '127.0.0.1')
        return line

    # ── JavaScript Dangerous Functions ──
    if 'innerhtml' in title_lower:
        line = line.replace('.innerHTML', '.textContent')
        return line
    if 'document.write' in title_lower:
        line = re.sub(r'document\.write\s*\(', '// FIXME [AEGIS]: Replace with DOM manipulation\n// document.write(', line)
        return line
    if 'new function' in title_lower:
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        line = f"{indent}// FIXME [AEGIS]: Replace new Function() with a dispatch map\n{indent}// {stripped}"
        return line

    # ── Python Dangerous Functions ──
    if title_lower.startswith('eval'):
        line = line.replace('eval(', 'ast.literal_eval(')
        return line
    if title_lower.startswith('exec'):
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        # Comment out exec() and add safe alternative hint
        line = f"{indent}# FIXME [AEGIS]: Replace exec() with a dispatch dict\n{indent}# {stripped}"
        return line
    if '__import__' in title_lower:
        line = re.sub(r'__import__\s*\(', 'importlib.import_module(', line)
        return line
    if 'subprocess' in title_lower and 'shell' in title_lower:
        line = re.sub(r'shell\s*=\s*True', 'shell=False', line)
        return line
    if 'os.system' in title_lower:
        line = line.replace('os.system(', 'subprocess.run(')
        return line

    # ── Debug Mode ──
    if 'debug' in line.lower():
        line = re.sub(r'debug\s*=\s*True', 'debug=False', line)
        return line

    # ── Hardcoded Secrets ──
    if category == 'Hardcoded Secret':
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        if stripped and not stripped.startswith('#') and not stripped.startswith('//'):
            line = f"{indent}# FIXME [AEGIS]: Move to environment variable\n{indent}# {stripped}"
            return line

    # ── Sensitive Files ──
    if category == 'Sensitive File':
        # Can't fix a sensitive file by editing its content — return a signal
        # The frontend will show guidance about .gitignore instead
        return line

    return line


def _get_fixed_line(filepath, lines, finding, line_num):
    """Two-tier fix pipeline: deterministic pattern first, AI rewrite fallback.
    Returns (fixed_line, method) where method is 'pattern' or 'ai'.
    """
    original_line = lines[line_num - 1].rstrip('\r\n')
    category = finding.get('category', '')
    title = finding.get('title', '')

    # Tier 1: Deterministic pattern fix (instant, no AI needed)
    pattern_fix = _apply_pattern_fix(original_line, category, title)
    if pattern_fix != original_line:
        return pattern_fix, 'pattern'

    # Tier 2: AI-powered rewrite (context-aware, handles complex cases)
    start = max(0, line_num - 6)
    end = min(len(lines), line_num + 5)
    context = [lines[i].rstrip('\r\n') for i in range(start, end)]

    ai_result = generate_fix(finding, context, original_line)
    if ai_result.get('fixed_line'):
        return ai_result['fixed_line'], 'ai'

    return original_line, None


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
        if line_num < 1 or line_num > len(lines):
            return jsonify({'error': f'Line {line_num} out of range'}), 400

        original_line = lines[line_num - 1].rstrip('\r\n')
        fixed_line, method = _get_fixed_line(filepath, lines, finding, line_num)

        if method is None:
            return jsonify({
                'diff': '',
                'original_line': original_line,
                'fixed_line': original_line,
                'line_num': line_num,
                'method': None,
                'message': 'Could not generate a fix for this finding.',
            })

        # Build diff with potentially multi-line fix
        modified = list(lines)
        fix_lines = fixed_line.split('\n')
        modified[line_num - 1] = fix_lines[0] + meta['newline_style']
        for i, extra_line in enumerate(fix_lines[1:], 1):
            modified.insert(line_num - 1 + i, extra_line + meta['newline_style'])

        diff = preview_diff(filepath, lines, modified)

        return jsonify({
            'diff': diff,
            'original_line': original_line,
            'fixed_line': fixed_line,
            'line_num': line_num,
            'method': method,
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
        if line_num < 1 or line_num > len(lines):
            return jsonify({'error': f'Line {line_num} out of range'}), 400

        original_line = lines[line_num - 1].rstrip('\r\n')
        fixed_line, method = _get_fixed_line(filepath, lines, finding, line_num)

        if method is None:
            return jsonify({'applied': False, 'reason': 'Could not generate a fix. Try again or fix manually.'})

        # Apply fix (may be multi-line)
        fix_lines = fixed_line.split('\n')
        lines[line_num - 1] = fix_lines[0] + meta['newline_style']
        for i, extra_line in enumerate(fix_lines[1:], 1):
            lines.insert(line_num - 1 + i, extra_line + meta['newline_style'])

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
            'line_num': line_num,
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
                results.append({'file': finding.get('file'), 'applied': False, 'reason': 'Line out of range'})
                continue

            fixed, method = _get_fixed_line(filepath, lines, finding, line_num)

            if method is None:
                results.append({'file': finding.get('file'), 'applied': False, 'reason': 'No fix available'})
                continue

            # Apply (may be multi-line)
            fix_lines = fixed.split('\n')
            lines[line_num - 1] = fix_lines[0] + meta['newline_style']
            for i, extra in enumerate(fix_lines[1:], 1):
                lines.insert(line_num - 1 + i, extra + meta['newline_style'])

            safe_write_file(filepath, lines, meta)
            files_modified.add(filepath)

            fhash = finding_hash(project_path, finding)
            set_resolution(fhash, project_path, finding, 'FIXED')

            results.append({
                'file': finding.get('file'),
                'line': line_num,
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
