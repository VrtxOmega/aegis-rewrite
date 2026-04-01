"""
Aegis ReWrite — Scanner Engine
Pattern-based code vulnerability detection.
Cross-platform. No external dependencies beyond stdlib.
"""
import os
import re
import time


# ═══════════════════════════════════════════
# DETECTION PATTERNS
# ═══════════════════════════════════════════

SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), 'API Key'),
    (re.compile(r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), 'Password/Secret'),
    (re.compile(r'(?:token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I), 'Token'),
    (re.compile(r'(?:aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Z0-9]{16,})["\']', re.I), 'AWS Key'),
    (re.compile(r'(?:private[_-]?key)\s*[:=]\s*["\']([^"\']{20,})["\']', re.I), 'Private Key'),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', re.I), 'Private Key Block'),
    (re.compile(r'(?:DATABASE_URL|MONGO_URI|REDIS_URL)\s*[:=]\s*["\']([^"\']+)["\']', re.I), 'Database URI'),
]

DANGEROUS_FUNCTIONS = [
    (re.compile(r'\beval\s*\('), 'eval()', '.py'),
    (re.compile(r'\bexec\s*\('), 'exec()', '.py'),
    (re.compile(r'\b__import__\s*\('), '__import__()', '.py'),
    (re.compile(r'\bsubprocess\.call\s*\(.*shell\s*=\s*True'), 'subprocess shell=True', '.py'),
    (re.compile(r'\bos\.system\s*\('), 'os.system()', '.py'),
    (re.compile(r'\beval\s*\('), 'eval()', '.js'),
    (re.compile(r'\bnew\s+Function\s*\('), 'new Function()', '.js'),
    (re.compile(r'innerHTML\s*='), 'innerHTML assignment', '.js'),
    (re.compile(r'document\.write\s*\('), 'document.write()', '.js'),
]

BINDING_PATTERNS = [
    (re.compile(r'\.listen\s*\(\s*["\']?0\.0\.0\.0["\']?'), 'Binding to 0.0.0.0'),
    (re.compile(r'host\s*[:=]\s*["\']0\.0\.0\.0["\']'), 'Host set to 0.0.0.0'),
    (re.compile(r'CORS\s*\(\s*\w+\s*\)'), 'CORS enabled (unrestricted)'),
    (re.compile(r'Access-Control-Allow-Origin.*\*'), 'CORS wildcard origin'),
]

SENSITIVE_FILES = {
    '.env', '.env.local', '.env.production', '.env.staging',
    'id_rsa', 'id_ed25519', 'id_ecdsa',
    '.htpasswd', 'credentials.json', 'service-account.json',
    'firebase-adminsdk.json', '.npmrc', '.pypirc',
}

EXCLUDE_DIRS = {
    'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv',
    'venv', '.next', 'out', 'coverage', '.pytest_cache', 'target',
    '.cargo', 'pkg', 'debug', 'release', '.tox', '.mypy_cache',
    '.eggs', 'vendor', 'bower_components',
}

SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.env', '.json', '.yml', '.yaml', '.toml', '.cfg', '.ini',
    '.rb', '.go', '.rs', '.java', '.kt', '.swift', '.php',
    '.sh', '.bash', '.zsh', '.ps1',
}


def scan_project(project_path):
    """Scan a project directory and return structured findings.
    Pure function — no Flask, no DB, no side effects.
    """
    findings = []
    files_scanned = 0
    start = time.time()

    if not os.path.isdir(project_path):
        return {'error': f'Not a directory: {project_path}'}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, project_path)
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            # Sensitive file detection
            if filename.lower() in SENSITIVE_FILES:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Sensitive File',
                    'file': rel_path,
                    'line': 0,
                    'title': f'Sensitive file detected: {filename}',
                    'detail': 'This file may contain credentials or private keys.',
                })

            if ext not in SCAN_EXTENSIONS:
                continue

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(256_000)
            except Exception:
                continue

            files_scanned += 1
            lines = content.splitlines()

            for i, line in enumerate(lines):
                line_num = i + 1

                # Secret detection
                for pattern, secret_type in SECRET_PATTERNS:
                    if pattern.search(line):
                        if any(x in rel_path.lower() for x in [
                            'test', 'example', 'mock', 'fixture',
                            'package-lock', 'yarn.lock', '.min.'
                        ]):
                            continue
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'Hardcoded Secret',
                            'file': rel_path,
                            'line': line_num,
                            'title': f'{secret_type} detected',
                            'detail': f'Line {line_num}: potential {secret_type.lower()} in source code',
                        })

                # Dangerous functions
                for pattern, func_name, target_ext in DANGEROUS_FUNCTIONS:
                    if ext == target_ext and pattern.search(line):
                        stripped = line.strip()
                        if stripped.startswith('#') or stripped.startswith('//'):
                            continue
                        findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Dangerous Function',
                            'file': rel_path,
                            'line': line_num,
                            'title': f'{func_name} usage detected',
                            'detail': f'Line {line_num}: {func_name} can lead to code injection',
                        })

                # Network binding
                for pattern, msg in BINDING_PATTERNS:
                    if pattern.search(line):
                        findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Exposed Binding',
                            'file': rel_path,
                            'line': line_num,
                            'title': msg,
                            'detail': f'Line {line_num}: {msg.lower()} — potential network exposure',
                        })

    elapsed_ms = int((time.time() - start) * 1000)

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1

    return {
        'project_path': project_path,
        'files_scanned': files_scanned,
        'total_findings': len(findings),
        'severity_counts': sev_counts,
        'findings': findings,
        'scan_time_ms': elapsed_ms,
    }
