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

# ═══════════════════════════════════════════
# SUPPLY CHAIN INTELLIGENCE
# ═══════════════════════════════════════════

KNOWN_MALICIOUS_PACKAGES = {
    'plain-crypto-js': ['4.2.1'],
    'axios': ['1.14.1', '0.30.4'],
}

TRUSTED_POSTINSTALL = {
    'esbuild',
    'puppeteer',
    'core-js',
    'husky',
    'electron',
    'node-gyp',
    'prisma',
    '@prisma/client',
    'sharp',
    'canvas',
    'better-sqlite3',
    'node-pty',
}

import json

def _scan_npm_supply_chain(project_path):
    """
    Dedicated scanner for NPM ecosystem supply-chain attacks.
    Executes fast JSON parsing before the expensive Regex phase.
    """
    supply_findings = []
    
    # ── Rule 1: Malicious Package Detection ──
    lockfile_path = os.path.join(project_path, 'package-lock.json')
    has_lockfile = False
    if os.path.isfile(lockfile_path):
        has_lockfile = True
        try:
            with open(lockfile_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            deps = lock_data.get('dependencies', {})
            pkgs = lock_data.get('packages', {})
            all_pkgs = {**deps, **{k.replace('node_modules/', ''): v for k, v in pkgs.items() if k}}
            
            for pkg_name, pkg_data in all_pkgs.items():
                if pkg_name in KNOWN_MALICIOUS_PACKAGES:
                    version = pkg_data.get('version', '')
                    if version in KNOWN_MALICIOUS_PACKAGES[pkg_name] or not KNOWN_MALICIOUS_PACKAGES[pkg_name]:
                        supply_findings.append({
                            'severity': 'CRITICAL',
                            'category': 'Package Blocklist',
                            'file': 'package-lock.json',
                            'line': 0,
                            'title': 'Known Malicious Package detected',
                            'detail': f'Package "{pkg_name}" at version {version} is a known supply-chain threat.'
                        })
        except Exception:
            pass

    # ── Rule 2: Suspicious Postinstall Hook Detection ──
    node_modules_dir = os.path.join(project_path, 'node_modules')
    if os.path.isdir(node_modules_dir):
        # We only want to go 1 or 2 levels deep (for @scoped packages)
        for entry in os.scandir(node_modules_dir):
            if not entry.is_dir(): continue
            
            pkg_dirs = []
            if entry.name.startswith('@'):
                for subentry in os.scandir(entry.path):
                    if subentry.is_dir():
                        pkg_dirs.append((f"{entry.name}/{subentry.name}", subentry.path))
            else:
                pkg_dirs.append((entry.name, entry.path))
                
            for pkg_name, pkg_path in pkg_dirs:
                pkg_json_path = os.path.join(pkg_path, 'package.json')
                if os.path.isfile(pkg_json_path):
                    try:
                        with open(pkg_json_path, 'r', encoding='utf-8') as f:
                            pkg_data = json.load(f)
                        scripts = pkg_data.get('scripts', {})
                        if 'postinstall' in scripts or 'preinstall' in scripts:
                            if pkg_name not in TRUSTED_POSTINSTALL:
                                supply_findings.append({
                                    'severity': 'HIGH',
                                    'category': 'Suspicious Hook',
                                    'file': f'node_modules/{pkg_name}/package.json',
                                    'line': 0,
                                    'title': 'Unverified postinstall script found',
                                    'detail': f'Package "{pkg_name}" has an unrecognized deploy script. Verify immediately.'
                                })
                    except Exception:
                        pass

    # ── Rule 3: Pinned Version Enforcement ──
    pkg_json_root = os.path.join(project_path, 'package.json')
    if os.path.isfile(pkg_json_root):
        try:
            with open(pkg_json_root, 'r', encoding='utf-8') as f:
                root_data = json.load(f)
            
            # Check dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                deps = root_data.get(dep_type, {})
                for pkg_name, version in deps.items():
                    if '^' in version or '~' in version:
                        # Find the line number manually for accuracy in the UI
                        line_num = 0
                        with open(pkg_json_root, 'r', encoding='utf-8') as f_text:
                            for idx, line in enumerate(f_text):
                                if f'"{pkg_name}"' in line and version in line:
                                    line_num = idx + 1
                                    break
                        
                        detail_msg = f'Line {line_num}: "{pkg_name}": "{version}" allows dangerous auto-updates.'
                        if not has_lockfile:
                            detail_msg += " (No package-lock.json found. Cannot auto-remediate accurately. Run npm install first.)"
                            
                        supply_findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Pinned Version Enforcement',
                            'file': 'package.json',
                            'line': line_num if line_num > 0 else 0,
                            'title': 'Unpinned dependency version',
                            'detail': detail_msg
                        })
        except Exception:
            pass

    return supply_findings




def scan_project(project_path):
    """Scan a project directory and return structured findings.
    Pure function — no Flask, no DB, no side effects.
    """
    findings = []
    files_scanned = 0
    start = time.time()

    if not os.path.isdir(project_path):
        return {'error': f'Not a directory: {project_path}'}

    # ── Phase 0: Fast NPM Ecosystem Analysis ──
    try:
        findings.extend(_scan_npm_supply_chain(project_path))
    except Exception as e:
        print(f"Supply chain scan error: {e}")

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


def scan_project_streaming(project_path):
    """Streaming scanner — yields JSON progress events for SSE.

    Phase 1: Fast directory walk to count total scannable files.
    Phase 2: Full scan, yielding progress after each file.

    Yields dicts:
      {"type": "counting", "total_files": N}
      {"type": "progress", "files_scanned": N, "total_files": T,
       "current_file": "rel/path", "findings_so_far": F}
      {"type": "complete", ...full result dict...}
    """
    import json as _json

    if not os.path.isdir(project_path):
        yield {'type': 'error', 'message': f'Not a directory: {project_path}'}
        return

    # ── Phase 1: Count total scannable files (fast — no file reading) ──
    total_files = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext.lower() in SCAN_EXTENSIONS:
                total_files += 1

    yield {'type': 'counting', 'total_files': total_files}

    # ── Phase 2: Full scan with progress ──
    findings = []
    files_scanned = 0
    start = time.time()

    try:
        supply_chain_findings = _scan_npm_supply_chain(project_path)
        if supply_chain_findings:
            findings.extend(supply_chain_findings)
            yield {
                'type': 'progress',
                'files_scanned': files_scanned,
                'total_files': total_files,
                'current_file': 'Supply Chain Analyzer',
                'findings_so_far': len(findings)
            }
    except Exception as e:
        pass

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

            # Yield progress event after each file scanned
            yield {
                'type': 'progress',
                'files_scanned': files_scanned,
                'total_files': total_files,
                'current_file': rel_path,
                'findings_so_far': len(findings),
            }

    elapsed_ms = int((time.time() - start) * 1000)

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1

    yield {
        'type': 'complete',
        'project_path': project_path,
        'files_scanned': files_scanned,
        'total_findings': len(findings),
        'severity_counts': sev_counts,
        'findings': findings,
        'scan_time_ms': elapsed_ms,
    }


def scan_single_file(filepath, project_path):
    """Scan a single file to verify fixes in real-time."""
    findings = []
    
    if not os.path.isfile(filepath):
        return findings

    filename = os.path.basename(filepath)
    rel_path = os.path.relpath(filepath, project_path)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    if ext not in SCAN_EXTENSIONS:
        return findings

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(256_000)
    except Exception:
        return findings

    lines = content.splitlines()

    for i, line in enumerate(lines):
        line_num = i + 1

        for pattern, secret_type in SECRET_PATTERNS:
            if pattern.search(line):
                if any(x in rel_path.lower() for x in ['test', 'example', 'mock', 'fixture', 'package-lock', 'yarn.lock', '.min.']):
                    continue
                findings.append({'category': 'Hardcoded Secret', 'file': rel_path, 'line': line_num, 'title': f'{secret_type} detected'})

        for pattern, func_name, target_ext in DANGEROUS_FUNCTIONS:
            if ext == target_ext and pattern.search(line):
                stripped = line.strip()
                if not (stripped.startswith('#') or stripped.startswith('//')):
                    findings.append({'category': 'Dangerous Function', 'file': rel_path, 'line': line_num, 'title': f'{func_name} usage detected'})

        for pattern, msg in BINDING_PATTERNS:
            if pattern.search(line):
                findings.append({'category': 'Exposed Binding', 'file': rel_path, 'line': line_num, 'title': msg})
                
    return findings
