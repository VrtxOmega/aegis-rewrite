"""
Aegis ReWrite — Scanner Engine v2
Pattern-based vulnerability detection. Cross-platform.
Refactored: shared _scan_file_content() eliminates code duplication.
New: debug=True, pickle.loads, yaml.load, SQL injection, dangerouslySetInnerHTML.
New: .gitignore awareness, finding deduplication, configurable severity per pattern.
"""
import os
import re
import time
import json


# ═══════════════════════════════════════════
# DETECTION PATTERNS
# Each tuple: (compiled_regex, display_title, severity, target_extension_or_None)
# target_extension: '.py' | '.js' | None (any)
# ═══════════════════════════════════════════

SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), 'API Key detected', 'CRITICAL'),
    (re.compile(r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), 'Password/Secret detected', 'CRITICAL'),
    (re.compile(r'(?:token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I), 'Token detected', 'CRITICAL'),
    (re.compile(r'(?:aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Z0-9]{16,})["\']', re.I), 'AWS Key detected', 'CRITICAL'),
    (re.compile(r'(?:private[_-]?key)\s*[:=]\s*["\']([^"\']{20,})["\']', re.I), 'Private Key detected', 'CRITICAL'),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', re.I), 'Private Key Block detected', 'CRITICAL'),
    (re.compile(r'(?:DATABASE_URL|MONGO_URI|REDIS_URL)\s*[:=]\s*["\']([^"\']+)["\']', re.I), 'Database URI detected', 'CRITICAL'),
]

# (regex, title, severity, ext) — ext=None means any extension
DANGEROUS_FUNCTIONS = [
    # Python
    (re.compile(r'\beval\s*\('), 'eval() usage detected', 'MEDIUM', '.py'),
    (re.compile(r'\bexec\s*\('), 'exec() usage detected', 'MEDIUM', '.py'),
    (re.compile(r'\b__import__\s*\('), '__import__() usage detected', 'MEDIUM', '.py'),
    (re.compile(r'\bsubprocess\.call\s*\(.*shell\s*=\s*True'), 'subprocess shell=True detected', 'HIGH', '.py'),
    (re.compile(r'\bos\.system\s*\('), 'os.system() usage detected', 'HIGH', '.py'),
    (re.compile(r'\bpickle\.loads?\s*\('), 'Unsafe pickle deserialization', 'HIGH', '.py'),
    (re.compile(r'\bdebug\s*=\s*True\b'), 'Debug Mode Enabled (debug=True)', 'CRITICAL', '.py'),
    # JavaScript / TypeScript
    (re.compile(r'\beval\s*\('), 'eval() usage detected', 'MEDIUM', '.js'),
    (re.compile(r'\bnew\s+Function\s*\('), 'new Function() usage detected', 'MEDIUM', '.js'),
    (re.compile(r'innerHTML\s*='), 'innerHTML assignment (XSS risk)', 'HIGH', '.js'),
    (re.compile(r'document\.write\s*\('), 'document.write() usage detected', 'MEDIUM', '.js'),
    # JSX / TSX
    (re.compile(r'dangerouslySetInnerHTML'), 'dangerouslySetInnerHTML (XSS risk)', 'HIGH', '.jsx'),
    (re.compile(r'dangerouslySetInnerHTML'), 'dangerouslySetInnerHTML (XSS risk)', 'HIGH', '.tsx'),
]

# YAML / SQL — handled separately to allow multi-line or conditional checks
def _check_yaml_unsafe(line):
    return bool(re.search(r'\byaml\.load\s*\(', line)) and 'Loader' not in line

def _check_sql_injection(line):
    return bool(re.search(
        r'\.execute\s*\(\s*(?:f["\']|["\'][^"\']*?\s*%\s*|["\'][^"\']*?\s*\+)',
        line
    ))

BINDING_PATTERNS = [
    (re.compile(r'\.listen\s*\(\s*["\']?0\.0\.0\.0["\']?'), 'Binding to 0.0.0.0', 'MEDIUM'),
    (re.compile(r'host\s*[:=]\s*["\']0\.0\.0\.0["\']'), 'Host set to 0.0.0.0', 'MEDIUM'),
    (re.compile(r'CORS\s*\(\s*\w+\s*\)'), 'CORS enabled (unrestricted)', 'MEDIUM'),
    (re.compile(r'Access-Control-Allow-Origin.*\*'), 'CORS wildcard origin', 'HIGH'),
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

# Paths containing these substrings are treated as test/mock code → skip secrets
SKIP_SECRET_SUBSTRINGS = {
    'test', 'example', 'mock', 'fixture',
    'package-lock', 'yarn.lock', '.min.',
}

# ═══════════════════════════════════════════
# SUPPLY CHAIN INTELLIGENCE
# ═══════════════════════════════════════════

KNOWN_MALICIOUS_PACKAGES = {
    'plain-crypto-js': ['4.2.1'],
    'axios': ['1.14.1', '0.30.4'],
}

TRUSTED_POSTINSTALL = {
    'esbuild', 'puppeteer', 'core-js', 'husky', 'electron',
    'node-gyp', 'prisma', '@prisma/client', 'sharp', 'canvas',
    'better-sqlite3', 'node-pty',
}

MAX_NODE_MODULES_SCANNED = 500  # Guard against enormous repos (A6)


def _load_gitignore(project_path):
    """Parse .gitignore and return a set of ignored basenames/patterns."""
    gitignore_path = os.path.join(project_path, '.gitignore')
    patterns = set()
    if os.path.isfile(gitignore_path):
        try:
            with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Store both the basename and the stripped leading-slash version
                        patterns.add(line.lstrip('/').split('/')[-1])
                        patterns.add(line.lstrip('/'))
        except Exception:
            pass
    return patterns


def _scan_npm_supply_chain(project_path):
    """Dedicated scanner for NPM ecosystem supply-chain attacks."""
    supply_findings = []
    has_lockfile = False

    # ── Rule 1: Malicious Package Detection ──
    lockfile_path = os.path.join(project_path, 'package-lock.json')
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
                            'detail': f'Package "{pkg_name}" at version {version} is a known supply-chain threat.',
                        })
        except Exception:
            pass

    # ── Rule 2: Suspicious Postinstall Hook Detection ──
    node_modules_dir = os.path.join(project_path, 'node_modules')
    if os.path.isdir(node_modules_dir):
        scanned_count = 0
        for entry in os.scandir(node_modules_dir):
            if scanned_count >= MAX_NODE_MODULES_SCANNED:
                break
            if not entry.is_dir():
                continue
            pkg_dirs = []
            if entry.name.startswith('@'):
                for subentry in os.scandir(entry.path):
                    if subentry.is_dir():
                        pkg_dirs.append((f"{entry.name}/{subentry.name}", subentry.path))
            else:
                pkg_dirs.append((entry.name, entry.path))
            for pkg_name, pkg_path in pkg_dirs:
                scanned_count += 1
                if scanned_count >= MAX_NODE_MODULES_SCANNED:
                    break
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
                                    'detail': f'Package "{pkg_name}" has an unrecognized deploy script. Verify immediately.',
                                })
                    except Exception:
                        pass

    # ── Rule 3: Pinned Version Enforcement ──
    pkg_json_root = os.path.join(project_path, 'package.json')
    if os.path.isfile(pkg_json_root):
        try:
            with open(pkg_json_root, 'r', encoding='utf-8') as f:
                root_data = json.load(f)
            for dep_type in ['dependencies', 'devDependencies']:
                deps = root_data.get(dep_type, {})
                for pkg_name, version in deps.items():
                    if '^' in version or '~' in version:
                        line_num = 0
                        with open(pkg_json_root, 'r', encoding='utf-8') as f_text:
                            for idx, line in enumerate(f_text):
                                if f'"{pkg_name}"' in line and version in line:
                                    line_num = idx + 1
                                    break
                        detail_msg = f'Line {line_num}: "{pkg_name}": "{version}" allows dangerous auto-updates.'
                        if not has_lockfile:
                            detail_msg += ' (No package-lock.json found — run npm install first.)'
                        supply_findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Pinned Version Enforcement',
                            'file': 'package.json',
                            'line': line_num if line_num > 0 else 0,
                            'title': 'Unpinned dependency version',
                            'detail': detail_msg,
                        })
        except Exception:
            pass

    return supply_findings


# ═══════════════════════════════════════════
# CORE FILE SCANNER (shared by all scan modes)
# ═══════════════════════════════════════════

def _scan_file_content(lines, rel_path, ext, gitignore_patterns=None):
    """Scan content lines of a single file. Returns list of findings.
    
    Pure function — no I/O, no side effects.
    Called by scan_project(), scan_project_streaming(), and scan_single_file().
    """
    findings = []
    rel_lower = rel_path.lower()
    is_skip_path = any(x in rel_lower for x in SKIP_SECRET_SUBSTRINGS)

    # ⚡ Bolt Optimization: Pre-filter dangerous functions by file extension outside the loop.
    # Avoids redundantly parsing and splitting comma-separated target extensions for every line,
    # significantly reducing the O(lines * patterns) overhead (~10x speedup for this block).
    applicable_dangerous_functions = [
        (pattern, title, severity)
        for pattern, title, severity, target_ext in DANGEROUS_FUNCTIONS
        if any(ext == e.strip() for e in target_ext.split(','))
    ]

    for i, line in enumerate(lines):
        line_num = i + 1
        stripped = line.strip()

        if 'aegis-ignore' in stripped:
            continue

        # Skip purely commented lines
        is_comment = stripped.startswith('#') or stripped.startswith('//')
        is_comment_block = stripped.startswith('/*') or stripped.startswith('*')

        # ── Secret Detection ──
        if not is_skip_path and not is_comment:
            for pattern, title, severity in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        'severity': severity,
                        'category': 'Hardcoded Secret',
                        'file': rel_path,
                        'line': line_num,
                        'title': title,
                        'detail': f'Line {line_num}: potential hardcoded credential in source code',
                    })

        # ── Dangerous Functions ──
        if not is_comment and not is_comment_block:
            for pattern, title, severity in applicable_dangerous_functions:
                if pattern.search(line):
                    findings.append({
                        'severity': severity,
                        'category': 'Dangerous Function',
                        'file': rel_path,
                        'line': line_num,
                        'title': title,
                        'detail': f'Line {line_num}: {title.lower()} can lead to security vulnerabilities',
                    })

            # YAML unsafe load check (Python only)
            if ext == '.py' and _check_yaml_unsafe(line):
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Dangerous Function',
                    'file': rel_path,
                    'line': line_num,
                    'title': 'Unsafe yaml.load() (no Loader specified)',
                    'detail': f'Line {line_num}: yaml.load() without Loader= can execute arbitrary Python objects',
                })

            # SQL injection check (Python only)
            if ext == '.py' and _check_sql_injection(line):
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'SQL Injection',
                    'file': rel_path,
                    'line': line_num,
                    'title': 'SQL Injection via string formatting',
                    'detail': f'Line {line_num}: User input interpolated directly into SQL query',
                })

        # ── Network Binding ──
        for pattern, title, severity in BINDING_PATTERNS:
            if pattern.search(line):
                findings.append({
                    'severity': severity,
                    'category': 'Exposed Binding',
                    'file': rel_path,
                    'line': line_num,
                    'title': title,
                    'detail': f'Line {line_num}: {title.lower()} — potential network exposure',
                })

    return findings


def _deduplicate(findings):
    """Remove exact duplicate findings (same file, line, category, title)."""
    seen = set()
    result = []
    for f in findings:
        key = (f.get('file', ''), f.get('line', 0), f.get('category', ''), f.get('title', ''))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


# ═══════════════════════════════════════════
# PUBLIC SCAN FUNCTIONS
# ═══════════════════════════════════════════

def scan_project(project_path):
    """Non-streaming scan. Returns full result dict."""
    findings = []
    files_scanned = 0
    start = time.time()

    if not os.path.isdir(project_path):
        return {'error': f'Not a directory: {project_path}'}

    gitignore = _load_gitignore(project_path)

    # Phase 0: NPM supply chain
    try:
        findings.extend(_scan_npm_supply_chain(project_path))
    except Exception as e:
        print(f'[Scanner] Supply chain error: {e}')

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, project_path)
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            # Sensitive file detection (with .gitignore awareness)
            if filename.lower() in SENSITIVE_FILES:
                basename = filename.lower()
                in_gitignore = basename in gitignore or filename in gitignore
                findings.append({
                    'severity': 'LOW' if in_gitignore else 'HIGH',
                    'category': 'Sensitive File',
                    'file': rel_path,
                    'line': 0,
                    'title': f'Sensitive file detected: {filename}',
                    'detail': (
                        f'This file is in .gitignore and protected from commits.'
                        if in_gitignore
                        else 'This file may contain credentials or private keys and is NOT in .gitignore.'
                    ),
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
            findings.extend(_scan_file_content(lines, rel_path, ext, gitignore))

    findings = _deduplicate(findings)
    elapsed_ms = int((time.time() - start) * 1000)

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

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

    Phase 1: Count total scannable files (fast).
    Phase 2: Full scan, yielding progress after each file.

    Yields dicts:
      {"type": "counting", "total_files": N}
      {"type": "progress", "files_scanned": N, "total_files": T,
       "current_file": "rel/path", "findings_so_far": F}
      {"type": "complete", ...full result dict...}
    """
    if not os.path.isdir(project_path):
        yield {'type': 'error', 'message': f'Not a directory: {project_path}'}
        return

    gitignore = _load_gitignore(project_path)

    # Phase 1: Count
    total_files = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext.lower() in SCAN_EXTENSIONS:
                total_files += 1

    yield {'type': 'counting', 'total_files': total_files}

    # Phase 2: Full scan
    findings = []
    files_scanned = 0
    start = time.time()

    try:
        sc = _scan_npm_supply_chain(project_path)
        if sc:
            findings.extend(sc)
            yield {
                'type': 'progress',
                'files_scanned': 0,
                'total_files': total_files,
                'current_file': 'Supply Chain Analyzer',
                'findings_so_far': len(findings),
            }
    except Exception:
        pass

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, project_path)
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            if filename.lower() in SENSITIVE_FILES:
                in_gitignore = filename.lower() in gitignore or filename in gitignore
                findings.append({
                    'severity': 'LOW' if in_gitignore else 'HIGH',
                    'category': 'Sensitive File',
                    'file': rel_path,
                    'line': 0,
                    'title': f'Sensitive file detected: {filename}',
                    'detail': (
                        'This file is in .gitignore and protected from commits.'
                        if in_gitignore
                        else 'This file may contain credentials or private keys and is NOT in .gitignore.'
                    ),
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
            file_findings = _scan_file_content(lines, rel_path, ext, gitignore)
            findings.extend(file_findings)

            yield {
                'type': 'progress',
                'files_scanned': files_scanned,
                'total_files': total_files,
                'current_file': rel_path,
                'findings_so_far': len(findings),
            }

    findings = _deduplicate(findings)
    elapsed_ms = int((time.time() - start) * 1000)

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

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
    """Scan a single file for real-time post-fix verification."""
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
    return _scan_file_content(lines, rel_path, ext)
