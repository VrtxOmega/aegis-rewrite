"""
Remediation Engine — Deterministic fix suggestion rules for scanner findings.
Maps (category, title_pattern) → structured remediation with confidence score.

NO AI. NO HALLUCINATION. Every suggestion comes from a hardcoded rule table.
Confidence is bounded by rule specificity (0.70–0.95).
"""
import re


# ═══════════════════════════════════════════
# REMEDIATION RULE TABLE
# ═══════════════════════════════════════════
# Each rule: (category_match, title_regex, suggestion_dict)
# Rules are checked in order; first match wins.

RULES = [
    # ── Hardcoded Secrets ──
    {
        'category': 'Hardcoded Secret',
        'title_pattern': re.compile(r'API Key', re.I),
        'suggestion': 'Extract the API key to an environment variable. Load via `os.environ["API_KEY"]` (Python) or `process.env.API_KEY` (Node.js). Add the variable to your `.env` file and ensure `.env` is in `.gitignore`.',
        'example_patch': (
            '# Before (INSECURE)\n'
            'API_KEY = "sk-abc123..."\n\n'
            '# After (SECURE)\n'
            'import os\n'
            'API_KEY = os.environ["API_KEY"]'
        ),
        'confidence': 0.92,
        'docs': 'https://12factor.net/config',
    },
    {
        'category': 'Hardcoded Secret',
        'title_pattern': re.compile(r'Password|Secret', re.I),
        'suggestion': 'Move the password/secret to an environment variable or a secrets manager. Never commit credentials to source control. If already committed, rotate the credential immediately and purge from git history using `git filter-repo` or BFG Repo Cleaner.',
        'example_patch': (
            '# Before (INSECURE)\n'
            'DB_PASSWORD = "mypassword123"\n\n'
            '# After (SECURE)\n'
            'import os\n'
            'DB_PASSWORD = os.environ.get("DB_PASSWORD")\n'
            'if not DB_PASSWORD:\n'
            '    raise RuntimeError("DB_PASSWORD not set")'
        ),
        'confidence': 0.90,
        'docs': 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
    },
    {
        'category': 'Hardcoded Secret',
        'title_pattern': re.compile(r'Token|Bearer', re.I),
        'suggestion': 'Tokens must be loaded from environment variables or a secure vault at runtime. Rotate the exposed token immediately. Add the file to `.gitignore` if it is a config file.',
        'example_patch': (
            '// Before (INSECURE)\n'
            'const TOKEN = "ghp_xxxxxxxxxxxx";\n\n'
            '// After (SECURE)\n'
            'const TOKEN = process.env.AUTH_TOKEN;\n'
            'if (!TOKEN) throw new Error("AUTH_TOKEN not configured");'
        ),
        'confidence': 0.90,
        'docs': 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
    },
    {
        'category': 'Hardcoded Secret',
        'title_pattern': re.compile(r'AWS', re.I),
        'suggestion': 'AWS credentials must use IAM roles, instance profiles, or the AWS credentials file (`~/.aws/credentials`). Never hardcode access keys. Rotate the exposed key via the AWS IAM console immediately.',
        'example_patch': (
            '# Before (INSECURE)\n'
            'aws_access_key_id = "AKIA..."\n\n'
            '# After (SECURE)\n'
            'import boto3\n'
            '# Uses ~/.aws/credentials or IAM role automatically\n'
            'client = boto3.client("s3")'
        ),
        'confidence': 0.95,
        'docs': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
    },
    {
        'category': 'Hardcoded Secret',
        'title_pattern': re.compile(r'Private Key', re.I),
        'suggestion': 'Private keys must never be in source code. Store in a secure key vault or as a file outside the repository. Reference via path environment variable. If committed, consider the key compromised and regenerate.',
        'example_patch': (
            '# Before (INSECURE)\n'
            '-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIEpAIBAAKCAQ...\n\n'
            '# After (SECURE)\n'
            'import os\n'
            'KEY_PATH = os.environ["PRIVATE_KEY_PATH"]\n'
            'with open(KEY_PATH) as f:\n'
            '    private_key = f.read()'
        ),
        'confidence': 0.93,
        'docs': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption',
    },
    {
        'category': 'Hardcoded Secret',
        'title_pattern': re.compile(r'Database URI', re.I),
        'suggestion': 'Database connection strings contain credentials and must be loaded from environment variables. Update your deployment config (Docker Compose, systemd, etc.) to inject the URI at runtime.',
        'example_patch': (
            '# Before (INSECURE)\n'
            'DATABASE_URL = "postgres://user:pass@host/db"\n\n'
            '# After (SECURE)\n'
            'import os\n'
            'DATABASE_URL = os.environ["DATABASE_URL"]'
        ),
        'confidence': 0.92,
        'docs': 'https://12factor.net/config',
    },

    # ── Dangerous Functions (Python) ──
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'^eval\(\)', re.I),
        'suggestion': 'Replace `eval()` with `ast.literal_eval()` for safe parsing of Python literals, or `json.loads()` for JSON data. `eval()` executes arbitrary code and is a direct code injection vector.',
        'example_patch': (
            '# Before (DANGEROUS)\n'
            'data = eval(user_input)\n\n'
            '# After (SAFE)\n'
            'import ast\n'
            'data = ast.literal_eval(user_input)  # Only parses literals\n'
            '# OR for JSON:\n'
            'import json\n'
            'data = json.loads(user_input)'
        ),
        'confidence': 0.88,
        'docs': 'https://docs.python.org/3/library/ast.html#ast.literal_eval',
    },
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'^exec\(\)', re.I),
        'suggestion': 'Remove `exec()` usage entirely. If dynamic dispatch is needed, use a dictionary mapping strings to callables. `exec()` allows arbitrary code execution.',
        'example_patch': (
            '# Before (DANGEROUS)\n'
            'exec(f"run_{action}()")\n\n'
            '# After (SAFE)\n'
            'ACTIONS = {"start": run_start, "stop": run_stop}\n'
            'handler = ACTIONS.get(action)\n'
            'if handler:\n'
            '    handler()'
        ),
        'confidence': 0.85,
        'docs': 'https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html',
    },
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'subprocess.*shell.*True', re.I),
        'suggestion': 'Replace `shell=True` with an explicit argument list (`shell=False`, the default). Passing user input through a shell enables command injection.',
        'example_patch': (
            '# Before (DANGEROUS)\n'
            'subprocess.call(f"process {filename}", shell=True)\n\n'
            '# After (SAFE)\n'
            'subprocess.run(["process", filename], check=True)'
        ),
        'confidence': 0.90,
        'docs': 'https://docs.python.org/3/library/subprocess.html#security-considerations',
    },
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'os\.system\(\)', re.I),
        'suggestion': 'Replace `os.system()` with `subprocess.run()`. `os.system()` invokes the shell and is vulnerable to command injection. `subprocess.run()` with an argument list is safer.',
        'example_patch': (
            '# Before (DANGEROUS)\n'
            'os.system(f"rm {filepath}")\n\n'
            '# After (SAFE)\n'
            'import subprocess\n'
            'subprocess.run(["rm", filepath], check=True)'
        ),
        'confidence': 0.88,
        'docs': 'https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html',
    },
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'__import__\(\)', re.I),
        'suggestion': 'Replace `__import__()` with standard `import` statements or `importlib.import_module()` with a validated allowlist of module names.',
        'example_patch': (
            '# Before (DANGEROUS)\n'
            'mod = __import__(user_input)\n\n'
            '# After (SAFE)\n'
            'import importlib\n'
            'ALLOWED = {"json", "csv", "datetime"}\n'
            'if module_name in ALLOWED:\n'
            '    mod = importlib.import_module(module_name)'
        ),
        'confidence': 0.82,
        'docs': 'https://docs.python.org/3/library/importlib.html',
    },

    # ── Dangerous Functions (JavaScript) ──
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'innerHTML', re.I),
        'suggestion': 'Replace `innerHTML` with `textContent` for plain text insertion. If HTML is required, sanitize input using DOMPurify before injection to prevent XSS.',
        'example_patch': (
            '// Before (DANGEROUS — XSS vector)\n'
            'el.innerHTML = userInput;\n\n'
            '// After (SAFE — plain text)\n'
            'el.textContent = userInput;\n\n'
            '// After (SAFE — sanitized HTML)\n'
            'import DOMPurify from "dompurify";\n'
            'el.innerHTML = DOMPurify.sanitize(userInput);'
        ),
        'confidence': 0.88,
        'docs': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    },
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'document\.write\(\)', re.I),
        'suggestion': 'Replace `document.write()` with DOM manipulation methods (`createElement`, `appendChild`, `insertAdjacentHTML`). `document.write()` can overwrite the entire page and enables XSS.',
        'example_patch': (
            '// Before (DANGEROUS)\n'
            'document.write("<p>" + msg + "</p>");\n\n'
            '// After (SAFE)\n'
            'const p = document.createElement("p");\n'
            'p.textContent = msg;\n'
            'document.body.appendChild(p);'
        ),
        'confidence': 0.90,
        'docs': 'https://developer.mozilla.org/en-US/docs/Web/API/Document/write',
    },
    {
        'category': 'Dangerous Function',
        'title_pattern': re.compile(r'new Function\(\)', re.I),
        'suggestion': 'Avoid `new Function()` as it evaluates strings as code (similar to `eval`). Refactor to use static function references or a dispatch map.',
        'example_patch': (
            '// Before (DANGEROUS)\n'
            'const fn = new Function("return " + expr);\n\n'
            '// After (SAFE)\n'
            '// Use a pre-defined operations map\n'
            'const ops = { add: (a,b) => a+b, sub: (a,b) => a-b };\n'
            'const fn = ops[opName];'
        ),
        'confidence': 0.82,
        'docs': 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function',
    },

    # ── Network Exposure ──
    {
        'category': 'Exposed Binding',
        'title_pattern': re.compile(r'0\.0\.0\.0', re.I),
        'suggestion': 'Bind to `127.0.0.1` (localhost only) for development servers and internal services. If external access is required, place behind a reverse proxy (nginx, Caddy) with TLS.',
        'example_patch': (
            '# Before (EXPOSED)\n'
            'app.run(host="0.0.0.0", port=8080)\n\n'
            '# After (LOCAL ONLY)\n'
            'app.run(host="127.0.0.1", port=8080)\n\n'
            '# After (PRODUCTION)\n'
            '# Use reverse proxy (nginx) in front'
        ),
        'confidence': 0.90,
        'docs': 'https://owasp.org/www-project-web-security-testing-guide/',
    },
    {
        'category': 'Exposed Binding',
        'title_pattern': re.compile(r'CORS', re.I),
        'suggestion': 'Restrict CORS to specific trusted origins instead of using wildcard (`*`). Wildcard CORS allows any website to make authenticated requests to your API.',
        'example_patch': (
            '# Before (DANGEROUS)\n'
            'CORS(app)  # Allows all origins\n\n'
            '# After (RESTRICTED)\n'
            'CORS(app, origins=["https://yourdomain.com"])'
        ),
        'confidence': 0.85,
        'docs': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    },

    # ── Sensitive Files ──
    {
        'category': 'Sensitive File',
        'title_pattern': re.compile(r'\.env|credentials|service.account', re.I),
        'suggestion': 'Add this file to `.gitignore` immediately. If already committed, remove from tracking with `git rm --cached <file>` and purge from history. Rotate any exposed credentials.',
        'example_patch': (
            '# .gitignore — add these lines:\n'
            '.env\n'
            '.env.local\n'
            '.env.production\n'
            'credentials.json\n'
            'service-account.json\n\n'
            '# Remove from git tracking (keeps local file):\n'
            'git rm --cached .env\n'
            'git commit -m "Stop tracking .env"'
        ),
        'confidence': 0.93,
        'docs': 'https://git-scm.com/docs/gitignore',
    },
    {
        'category': 'Sensitive File',
        'title_pattern': re.compile(r'id_rsa|id_ed25519|private.*key', re.I),
        'suggestion': 'SSH private keys must never be in a repository. Remove from tracking, add to `.gitignore`, and regenerate the key pair. The exposed key should be considered compromised.',
        'example_patch': (
            '# Remove from git:\n'
            'git rm --cached id_rsa\n'
            'echo "id_rsa" >> .gitignore\n'
            'git commit -m "Remove private key from tracking"\n\n'
            '# Regenerate key pair:\n'
            'ssh-keygen -t ed25519 -C "your_email@example.com"'
        ),
        'confidence': 0.95,
        'docs': 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key',
    },
]


def suggest_fix(finding: dict) -> dict:
    """Match a scanner finding to a remediation rule.
    Returns structured suggestion with confidence score.
    """
    category = finding.get('category', '')
    title = finding.get('title', '')

    for rule in RULES:
        if rule['category'] != category:
            continue
        if rule['title_pattern'].search(title):
            return {
                'matched': True,
                'suggestion': rule['suggestion'],
                'example_patch': rule['example_patch'],
                'confidence': rule['confidence'],
                'docs_url': rule.get('docs', ''),
                'finding_category': category,
                'finding_title': title,
            }

    # Fallback: no specific rule matched
    return {
        'matched': False,
        'suggestion': f'No specific remediation rule for "{title}" ({category}). Review the code manually and apply security best practices.',
        'example_patch': '',
        'confidence': 0.0,
        'docs_url': '',
        'finding_category': category,
        'finding_title': title,
    }
