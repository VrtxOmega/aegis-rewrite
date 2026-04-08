"""
Aegis ReWrite — AI Explain Engine
Optional Ollama integration for plain-English vulnerability explanations.
Graceful degradation — works fully without Ollama installed.
"""
import re
import json
import requests

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL = "qwen3:8b"
TIMEOUT_SECONDS = 60
MAX_RESPONSE_LEN = 4000

__all__ = ['OLLAMA_URL', 'MODEL', 'check_ollama', 'model_exists',
           'explain_finding', 'explain_fix', 'generate_fix']

# ═══════════════════════════════════════════
# POST-LLM OUTPUT SANITIZER
# ═══════════════════════════════════════════
_DANGEROUS_PATTERNS = [
    (re.compile(r'(?:rd|rmdir)\s+/s\s+/q', re.I), '[REDACTED: destructive command]'),
    (re.compile(r'Remove-Item\s+.*-Recurse', re.I), '[REDACTED: destructive command]'),
    (re.compile(r'format\s+[A-Z]:', re.I), '[REDACTED: destructive command]'),
    (re.compile(r'del\s+/[fFsS]\s+/[qQ]', re.I), '[REDACTED: destructive command]'),
    (re.compile(r'reg\s+delete', re.I), '[REDACTED: destructive command]'),
    (re.compile(r'(?:Invoke-WebRequest|curl|wget)\s+.*\|\s*(?:iex|Invoke-Expression|bash|sh)', re.I),
     '[REDACTED: download cradle]'),
]


def _sanitize(text):
    """Strip dangerous OS commands from LLM output."""
    for pattern, replacement in _DANGEROUS_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def check_ollama():
    """Check if Ollama is running and responsive."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def model_exists(model_name):
    """Check if a specific model is pulled and available in Ollama.
    Returns True if found, False if not, None if Ollama is offline.
    """
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        if r.status_code != 200:
            return None
        models = [m['name'] for m in r.json().get('models', [])]
        # Allow partial match (e.g. 'qwen3:8b' matches 'qwen3:8b' exactly,
        # and 'qwen3' matches 'qwen3:latest')
        return any(model_name == m or model_name.split(':')[0] == m.split(':')[0] for m in models)
    except Exception:
        return None


def _generate(prompt, system=None, max_tokens=2000, model=MODEL):
    """Call Ollama generate endpoint."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": max_tokens, "temperature": 0.3},
    }
    if system:
        payload["system"] = system

    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=TIMEOUT_SECONDS
        )
        if r.status_code == 200:
            text = r.json().get("response", "").strip()
            text = _sanitize(text)
            if len(text) > MAX_RESPONSE_LEN:
                text = text[:MAX_RESPONSE_LEN] + "\n\n[Response truncated for safety]"
            return text
    except Exception:
        pass
    return None


EXPLAIN_SYSTEM = """You are a code security advisor inside Aegis ReWrite.
Your job: explain security vulnerabilities in plain English that any developer can understand.
Rules:
- Use simple, direct language. No jargon without explanation.
- Start with WHAT the problem is (1-2 sentences).
- Then WHY it matters (what could go wrong).
- Then HOW to fix it (specific code-level guidance).
- Keep total response under 200 words.
- Never suggest destructive system commands.
- Never include download links or external scripts."""


def explain_finding(finding):
    """Generate a plain-English explanation of a security finding.
    Returns dict with 'explanation', 'ai_available', and optional 'error'.
    """
    if not check_ollama():
        return {'explanation': None, 'ai_available': False, 'error': 'ollama_offline'}

    model = finding.get('model', MODEL)
    exists = model_exists(model)
    if exists is False:
        return {
            'explanation': None,
            'ai_available': True,
            'error': f'model_not_found:{model}',
        }

    prompt = f"""Explain this security finding to a developer in plain English:

Category: {finding.get('category', 'Unknown')}
Title: {finding.get('title', 'Unknown')}  
Severity: {finding.get('severity', 'Unknown')}
File: {finding.get('file', 'Unknown')}
Line: {finding.get('line', '?')}
Detail: {finding.get('detail', 'No details')}

Plain English explanation:"""

    text = _generate(prompt, system=EXPLAIN_SYSTEM, model=model)
    if text:
        return {'explanation': text, 'ai_available': True, 'error': None}
    return {'explanation': None, 'ai_available': True, 'error': 'generation_failed'}


def explain_fix(finding, suggestion):
    """Explain what a proposed fix does and why it works."""
    if not check_ollama():
        return {'explanation': None, 'ai_available': False}

    prompt = f"""A code scanner found this issue:
{finding.get('title', '')} in {finding.get('file', '')} (line {finding.get('line', '?')})

The suggested fix is:
{suggestion}

Explain in 2-3 plain English sentences what this fix does and why it addresses the security issue."""

    model = finding.get('model', MODEL)
    text = _generate(prompt, system=EXPLAIN_SYSTEM, max_tokens=500, model=model)
    if text:
        return {'explanation': text, 'ai_available': True}
    return {'explanation': None, 'ai_available': False}


# ═══════════════════════════════════════════
# AI CODE REWRITER
# ═══════════════════════════════════════════

REWRITE_SYSTEM = """You are an expert code security engineer inside Aegis ReWrite.
Your ONLY job: rewrite vulnerable code to be secure. Output ONLY the fixed code lines.

ABSOLUTE RULES:
1. Output ONLY the replacement code. No explanations, no markdown, no backticks, no comments about what you changed.
2. Preserve the original indentation exactly.
3. Preserve the original coding style (quotes, spacing, naming conventions).
4. The fix must be a DROP-IN replacement — same function signature, same behavior, just secure.
5. If the original is 1 line, your fix should be 1-3 lines max.
6. If the original uses specific imports, keep them.
7. Never add print statements, logging, or comments unless replacing a dangerous call.
8. Never output system commands, file deletions, or network requests.
9. Never wrap output in markdown code fences or backticks.
10. Output must be valid code in the same language as the input."""


def generate_fix(finding, code_context, target_line):
    """Use AI to generate a secure replacement for vulnerable code.
    
    Args:
        finding: dict with category, title, severity, detail
        code_context: list of surrounding code lines (5 before + target + 5 after)
        target_line: the specific line that needs fixing
    
    Returns:
        dict with 'fixed_line', 'ai_available', 'method'
    """
    if not check_ollama():
        return {'fixed_line': None, 'ai_available': False, 'method': None}

    context_str = '\n'.join(code_context)
    category = finding.get('category', '')
    title = finding.get('title', '')

    prompt = f"""Fix this security vulnerability. Output ONLY the replacement line(s).

VULNERABILITY: {title} ({category})
SEVERITY: {finding.get('severity', 'MEDIUM')}

SURROUNDING CODE:
{context_str}

VULNERABLE LINE:
{target_line}

SECURITY GUIDANCE:
{_get_fix_guidance(category, title)}

Output ONLY the fixed replacement for the vulnerable line. No explanation. No markdown. Just code:"""

    model = finding.get('model', MODEL)
    result = _generate(prompt, system=REWRITE_SYSTEM, max_tokens=500, model=model)
    
    if result:
        # Clean up AI output — strip markdown fences, backticks, leading/trailing whitespace
        fixed = _clean_ai_code_output(result, target_line)
        if fixed and fixed.strip() != target_line.strip():
            return {'fixed_line': fixed, 'ai_available': True, 'method': 'ai'}
    
    return {'fixed_line': None, 'ai_available': True, 'method': None}


def _clean_ai_code_output(raw, original_line):
    """Clean AI output to extract just the code."""
    lines = raw.strip().split('\n')
    
    # Remove markdown fences
    cleaned = []
    in_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('```'):
            in_fence = not in_fence
            continue
        if stripped.startswith('//') and ('FIXME' in stripped or 'TODO' in stripped or 'AEGIS' in stripped):
            continue  # Skip meta-comments
        if stripped.startswith('#') and ('FIXME' in stripped or 'TODO' in stripped or 'AEGIS' in stripped):
            continue
        cleaned.append(line)
    
    if not cleaned:
        return None
    
    # Preserve original indentation
    original_indent = original_line[:len(original_line) - len(original_line.lstrip())]
    
    # If AI returned multiple lines, join with newlines and apply indent
    result_lines = []
    for i, line in enumerate(cleaned):
        if i == 0:
            # First line gets original indentation
            result_lines.append(original_indent + line.lstrip())
        else:
            # Subsequent lines preserve relative indentation from AI
            result_lines.append(original_indent + line.lstrip())
    
    return '\n'.join(result_lines)


def _get_fix_guidance(category, title):
    """Provide specific security guidance for the AI based on finding type."""
    title_lower = title.lower()
    
    if category == 'Hardcoded Secret':
        return "Replace the hardcoded value with os.environ.get() or os.environ[]. Keep the variable name. Import os if needed."
    
    if 'eval' in title_lower and 'eval()' in title_lower:
        return "Replace eval() with ast.literal_eval() for data parsing or json.loads() for JSON. Import ast or json if needed."
    
    if 'exec' in title_lower and 'exec()' in title_lower:
        return "Replace exec() with a dictionary dispatch pattern. Map string keys to callable functions. Never execute arbitrary strings as code."
    
    if '__import__' in title_lower:
        return "Replace __import__() with importlib.import_module(). Add 'import importlib' if needed. Validate module name against an allowlist."
    
    if 'subprocess' in title_lower and 'shell' in title_lower:
        return "Change shell=True to shell=False. Convert the command string to a list of arguments. Use subprocess.run() instead of subprocess.call()."
    
    if 'os.system' in title_lower:
        return "Replace os.system() with subprocess.run(). Convert the command string to a list of arguments with shell=False."
    
    if 'innerhtml' in title_lower:
        return "Replace .innerHTML with .textContent for plain text, or sanitize with DOMPurify before using .innerHTML."
    
    if 'document.write' in title_lower:
        return "Replace document.write() with document.createElement() and appendChild(), or insertAdjacentHTML()."
    
    if 'new function' in title_lower:
        return "Replace new Function() with a static dispatch map (object mapping keys to arrow functions)."
    
    if '0.0.0.0' in title_lower:
        return "Replace 0.0.0.0 with 127.0.0.1 to bind to localhost only."
    
    if 'cors' in title_lower:
        return "Restrict CORS to specific origins instead of wildcard. Use CORS(app, origins=['http://127.0.0.1'])."
    
    if category == 'Sensitive File':
        return "This file should be added to .gitignore and removed from version control with 'git rm --cached'."
    
    return "Apply the most secure standard practice for this vulnerability type."

