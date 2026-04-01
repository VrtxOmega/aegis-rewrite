import app
import json

MUTATIONS = [
    # eval()
    {"title": "eval()", "category": "Dangerous Function", "file": "test.py", "lines": [
        ("data = eval('1+1')", "data = ast.literal_eval('1+1')", "Basic"),
        ("res=eval ( x )", "res=ast.literal_eval ( x )", "Spacing"),
        ("  v = eval(f'var_{i}')", "  v = ast.literal_eval(f'var_{i}')", "Indented"),
        ("# eval('print(1)')", None, "Commented out"),
    ]},

    # exec()
    {"title": "exec()", "category": "Dangerous Function", "file": "test.py", "lines": [
        ("exec(code)", "# FIXME [AEGIS]: Replace exec() with a dispatch dict\n# exec(code)", "Basic"),
        ("  exec ( f'run_{action}()' )", "  # FIXME [AEGIS]: Replace exec() with a dispatch dict\n  # exec ( f'run_{action}()' )", "F-string spacing"),
        ("// exec(data)", None, "Comment JS"),
    ]},

    # os.system()
    {"title": "os.system()", "category": "Dangerous Function", "file": "test.py", "lines": [
        ("os.system('ls')", "subprocess.run('ls')", "Basic"),
        ("os.system ( cmd )", "subprocess.run ( cmd )", "Spacing"),
    ]},

    # subprocess shell
    {"title": "subprocess shell", "category": "Dangerous Function", "file": "test.py", "lines": [
        ("subprocess.run('ls', shell=True)", "subprocess.run('ls', shell=False)", "Basic"),
        ("subprocess.Popen(cmd, shell = True)", "subprocess.Popen(cmd, shell=False)", "Spacing"),
    ]},

    # hardcoded secret
    {"title": "Hardcoded Secret", "category": "Hardcoded Secret", "file": "test.py", "lines": [
        ('API_KEY = "sk-123456789456789"', 'API_KEY = os.environ.get("API_KEY", "")', "Basic Python"),
        ('TOKEN: str = "secret"', 'TOKEN = os.environ.get("TOKEN", "")', "Type Hint Python"),
        ('  password="password123"', '  password = os.environ.get("PASSWORD", "")', "Indented, no space"),
        ('# API_KEY = "sk-123456789456789"', None, "Commented Python"),
    ]},
    {"title": "Hardcoded Secret", "category": "Hardcoded Secret", "file": "test.js", "lines": [
        ('const apiKey = "sk-123456789456789"', 'const apiKey = process.env.API_KEY || ""', "Basic JS"),
        ('export const jwtToken = "ey123"', 'export const jwtToken = process.env.JWT_TOKEN || ""', "Export const JS"),
        ('let _secret="abc"', 'let _secret = process.env._SECRET || ""', "Let no space"),
        ('var dbPass = `password123`', 'var dbPass = process.env.DB_PASS || ""', "Backticks"),
        ('{ "api_key": "sk-123456789456789" }', '{ "api_key": process.env.API_KEY || "" }', "JSON/Dict style keys string"),
        ('config = { apiKey: "sk-123456789" }', 'config = { "apiKey": process.env.API_KEY || "" }', "Object literal JS keys bare"),
    ]},

    # innerHTML
    {"title": "innerhtml", "category": "Dangerous Function", "file": "test.js", "lines": [
        ("el.innerHTML = '<h1>Hi</h1>'", "el.textContent = '<h1>Hi</h1>'", "Basic"),
        ("result.innerHTML = condition ? html1 : html2", "result.textContent = condition ? html1 : html2", "Inline conditional"),
        ("a = b.innerHTML = value", "a = b.textContent = value", "Chained assignment"),
        ("// el.innerHTML = x", None, "Commented JS"),
        ("<!-- <div innerHTML='test'></div> -->", None, "Commented HTML"),
        ("<div dangerouslySetInnerHTML={{ __html: data }} />", None, "JSX dangerouslySetInnerHTML (should ignore for Tier 1)"),
    ]},

    # document.write
    {"title": "document.write()", "category": "Dangerous Function", "file": "test.js", "lines": [
        ("document.write('<h1>Hi</h1>')", "// FIXME [AEGIS]: Replace with DOM manipulation\n// document.write('<h1>Hi</h1>')", "Basic"),
        ("  document.write ( data )", "  // FIXME [AEGIS]: Replace with DOM manipulation\n  // document.write ( data )", "Spacing"),
        ("/* document.write(a) */", None, "Comment JS multi"),
    ]},

    # CORS
    {"title": "cors wildcard", "category": "Exposed Binding", "file": "test.js", "lines": [
        ("res.setHeader('Access-Control-Allow-Origin', '*');", "res.setHeader('Access-Control-Allow-Origin', '\"http://127.0.0.1\"');", "Basic JS wildcard"),
    ]},

    {"title": "cors enabled", "category": "Exposed Binding", "file": "test.py", "lines": [
        ("CORS(app)", "CORS(app, origins=[\"http://127.0.0.1\"])", "Basic Flask CORS"),
        ("CORS ( api )", "CORS ( api, origins=[\"http://127.0.0.1\"] )", "Spacing"),
    ]},

    # debug mode
    {"title": "debug mode", "category": "Misc", "file": "test.py", "lines": [
        ("app.run(debug=True)", "app.run(debug=False)", "Basic"),
        ("app.run(port=5000, Debug = True)", "app.run(port=5000, debug=False)", "Case insensitive spacing"),
    ]}
]


def run_tests():
    passed = 0
    failed = 0
    total = 0

    print("=== AEGIS REWRITE: MUTATION TEST SUITE ===")

    for group in MUTATIONS:
        title = group['title']
        cat = group['category']
        file = group['file']
        finding = {'category': cat, 'title': title, 'file': file}

        print(f"\nTesting: {title} ({file})")
        for orig, expected, desc in group['lines']:
            total += 1
            res = app._apply_pattern_fix(orig, finding)

            if res == expected:
                passed += 1
                status = "✅ PASS"
            else:
                failed += 1
                status = "❌ FAIL"
            
            print(f"  {status} | {desc}")
            if status == "❌ FAIL":
                print(f"    In : {orig}")
                print(f"    Out: {res}")
                print(f"    Exp: {expected}")
    
    print(f"\n=== SUMMARY ===")
    print(f"Total: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    if failed == 0:
        print("DIAMOND ACHIEVED 💎")

if __name__ == '__main__':
    run_tests()
