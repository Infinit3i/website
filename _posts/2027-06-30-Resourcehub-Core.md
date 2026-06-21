---
layout: post
title: "Resourcehub Core"
date: 2027-06-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Secure Coding]
tags: [hackthebox, challenge, secure-coding, path-traversal, cwe-22, nodejs, file-upload, formidable, socketio]
---

## Overview

Resourcehub Core is an HTB Secure Coding challenge (Easy, retired) presenting an HTB Editor — a React SPA fronting a Node.js Express application that manages uploadable resource files. The sole vulnerability is a [path traversal](https://cwe.mitre.org/data/definitions/22.html) in the multipart file-upload handler: the client-supplied `originalFilename` is passed directly to `path.join()` without calling `path.basename()`, letting an attacker escape the `resources/` directory and write arbitrary files anywhere the process has write access. The solve is a Secure Coding challenge, so the goal is to **patch the vulnerability** and trigger `GET /api/verify` to collect the flag — not to exploit the running service.

**[CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**

---

## The Technique

The Express upload route uses the `formidable` library to parse multipart uploads. After parsing it constructs the destination path by concatenating `__dirname + '/../resources/' + file.originalFilename` via `path.join()`:

```javascript
// routes/routes.js — vulnerable code
const targetFilename = file.originalFilename;
const targetPath = path.join(__dirname, '../resources', targetFilename);
fs.renameSync(file.filepath, targetPath);
```

`path.join` normalises `..` segments rather than rejecting them, so a filename like `../static/js/evil.js` resolves cleanly to the web-accessible `static/js/` directory. The challenge ships a confirming `exploit/solver.py` that uploads to `../static/js/<random>.txt` and GETs it back to verify the traversal succeeded.

The HTB Editor (the code-editing frontend) saves file changes over **Socket.IO EIO4 long-polling** — not a plain HTTP PUT. The save flow:

1. `GET /socket.io/?EIO=4&transport=polling` → handshake, receive session id (SID).
2. `POST /socket.io/?EIO=4&transport=polling&sid=<SID>` with body `40` → connect to the default namespace.
3. `POST /socket.io/...` with body `42["message", {type:"save", data:{fileName, content, md5}}]` → save the file. The `md5` field is the MD5 of the **current server file** (conflict detection), **not** the new content — sending the wrong MD5 returns a `save_conflict` event.
4. `POST /api/restart` → reload the Node.js process so it picks up the edited file.
5. `GET /api/verify` → the server runs the built-in exploit script against itself; if the traversal no longer succeeds it returns `{"flag": "HTB{...}"}`.

---

## Solution

Read the original file to compute its MD5, send the patched version via Socket.IO polling, restart the service, then verify.

```python
#!/usr/bin/env python3
import requests, json, hashlib, time

TARGET = "http://<rhost>:<port>"
SIO    = f"{TARGET}/socket.io/"

# 1. Read current file; its MD5 is the conflict-check token the editor expects
r = requests.get(f"{TARGET}/api/file?path=routes/routes.js")
original_content = r.json()['content']
original_md5 = hashlib.md5(original_content.encode()).hexdigest()

# 2. Fixed content — path.basename() + resolved-path prefix check
FIXED = r"""const express = require('express');
const router = express.Router();
const { formidable } = require('formidable');
const fs = require('fs');
const path = require('path');

const resourcesDir = path.join(__dirname, '../resources');
const uploadsDir = path.join(__dirname, '../uploads');

router.use(express.static('static'));

router.post('/api/upload-resource', (req, res) => {
    const form = formidable({ uploadDir: uploadsDir, keepExtensions: true });
    form.parse(req, (err, fields, files) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        const file = Array.isArray(files.file) ? files.file[0] : files.file;
        if (!file) return res.status(400).json({ success: false, error: 'No file uploaded' });
        try {
            const targetFilename = path.basename(file.originalFilename);
            if (!targetFilename)
                return res.status(400).json({ success: false, error: 'Invalid filename' });
            const targetPath = path.join(resourcesDir, targetFilename);
            if (!targetPath.startsWith(resourcesDir + path.sep))
                return res.status(400).json({ success: false, error: 'Invalid file path' });
            fs.renameSync(file.filepath, targetPath);
            res.json({ success: true, filename: targetFilename });
        } catch (e) {
            res.status(500).json({ success: false, error: e.message });
        }
    });
});

router.get('/api/resources', (req, res) => {
    try {
        const files = fs.readdirSync(resourcesDir);
        const resources = files.map(f => ({
            name: f, path: `/resources/${f}`,
            size: fs.statSync(path.join(resourcesDir, f)).size,
            lastModified: fs.statSync(path.join(resourcesDir, f)).mtime
        }));
        res.json({ success: true, resources });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../views', 'index.html'));
});

module.exports = router;
"""

# 3. Socket.IO EIO4 polling — handshake
r = requests.get(f"{SIO}?EIO=4&transport=polling")
sid = json.loads(r.text[1:])['sid']          # response: "0{...json...}"
requests.post(f"{SIO}?EIO=4&transport=polling&sid={sid}", data="40")
time.sleep(0.5)
requests.get(f"{SIO}?EIO=4&transport=polling&sid={sid}")  # drain welcome

# 4. Save — md5 is the ORIGINAL file hash, not the fixed content hash
msg = json.dumps(["message", {"type": "save", "data": {
    "fileName": "routes/routes.js",
    "content":  FIXED,
    "md5":      original_md5   # conflict check: hash of current server file
}}])
requests.post(f"{SIO}?EIO=4&transport=polling&sid={sid}", data=f"42{msg}")
time.sleep(1)

# 5. Restart + verify
requests.post(f"{TARGET}/api/restart")
time.sleep(3)
r = requests.get(f"{TARGET}/api/verify")
print(r.json())  # {"flag": "HTB{...}"}
```

---

## Why It Worked

`path.join()` in Node.js resolves `..` components by design — it is a path-composition utility, not a security boundary. Giving it user-supplied input like `../static/js/evil.txt` produces a valid, normalised path outside the intended directory with no error or warning. The only correct defence is to strip all directory components from the client-supplied name before any path construction.

The Socket.IO MD5 conflict-check is an interesting subtlety: the editor sends the hash of the **file as it was when you opened it**, not the hash of your new content. Sending the new content's hash triggers a `save_conflict` response — the server interprets it as "someone else changed the file since you loaded it."

---

## Fix / Defense

Replace the raw `originalFilename` with `path.basename(originalFilename)` and validate the resolved path before writing:

```javascript
const targetFilename = path.basename(file.originalFilename);   // strips ../../../
if (!targetFilename) throw new Error('empty filename');

const targetPath = path.join(resourcesDir, targetFilename);
if (!targetPath.startsWith(resourcesDir + path.sep))           // belt-and-suspenders
    throw new Error('path traversal detected');

fs.renameSync(file.filepath, targetPath);
```

Stronger approach: ignore the client filename entirely and generate a server-side name (`crypto.randomUUID() + '.txt'`), which removes the attack surface completely.

OWASP [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) / [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
