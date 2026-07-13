---
layout: post
title: "Hypercraft"
date: 2028-05-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, html-smuggling, malware-analysis, deobfuscation, powershell, python]
description: "A single phishing .eml peels down through seven layers of an HTML-smuggling dropper — XOR-over-base64 in-browser ZIP assembly, an obfuscated .pdf.js, a hex-eval stage, and a raw-deflate PowerShell IEX cradle whose strings are single-byte XOR — with the flag at the bottom. Every layer is a reversible encoding, so it comes apart statically in Python, no sandbox execution."
---

## Overview

Hypercraft is a **Medium** HackTheBox **Forensics** challenge. You're handed one file, `hypercraft.eml` —
a phishing email with a `[TOP SECRET] Arodorian Hypercraft.pdf.html` attachment. The `.pdf.html`
double-extension is the classic [HTML smuggling](https://cwe.mitre.org/data/definitions/506.html)
tell: the browser renders it, JavaScript rebuilds a malicious file entirely client-side, and it
self-downloads — no payload ever crosses the network, so a mail gateway's AV never sees it. The whole
challenge is peeling that dropper apart, one reversible encoding at a time, until the flag falls out.

## The technique

The dropper stacks **seven layers**, each a plain encoding you can invert in Python. The rule for the
whole class: an obfuscated dropper is a stack of reversible transforms — identify each one and undo it,
never run the sample.

| # | Layer | Transform to undo |
|---|-------|-------------------|
| 1 | `.eml` | MIME base64-decode the attachment |
| 2 | `.pdf.html` (HTML smuggling) | `ZIP = base64( XOR( atob(element#A data-attr), element#B data-attr ) )` — payload in one element's `data=` attribute, XOR key in another's |
| 3 | ZIP | contains `[TOP SECRET] Arodorian Hypercraft.pdf.js` |
| 4 | `.pdf.js` | strip `s`/`V` junk chars from 4 concatenated chunks, hex-decode pairs, `Function(...)()` = eval |
| 5 | stage-3 JS | rebuild a `var x = y + "..."` concat chain, base64-decode, split on `!` |
| 6 | obfuscated PowerShell | `[convert]::FromBase64String(...)` + `DeflateStream` = raw-deflate inflate |
| 7 | PowerShell strings | every secret is `UYcxq(byte[], key)` = single-byte XOR |

Layer 2 is the heart of it. The page hides every API name behind an XOR-over-base64 string decoder and
`window[name]` dynamic lookups, padded with huge `/* random words */` comment noise. The malicious ZIP
is assembled in-browser from two `data=` attributes and handed to a `Blob` + anchor `.click()` download.
Layer 6's PowerShell is a fileless `IEX` cradle: it inflates a base64 blob with
`System.IO.Compression.DeflateStream` (raw DEFLATE — `zlib.decompress(blob, -15)` in Python), and the
inflated script hides every string, including the flag, as a single-byte XOR byte array.

## Solution

The full chain runs offline — nothing is executed, each layer is a Python re-implementation of the
sample's own transform.

Create `solve.py`:

```python
#!/usr/bin/env python3
# Peel the 7-layer HTML-smuggling dropper down to the flag. No stage is executed.
import email, re, base64, zlib, sys

BASE = "files/"

def xor_b64(b64, key):
    """pbmbiaan(): atob then XOR each byte with key[i % len] (key used raw, not decoded)."""
    d = base64.b64decode(b64)
    return bytes(d[i] ^ ord(key[i % len(key)]) for i in range(len(d)))

def resolve_chain(js, target):
    """Rebuild `var X = "lit"` / `var X = OTHER + "lit"` concatenation chains."""
    a = {}
    for m in re.finditer(r'var\s+(\w+)\s*=\s*"([^"]*)"\s*;', js):
        a[m.group(1)] = ('lit', m.group(2), None)
    for m in re.finditer(r'var\s+(\w+)\s*=\s*(\w+)\s*\+\s*"([^"]*)"\s*;', js):
        a[m.group(1)] = ('cat', m.group(3), m.group(2))
    def r(n):
        if n not in a: return ''
        k, lit, base = a[n]
        return lit if k == 'lit' else r(base) + lit
    return r(target)

# Layer 1: .eml -> save the .pdf.html attachment
msg = email.message_from_file(open(BASE + "hypercraft.eml"))
html = next(p.get_payload(decode=True).decode('latin1')
            for p in msg.walk() if (p.get_filename() or '').endswith('.pdf.html'))

# Layer 2: HTML smuggling. ZIP = base64( XOR(atob(main.data), div.data) )
main = re.search(r'id="jzasjnpc"[^>]*data="([^"]*)"', html).group(1)   # payload
key  = re.search(r"id='begjwbvi'[^>]*data=\"([^\"]*)\"", html).group(1)  # raw XOR key
zipbytes = base64.b64decode(xor_b64(main, key))
open(BASE + "hypercraft_plans.zip", "wb").write(zipbytes)

# Layer 3: unzip the .pdf.js manually (unzip -P hackthebox), then read it
js = open(BASE + "[TOP SECRET] Arodorian Hypercraft.pdf.js", encoding='latin1').read()

# Layer 4: strip 's'/'V' noise from 4 concatenated chunks, hex-decode pairs -> eval'd stage
longs = [l for l in re.findall(r'"([^"]+)"', js) if len(l) > 50][:4]
hexstr = ''.join(longs).replace('s', '').replace('V', '')
stage3 = ''.join(chr(int(hexstr[i:i+2], 16)) for i in range(0, len(hexstr), 2))

# Layer 5: rebuild bxmanhtn via the var-concat chain, base64, split on '!'
bx = resolve_chain(stage3, 'bxmanhtn')
ps = base64.b64decode(bx + '=' * (-len(bx) % 4)).decode('latin1').split('!')[2]

# Layer 6: PowerShell inflates a raw-deflate base64 blob
b = re.search(r"FromBase64String\(''([A-Za-z0-9+/=]+)''\)", ps).group(1)
inner = zlib.decompress(base64.b64decode(b), -15).decode('latin1')

# Layer 7: every hidden string is single-byte XOR: UYcxq(byte[], key)
for arr, k in re.findall(r'@\(((?:\s*0x[0-9a-fA-F]+\s*,?)+)\)\)\s*(\d+)', inner):
    by = [int(x, 16) for x in re.findall(r'0x[0-9a-fA-F]+', arr)]
    s = ''.join(chr(x ^ int(k)) for x in by)
    if 'HTB{' in s:
        print(s)
        sys.exit(0)
```

Running it prints the flag:

```console
$ python3 solve.py
HTB{...}
```

The sibling layer-7 XOR arrays decode to the dropper's real intent — the C2 URL
`http://stolenplans.htb/r/`, a `.vbs` persistence dropper written into
`~/AppData/Local/Microsoft/Windows/PowerShell/`, and an `iex (iwr -useb ...)` download-cradle.

## Why it worked

Obfuscation is not encryption. Each layer here is a bijective, keyless-or-known-key transform —
base64, a XOR whose key sits in the same document, a hex encoding with junk characters, a `var`
concat chain, raw DEFLATE, single-byte XOR. Because nothing depends on a secret you don't already
have, the whole stack peels deterministically without ever running attacker code.

Two gotchas make or break the static approach. First, **resolve the JavaScript `var`-concat chain
programmatically** (regex `var x="lit"` plus `var x=y+"lit"`, then recurse) — a naive "grab every
string literal" pulls in a decoy alphabet string and misaligns the base64, corrupting everything
downstream. Second, the PowerShell's backtick-splitting (`` UYc`xq ``, `` As`Cii ``) and
format-operator obfuscation (`"{1}{0}"-f 'b','a'`) are cosmetic — strip the backticks and reorder
the format args and the cmdlet names read plainly. And the challenge name is the hint: *Hypercraft*,
*lots of layers*.

## Fix / defense

- Block or alert on double-extension attachments (`*.pdf.html`, `*.pdf.js`) at the mail gateway.
- Constrain PowerShell with **Constrained Language Mode**; ScriptBlock logging (event 4104) plus AMSI
  catch the fileless `IEX` / `FromBase64String` / `DeflateStream` cradle even when the payload never
  touches disk.
- Use ASR rules to block `mshta`/`wscript` spawning `powershell`, and egress-filter unknown C2 hosts
  like `stolenplans.htb`.
