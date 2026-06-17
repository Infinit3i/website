---
title: "Don't Overreact"
date: 2026-09-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Mobile]
tags: [hackthebox, challenge, mobile, react-native, android, apk, hardcoded-secret, base64]
description: "A Very Easy Android challenge that hides its flag in plain sight — a React Native release APK ships all of its JavaScript inside index.android.bundle, and the flag is a base64 string sitting in a config object at the end of that bundle."
---

## Overview

`Don't Overreact` is a Very Easy HackTheBox **Mobile** challenge: a single `app-release.apk`, no live target. The name and the prompt ("some web developers wrote this fancy new app") are the hint — *web developers writing a mobile app* means **React Native**, i.e. JavaScript bundled inside the APK. The flag is hard-coded in that bundle. The lesson is the title: don't *over*-react — no Frida, no emulator, just read the shipped client code.

## The technique

A React Native release APK bundles every line of app JavaScript into `assets/index.android.bundle`. That bundle comes in two flavors:

- **Plain minified JS** — `file` reports "React Native minified JavaScript, ASCII text". You can `grep`/`strings` it directly.
- **Hermes bytecode** — a binary Hermes magic header; needs `hbctool` or `hermes-dec` to disassemble first.

This one is plain JS. Anything shipped inside the package is readable by anyone holding the APK, so a secret stored there has zero confidentiality — a [cleartext storage of sensitive information](https://cwe.mitre.org/data/definitions/312.html) / [use of hard-coded credentials](https://cwe.mitre.org/data/definitions/798.html) weakness.

## Solution

Confirm React Native by the bundled native libraries:

```bash
unzip -l app-release.apk | grep -E 'libhermes|libreactnative'
```

Pull out the bundle and check its type:

```bash
unzip -p app-release.apk assets/index.android.bundle > bundle.js
file bundle.js   # -> React Native minified JavaScript, ASCII text
```

The bundle is a flat list of `__d(function(g,r,i,a,m,e,d){...}, <moduleId>, [deps])` module definitions. **App code lives at the end (the highest module IDs); the React Native framework is everything before it.** The final app module hard-codes a config object:

```js
__d(function(g,r,i,a,m,e,d){
  e.myConfig = void 0;
  var t = { importantData:"baNaNa".toLowerCase(),
            apiUrl:'https://www.hackthebox.eu/',
            debug:'SFRCe...base64...' };
  e.myConfig = t;
}, 400, []);
```

The `debug` field is base64. A four-line script regexes it out and decodes it:

Create `solve.py`:

```python
#!/usr/bin/env python3
import re, base64, sys
bundle = sys.argv[1] if len(sys.argv) > 1 else "bundle.js"
data = open(bundle, "r", errors="ignore").read()
b64 = re.search(r"debug:'([A-Za-z0-9+/=]+)'", data).group(1)
print(base64.b64decode(b64).decode())
```

```bash
python3 solve.py bundle.js
# -> HTB{...}
```

Or as a one-liner straight from the APK:

```bash
unzip -p app-release.apk assets/index.android.bundle | grep -oE "debug:'[A-Za-z0-9+/=]+'" | sed "s/debug:'//;s/'//" | base64 -d
```

## Why it worked

React Native compiles the entire application into a single JavaScript bundle that ships inside the APK. Storing a secret in that bundle puts it in the hands of every user who installs the app — it is client-side data, fully recoverable by anyone with the package. base64 is encoding, not encryption, so the "debug" value is plaintext to anyone who looks.

## Fix / defense

- **Never ship secrets in the client bundle.** Secrets belong server-side behind authenticated APIs; the client requests them at runtime, it doesn't carry them.
- Strip debug/dev config from release builds.
- Treat Hermes bytecode as obfuscation, not protection — it raises the bar slightly but is fully reversible. It is never a secret store.
- Rotate any key or token that has ever shipped inside a client artifact.
