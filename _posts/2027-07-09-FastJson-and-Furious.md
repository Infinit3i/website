---
layout: post
title: "FastJson and Furious"
date: 2027-07-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Mobile]
tags: [hackthebox, challenge, mobile, android, fastjson, cve-2022-25845, deserialization, apk, md5, cwe-502]
---

## Overview

FastJson and Furious is an HTB Mobile challenge (Easy) built around an Android APK that uses the FastJSON library (version 1.1.52.android). The vulnerability is [CVE-2022-25845](https://nvd.nist.gov/vuln/detail/CVE-2022-25845) — FastJSON 1.1.x's AutoType feature allows an attacker to deserialize an arbitrary class via the `@type` field. Triggering it with the correct type and field unlocks a flag-generating code path that computes an MD5 hash from the modified JSON input.

**[CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data**

---

## Reverse Engineering the APK

Decompiling `classes2.dex` with androguard reveals three key classes:

### `Flag.setSuccess(boolean)`

```java
// Lhhhkb/ctf/fastjson_and_furious/Flag;
void setSuccess(boolean value) {
    MainActivity.succeed = value;  // sets static boolean flag
}
```

### `MainActivity.calcHash(String input)`

```java
String calcHash(String input) {
    if (!succeed) return "";  // guard
    String POSTFIX = "20240227";  // static field, from class static_values
    String v1 = "\":";            // two-char string: double-quote + colon
    String replacement = POSTFIX + v1;  // "20240227\":"
    String modified = input.replace(v1, replacement);  // append POSTFIX to every JSON key name

    JSONObject obj = JSON.parseObject(modified);  // FastJSON (lenient)
    if (obj.keySet().size() != 2) return "";

    // Sort keys, concatenate key+value for each
    String concat = obj.keySet().stream().sorted()
        .map(k -> k + obj.get(k).toString())
        .collect(Collectors.joining());

    // MD5 of the lowercase concatenation
    MessageDigest md5 = MessageDigest.getInstance("MD5");
    md5.update(concat.toLowerCase().getBytes(), 0, concat.length());
    String hash = new BigInteger(1, md5.digest()).toString(16);
    while (hash.length() < 32) hash = "0" + hash;
    return "HTB{" + hash + "}";
}
```

### `MainActivity.onClick` (button handler)

```java
void onClick(View v) {
    String input = editText.getText().toString();
    JSON.parseObject(input);       // FastJSON deserialization → setSuccess(true)
    String flag = calcHash(input); // flag computation on the SAME string
    if (flag.length() > 0)
        showText.setText("Flag is: " + flag);
}
```

The POSTFIX `"20240227"` comes from the `static_values` encoded array in the DEX class definition — not initialized in `<clinit>`.

---

## The Technique

### Step 1 — Trigger deserialization

FastJSON 1.1.x supports AutoType: when `@type` appears in JSON, it instantiates that Java class and calls setter methods for each remaining field. Supplying:

```json
{"@type":"hhhkb.ctf.fastjson_and_furious.Flag","success":true}
```

calls `Flag.setSuccess(true)` → sets `MainActivity.succeed = true`.

### Step 2 — Key mutation by POSTFIX replacement

`calcHash` is then called with the SAME JSON string. It replaces every `":` (the 2-char sequence `"` + `:`) with `20240227":`, which appends POSTFIX to every JSON key name:

```
{"@type":"...Flag","success":true}
     ↓ replace '":' with '20240227":'
{"@type20240227":"...Flag","success20240227":true}
```

FastJSON parses this as a valid 2-key JSON object: `@type20240227` → `hhhkb.ctf.fastjson_and_furious.Flag`, `success20240227` → `true`.

### Step 3 — MD5 flag computation

Keys sorted alphabetically: `@type20240227`, `success20240227` (`@` < `s`).

Concatenation: `@type20240227hhhkb.ctf.fastjson_and_furious.Flagsuccess20240227true`

MD5 of lowercase → `6ea340daa0bc5c4f79dd152df72f0e9e` → `HTB{6ea340daa0bc5c4f79dd152df72f0e9e}`.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import hashlib

POSTFIX = "20240227"
INPUT = '{"@type":"hhhkb.ctf.fastjson_and_furious.Flag","success":true}'

V1 = '":'
modified = INPUT.replace(V1, POSTFIX + V1)

import json
parsed = json.loads(modified)  # standard parser works; FastJSON AutoType fires on orig
sorted_keys = sorted(parsed.keys())
concat = "".join(k + str(parsed[k]) for k in sorted_keys)
flag = "HTB{" + hashlib.md5(concat.lower().encode()).hexdigest() + "}"
print(f"[+] FLAG: {flag}")
```

```
[+] FLAG: HTB{6ea340daa0bc5c4f79dd152df72f0e9e}
```

---

## Why it worked

FastJSON 1.1.x's AutoType deserializes arbitrary classes — a long-known RCE vector in server contexts. Here it calls `setSuccess(true)` which enables the flag path. The POSTFIX substitution is the unique "proof of understanding" step: the developer hid the flag behind a computation that requires knowing POSTFIX (buried in the APK's `static_values` section) and understanding the exact `":"` → `"POSTFIX":` substitution.

---

## Fix

```java
// 1. Disable AutoType (FastJSON 1.2.70+):
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
// 2. Or upgrade to fastjson ≥ 1.2.83 (CVE-2022-25845 patched)
// 3. Or use a safer JSON library (Jackson, Gson) that does not support @type deserialization
```
