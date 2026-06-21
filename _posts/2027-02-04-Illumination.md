---
title: "Illumination"
date: 2027-02-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, git, secrets, version-control, base64]
description: "An Easy forensics challenge that hands you a Node.js bot still carrying its .git directory. The token was 'removed' in a later commit — but deleting a secret from the working tree never erases it from git history. Recover the parent blob and decode."
---

## Overview

Illumination is an Easy HackTheBox **Forensics** challenge. You download a zip
containing a small Node.js Discord bot — and crucially, its `.git` directory
came along for the ride. The working files look clean, but git history is not:
an API token was committed, then "removed" in a follow-up commit. The whole
challenge is recovering that token, because deleting a secret from the working
tree does **not** purge it from history.

## The technique

This is [sensitive information left in version-control history](https://cwe.mitre.org/data/definitions/540.html)
([CWE-540](https://cwe.mitre.org/data/definitions/540.html)). Git is
content-addressed and append-only — every committed blob lives in the object
store forever. A commit that *deletes* a secret only moves the branch tip; the
previous version of the file is still one `git show` away. Better still, the
developer left a signpost: the commit message literally says they removed the
token. That points straight at the commit *before* it.

## Solution

First, look at what's there. `config.json` has been scrubbed and a `username`
field is suspiciously base64:

```bash
cat files/Illumination.JS/config.json
# "token": "Replace me with token when in use! Security Risk!"
# "username": "UmVkIEhlcnJpbmcsIHJlYWQgdGhlIEpTIGNhcmVmdWxseQ=="
```

That `username` decodes to `Red Herring, read the JS carefully` — a decoy. The
real lead is in the history:

```bash
cd files/Illumination.JS
git log --all --oneline
# edc5aab Added some whitespace for readability!
# 47241a4 Thanks to contributors, I removed the unique token as it was a security risk.
# ddc606f Added some more comments for the lovely contributors!
# 335d6cf Moving to Git, first time using it. First Commit!
```

Commit `47241a4` removed the token — so its parent `ddc606f` still has it.
Print that file as it existed before the scrub, and decode the base64 token:

```bash
git show ddc606f:config.json
# "token": "SFRCe3YzcnNpMG5fYzBudHIwbF9hbV9JX3JpZ2h0P30="
echo 'SFRCe3YzcnNpMG5fYzBudHIwbF9hbV9JX3JpZ2h0P30=' | base64 -d
```

The same recovery as a self-contained script:

Create `solve.py`:

```python
#!/usr/bin/env python3
import base64, subprocess, json, os
repo  = os.path.expanduser("~/htb/chal-illumination/files/Illumination.JS")
blob  = subprocess.check_output(["git", "-C", repo, "show", "ddc606f:config.json"]).decode()
token = json.loads(blob)["token"]
print(base64.b64decode(token).decode())
```

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

A delete-commit changes only what the branch tip points to — git never rewrites
or removes the older blobs. The token committed in the first place is still
recoverable from the parent of the "removal" commit, and the commit message
advertised exactly where to look. `git log -p -S<term>` (the pickaxe) finds
every commit that touched a given string when the message *isn't* so helpful,
and tools like gitleaks/trufflehog automate scanning all blobs for secrets.

## Fix / defense

- Never commit secrets — load them from environment variables or a secret store
  (`const token = process.env.BOT_TOKEN`).
- A delete-commit is not a fix. Purge the value from history with
  `git filter-repo` / BFG, **and rotate the secret** — assume it is compromised
  the moment it ever touched a repo.
- Add pre-commit secret scanning (gitleaks) and block `/.git` on web servers —
  an exposed `.git` directory lets anyone `git-dumper` it and replay this exact
  recovery against your production credentials.
