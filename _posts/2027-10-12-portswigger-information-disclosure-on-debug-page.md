---
layout: post
title: "PortSwigger: Information Disclosure on Debug Page"
date: 2027-10-12 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, InformationDisclosure]
tags: [portswigger, information-disclosure, debug-page, phpinfo, secret-key, recon, cwe-200]
---

A debug page nobody linked is still a debug page everybody can reach. This lab leaks the application's `SECRET_KEY` through a `phpinfo()` page that was left in production and only "hidden" by commenting out the link to it. It's a clean example of [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information to an Unauthorized Actor).

## Overview

The shop looks ordinary — a product catalogue, nothing obviously sensitive linked in the UI. The goal is to find the leaked `SECRET_KEY` and submit it.

## Reading the source

The trick to information disclosure is to read what the browser *renders* and what the browser *receives* — they aren't the same. The page source carries a developer's leftover comment:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/' | grep -iE '<!--|phpinfo|cgi-bin'
```

```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```

The link is commented out, so it never appears on the page — but the endpoint it points at is still served.

## The debug page leaks the environment

`phpinfo()` prints PHP's entire configuration *and the process environment*. Fetch it and grep for the secret:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/cgi-bin/phpinfo.php' \
  | grep -oiE 'SECRET_KEY.{0,120}' | sed -E 's/<[^>]+>/ /g'
```

```
SECRET_KEY   eeosm372svpeycgkjy9p1gr659jt85r5
```

The app stored its `SECRET_KEY` in an environment variable, and `phpinfo()` dumps every environment variable to anyone who loads the page.

## Solving

Submit the key:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/submitSolution' \
  --data-urlencode 'answer=eeosm372svpeycgkjy9p1gr659jt85r5'
# {"correct":true}
```

The lab banner flips to **Solved**.

## Why it worked

Two mistakes stack:

1. **"Unlinked" was mistaken for "protected."** The debug link was commented out, not removed. Commenting out hides a link from a casual browser, but the endpoint is still live — anyone reading source or fuzzing `/cgi-bin/` finds it. There is no authentication on the page.
2. **A secret was readable from `phpinfo()`.** Because the app kept `SECRET_KEY` in its environment, and `phpinfo()` prints the environment, a single info-leak exposed it. In the real world that same dump would hand over database passwords, API keys, and cloud credentials.

## The fix

- Remove `phpinfo.php` and every debug endpoint from production builds — don't rely on an unlinked or unguessable URL as the only protection.
- Delete debug links from source; commenting out is not deleting.
- Keep secrets out of the environment of web-facing processes (use a secrets manager), so one info-leak doesn't expose everything.
- Rotate any secret that has ever appeared in a `phpinfo` or debug dump — assume it's burned.

## Takeaway

When you recon an app, always read the raw HTML and chase comments, not just the rendered page. Then try the obvious debug endpoints — `/cgi-bin/phpinfo.php`, `/info.php`, `/phpinfo.php`. The same class shows up far beyond PHP: Laravel's Whoops/Ignition page with `APP_DEBUG=true`, Flask/Werkzeug's debug console, Symfony's `_profiler`, Django's `DEBUG=True` settings dump. Every one of them turns "left debug on in prod" into "here are my secrets."
