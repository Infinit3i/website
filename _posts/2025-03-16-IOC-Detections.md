---
title: "IOC-Detections — Threat Hunting & IOCs Collection"
date: 2025-03-16 10:00:00 -0500
categories: [Project, GitHub]
tags: [ioc detections, threat hunting, malware, soc analysis, yara, suricata, sigma, python, indicators of compromise, defanged iocs, infosec research, malware family intel, detection engineering, blue team, threat intel, security analytics]
image:
  path: https://github.com/Infinit3i/Custom-Detections/raw/579a4a5d0281b99bcd3311679cabb2aa1d109e6a/Images/f8df6cf748cc3cf7c05ab18e798b3e91.jpg
---

## [IOC-Detections](https://github.com/Infinit3i/IOC-Detections) — Threat Hunting & IOCs Collection

**IOC-Detections** is a curated repository of Indicators of Compromise (IOCs), detection logic, and investigative notes assembled through active research on emerging threats, malware families, and vulnerability disclosures. The goal of this collection is to document *what was found*, *how it was researched*, and provide defenders with a starting point for detection, hunting, and analysis. The repo consolidates defanged IOCs and detection artifacts in formats like **YARA**, **Suricata**, and **Sigma**, organized for readability and reuse. :contentReference[oaicite:0]{index=0}

Beyond raw IOCs, the project includes **SOC alerts**, **threat hunt artifacts**, and contextual research on malware families that have been observed in real environments. This situates each IOC within its operational context — not just as a string of hashes or domains, but as evidence of adversary tradecraft, beaconing behavior, or post-exploitation activity. :contentReference[oaicite:1]{index=1}

The repositories’ contents are intentionally **defanged** for safety, meaning all malicious elements are inert and safe for review. These artifacts are useful for defenders when building detections, validating hunts, or cross-referencing adversary behaviors across families such as Agent Tesla, Vidar, Emotet, njRAT, and others. :contentReference[oaicite:2]{index=2}

This collection was developed collaboratively with **deej1721** and others in the community, emphasizing practical detection engineering and shared knowledge. As with all open research, these artifacts should be validated in your environment before operational use.
