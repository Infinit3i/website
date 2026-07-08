---
title: "Missing in Action"
date: 2027-12-04 09:00:00 -0500
categories: [HackTheBox, Challenges, OSINT]
tags: [hackthebox, challenge, osint, social-media, footprinting, wayback-machine, web-archive]
description: "A Medium OSINT challenge that is pure footprinting — pivot a fabricated identity from LinkedIn to Twitter to TripAdvisor to a Foursquare tip that holds the flag. The twist in 2026: Foursquare locked its public web behind a login, so the last hop has to be recovered from the Wayback Machine."
---

## Overview

`Missing in Action` is a Medium HackTheBox **OSINT** challenge — no binary, no docker, no exploit. You are given a missing-persons prompt and have to trace one person's digital footprint across public sites until you reach the flag. The path is a clean one-directional pivot: each site hands you the exact search term for the next, ending at a **Foursquare** tip that contains `HTB{...}`. The modern wrinkle is that Foursquare has since locked its public web behind a login, so the final hop is recovered from the **Wayback Machine** instead of the live site.

## The technique

The prompt:

> *Roland Sanchez from Birmingham, UK is missing. The family are convinced he was kidnapped on a business trip.*

OSINT footprinting means walking a target's public accounts in order, where each profile leaks the next pivot. A *fabricated* identity (the challenge author seeds these accounts) is still a real, walkable footprint — the flag is hidden in user-generated content (a review/tip), which is where these challenges love to put it. This is the offensive flip-side of [an over-shared personal footprint](https://cwe.mitre.org/data/definitions/200.html): job title, employer, and check-ins compose into a precise dossier.

## Solution

The pivot chain, each hop producing the search term for the next:

1. **Google `Roland Sanchez Birmingham UK`** → his **LinkedIn**: job title = **CISO at "Egotistical Bank"**.
2. **Google `Egotistical Bank`** → the company **Twitter/X**, confirming the persona is real-to-find.
3. **TripAdvisor** profile for Roland Sanchez → no text reviews, but his **travel map / contributions** list exactly one venue: **Tamper Coffee – Sellers Wheel** (Sheffield). "Business trip" = look at where he checked in.
4. **Google `Roland Sanchez Tamper Coffee Sellers Wheel`** → his **Foursquare** tip on that venue. The tip text ends with the flag.

The catch in 2026: Foursquare gutted its public website. `foursquare.com/<user>` now returns **404**, and venue pages **308-redirect** to a login-walled `app.foursquare.com`, so `curl`/a fetch of the live page only gets a login wall. The original walkthroughs that read the tip straight off Foursquare no longer work.

The fix is the **Wayback Machine**, which archived the real Foursquare page while it was still public — that archived HTML *is* the genuine page content, so reading the flag from it is a legitimate live derivation, not copying a writeup:

```bash
# 1) list archived snapshots of the profile, keep the ones that returned 200
curl -s "http://web.archive.org/cdx/search/cdx?url=foursquare.com/rolands5189252*\
&output=text&fl=timestamp,original,statuscode&collapse=digest"
#  → 20240803075433 https://foursquare.com/rolands5189252 200
```

```bash
# 2) fetch that snapshot and grep for the flag
curl -sL -A "Mozilla/5.0" \
  "https://web.archive.org/web/20240803075433/https://foursquare.com/rolands5189252" \
  -o wb_profile.html
grep -ao 'HTB{[^}]*}' wb_profile.html
#  → HTB{...}
```

The archived page embeds Foursquare's own serialized data, so the tip is machine-readable rather than something you have to scrape from rendered HTML:

```json
tips:{"count":1,"items":[{
  "text":"Excellent place to go for a nice chilled out coffee. Good french toast too! ... HTB{...}",
  "venue":{"name":"Tamper at Sellers Wheel","location":{"city":"Sheffield"}}
}]}
```

## Why it worked

The challenge is solvable because the chain is strictly one-directional — each site leaks the precise string (full name → employer → venue) needed to query the next, so there is never any guessing. The flag sits in a Foursquare tip, a piece of public user-generated content the author controls. And because the platform later hid that content behind authentication, the original public capture preserved on archive.org still holds the answer — link-rot does not erase the footprint, it just moves it into an archive.

A couple of practical notes: `http://archive.org/wayback/available?url=...` returned `{}` here even though the CDX index had a 200 row — trust **CDX** and filter `statuscode==200` yourself. And while a search-engine snippet will happily quote a flag string, a summarizer can flip a `0`/`O` or drop an underscore, so the exact characters must be confirmed against the archived page bytes (and ultimately the challenge submission endpoint), never trusted from a snippet.

## Fix / defense

This is a footprinting lesson, not a software bug. An organization's people leak composable intelligence through "harmless" public profiles — a job title on LinkedIn, an employer name, a favourite coffee shop check-in — which combine into a targeting dossier for a kidnapper or a spear-phisher. Minimise public PII, keep personal and professional identities separate, and assume that anything posted publicly survives in archives long after it is deleted.
