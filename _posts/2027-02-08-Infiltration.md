---
title: "Infiltration"
date: 2027-02-08 09:00:00 -0500
categories: [HackTheBox, Challenges, OSINT]
tags: [hackthebox, challenge, osint, social-media, linkedin, instagram, image-analysis]
description: "An Easy OSINT challenge where the flag is printed inside a photo, not in any text or metadata. The whole puzzle is the pivot: company name to LinkedIn employee to their Instagram to a photo of a work badge whose barcode hides the flag."
---

## Overview

Infiltration is an Easy OSINT challenge for the fictional "Evil Corp LLC". There is no download and no instance to connect to — the entire solve happens out in the open web. The path is a classic recon pivot: a company name leads to a LinkedIn page, the LinkedIn page names an employee, the employee's personal Instagram leaks a photo of their work badge, and the flag is printed on that badge under the barcode.

## The technique

OSINT flags are *found, not exploited*. The skill being tested is **pivoting from an organisation to a specific human to something they accidentally exposed**. Two traps make it interesting:

- A **decoy** is planted early so impatient solvers stop too soon.
- The real flag lives **inside an image**, so grepping page text, metadata, or `strings` finds nothing — you have to actually read the photo.

## Solution

1. Google the company:

   ```bash
   # search engine query
   evil corp llc
   ```

   The top hit is the **LinkedIn** company page for "Evil Corp LLC". Its description contains a flag-shaped string:

   ```bash
   echo 'WW91IGNhbiBkbyB0aGlzLCBrZWVwIGdvaW5nISEh' | base64 -d
   # -> You can do this, keep going!!!
   ```

   That is a **decoy** — keep pivoting.

2. From the LinkedIn page, move to the **employees**. One is **Eryn McMahon**. Her personal **Instagram** (`@eryn_mcmahon12`) bio echoes the same employer/role ("Relational Factors Analyst working at Evil Corp LLC") — that confirms it is the same person.

3. Her post *"Hard at work on my first day for @EvilCorpLLC"* shows a laptop and, on a lanyard, her **work badge**. Below the badge's barcode, in flag format, is the answer.

4. Grab the photo **live, no Instagram login**. The logged-out *embed* hides the image, but fetching the post page itself renders it and exposes the full **signed** `cdninstagram.com` `.jpg` URL (1080×1080) — keep the whole query string or a stripped URL returns `Bad URL hash`:

   ```bash
   UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120 Safari/537.36'
   curl -s -A "$UA" "$SIGNED_CDN_JPG_URL" -o badge.jpg
   ```

   The text is tiny and the badge is tilted ~13°, so deskew and upscale the region before reading. A fixed horizontal crop only catches `HTB{` because the line slopes up-right — rotate to flatten it first:

   ```bash
   magick badge.jpg -crop 220x70+24+812 +repage -rotate 13 -resize 600% -unsharp 0x1 flag.png
   ```

   Iterate the rotation angle and crop box until the line under the barcode reads cleanly (fall back to `tesseract deskew.png -` if eyeballing fails). The flag comes straight off the badge:

   ```text
   HTB{...}
   ```

   Flag value redacted.

## Why it worked

The badge carried a sensitive string in plaintext and was photographed and posted to a public, employer-linked social account. The LinkedIn → Instagram pivot is only possible because the personal profile advertises the employer and exact role, tying the human back to the org. Nothing was "hacked" — the disclosure was self-inflicted.

## Fix / defense

- Don't print secrets on physical badges, and treat any photo that shows credentials, badges, or screens as sensitive — review before posting.
- Minimise the public link between personal social accounts and an employer/role; awareness training shrinks the org-to-human pivot that makes this kind of targeting trivial.
- Reading text hidden in images is a reusable OSINT/forensics primitive: crop the region, `-rotate` to flatten angled text, then upscale + sharpen, and OCR if needed.
