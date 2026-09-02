---
title: Services
icon: fas fa-shield-halved
order: 0
---

**Infinit3i** is the trading name of Matthew Iverson, sole proprietor, based in
Spring Hill, Florida, United States. I hunt security bugs in websites and web
applications, working remotely for the owner of the site.

This is a professional service delivered electronically. **No physical goods are
sold or shipped, and no software, tooling, or exploit code is sold.**

## Bug Bounty Work on Websites

I find and report security vulnerabilities in websites and web applications you
own or are authorized to have tested. Typical findings include cross-site
scripting, access control and authorization flaws, injection bugs, insecure
direct object references, authentication and session weaknesses, and business
logic abuse.

For each valid finding you receive a written report containing:

- a plain description of the bug and the affected endpoint;
- reproduction steps detailed enough for your developers to confirm it;
- a severity rating mapped to CVSS;
- concrete remediation guidance.

Scope is agreed in writing before any testing begins. Nothing outside that
written scope is touched.

## How Engagements Work

1. **Scoping call** — we define exactly which domains, applications, and
   endpoints are in scope, and what is explicitly out of scope.
2. **Written contract and authorization to test**, signed by both parties before
   any testing starts.
3. **Testing window**, with status updates and immediate disclosure of critical
   findings rather than holding them until the end.
4. **Written report** delivered electronically covering every valid finding.
5. **Remediation support** and an optional retest of fixed issues.

## Pricing and Payment

**You pay per valid finding. Nothing else.** There is no upfront fee, no hourly
rate, no retainer, no subscription, and no recurring charge. If I find nothing
valid in your scope, you owe nothing.

The fee for each severity tier — critical, high, medium, low — is set out in a
rate card in the signed contract before any testing begins, so you know the price
of every possible outcome in advance.

### What Counts as a Valid Finding

A finding is billable only when all of the following are true:

- it is reproducible on a target inside the written scope;
- it has a real security impact, rated against CVSS — not an informational note
  or a general hardening suggestion;
- it is not a duplicate of an issue you already knew about, already had reported,
  or that appears more than once in my own report;
- it is not an issue you have already documented as an accepted risk.

Duplicates, out-of-scope findings, informational notes, and anything you can show
is not reproducible are **not billed**.

### How Billing Runs

1. Findings are reported to you as they are confirmed, not held back to the end.
2. You get **10 business days** from the final report to triage each finding and
   accept it or tell me in writing why it is not valid.
3. One invoice is issued after triage, covering accepted findings only, at the
   contracted severity rate.
4. Payment is due per the terms in the signed contract, in United States dollars.

Card payments are processed by Stripe; card statements show charges from
**INFINIT3I**. Severity disagreements are settled against the CVSS vector in the
report before the invoice is issued.

Full terms: [Terms of Service]({{ '/terms/' | relative_url }}) ·
[Refund, Cancellation & Dispute Policy]({{ '/refunds/' | relative_url }})

> No testing is ever performed without written permission from the owner of the
> target website. I do not sell offensive tooling or exploit code, and I do not
> test systems outside the agreed written scope.
{: .prompt-info }

## Contact

See the [Contact]({{ '/contact/' | relative_url }}) page to start a conversation
about an engagement.
