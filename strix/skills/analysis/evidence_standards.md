---
name: evidence_standards
description: Universal evidence bar for every vulnerability report — irrefutable PoC plus claim-matching screenshots; curl over Python; full URLs; SQLi must identify schema objects
---

# Evidence Standards (Universal)

Every vulnerability you file must be **undeniable to a reviewer who was
not in the room**. Claims without matching proof are not findings —
do not file them.

## Irrefutable Evidence Bar

Before `create_vulnerability_report`, you must have **both**:

1. **PoC** — a reproducible exploit the reviewer can run or replay.
2. **Screenshot(s)** — pixel proof that the claimed effect actually
   happened on the target.

A description of what "would happen", a scanner hit, a static trace you
did not execute, or a screenshot of an unrelated page is not enough.

## Screenshots Must Match the Claim

The screenshot is evidence of the **specific unauthorized result**, not
atmosphere. Capture the screen that shows the stolen/modified/leaked
artifact itself.

| Claim | Screenshot must show |
| --- | --- |
| IDOR / broken object auth / BFLA | The unauthorized object's data (other user's PII, order, document, admin record) under the attacker's session |
| Information disclosure / leak | The leaked secret, PII, source, token, or internal data in the response/UI |
| Auth bypass / privilege escalation | The privileged action succeeding or the privileged UI/data under a lower-privilege identity |
| XSS | Payload execution in context (reflected content, stolen cookie/token, or DOM effect) — not just the raw reflection |
| SQLi | Extracted rows / schema objects / database error proving injection, not just a timing delay claim without follow-up |
| SSRF | Response/body/callback proving the internal fetch (metadata body, internal banner, OAST hit) |
| RCE | Command output or side-effect proof (file write, reverse callback, whoami) |
| CSRF / state change | Before/after of the durable state change under the victim context |

Rules:

- Take the screenshot with `agent-browser screenshot`, then `view_image`
  it yourself before filing so you know the pixels match the claim.
- Put the screenshot path and a one-line caption of what it proves into
  `evidence` (e.g. ``screenshot: /workspace/.agent-browser-screenshots/idor-user-2-email.png — attacker session reading victim email``).
- A screenshot of the request builder, a 200 OK with no body, or the
  login page after a failed attempt does **not** prove the claim.

## PoC Format Preferences

Prefer the smallest, most reviewable artifact:

1. **Full URL** when a single GET (or bookmarkable link) reproduces it —
   include scheme, host, path, and every query parameter. No truncated
   hosts, no `...`, no relative paths without the base URL.
2. **`curl` script** for any HTTP request/response PoC (POST, headers,
   cookies, multipart, JSON body). Include method, URL, headers, body,
   and the exact cookie/token values needed (redact only if the user
   asked; otherwise keep them so the PoC runs).
3. **Browser steps + screenshot** for UI-only flows that cannot be
   reduced to curl.
4. **Python (or other) script** only when curl/URL cannot express the
   attack (multi-step crypto, websocket, race, non-HTTP protocol). If
   you reach for Python, say why curl is insufficient in
   `poc_description`.

Do **not** default to Python for ordinary HTTP vulns. Put the runnable
artifact in `poc_script_code` even when it is a URL or a curl block.

## Class-Specific Minimums

**SQL injection** — a timing/boolean oracle alone is incomplete for a
filed High/Critical. Before filing you should identify at least:

- DBMS family when observable
- At least one concrete schema object (database / table / column name)
  retrieved via the injection, **or** an explicit extracted row that
  proves data access

Put those names in `evidence` and `impact`. "Sleep worked" without
schema or data is an `open_proof_gap`, not a finished report.

**IDOR / authz** — name the two principals (attacker id, victim id),
the object id, and show the unauthorized fields in the screenshot /
response excerpt.

**Leakage** — quote the leaked value (or a distinctive prefix) in
`evidence`; the screenshot must show that same value.

## What Goes Where

- `poc_description` — numbered steps only (no large code dumps).
- `poc_script_code` — the runnable PoC: full URL, curl, or (only if
  necessary) a script.
- `evidence` — request/response excerpts **plus** screenshot paths and
  captions that match the claim; for SQLi include table/column names.

If you cannot produce both a PoC and a claim-matching screenshot, do
not file. Leave an `open_proof_gap` in coverage instead.
