# Known findings

Every CVE the scanner currently reports, why it hasn't been fixed, and what
would fix it.

**There are no `.trivyignore` files in this repo, and adding one is a policy
change rather than a maintenance decision.** Nothing is suppressed. Every
finding below appears in full in `make scan` output on every run. The gate
blocks a finding that is in CISA KEV, has EPSS above 0.1, has had a fix for at
least 30 days, or has not been reviewed in 90 days. Missing evidence blocks.

## Why a register instead of suppression

A suppression and a register look similar and behave in opposite ways.

A `.trivyignore` entry deletes the finding from the output. What's left is a
green tick, and the reasoning survives only in a comment nobody reads next to a
CVE nobody sees. It ages badly in a specific way: the justification was written
about one version of one image, and it keeps applying silently after the image,
the package, or the exploitability have all changed. The finding doesn't come
back when the reason stops being true.

A register does the opposite. The finding stays in the report and this file
records what's known about it. A finding can pass only while all four risk
conditions above remain clear. The noise is the reminder.

This also keeps the scanner honest as a **black box**. Trivy is imported
tooling; it decides what counts as a finding, and its verdicts change when its
database updates, without anything in this repo changing. Suppressing a CVE-ID
is an assertion about the scanner's output. Recording why the vulnerable code
isn't reachable is an assertion about the image, which is the thing actually
being defended. Only one of those survives a scanner swap. The same argument
applies to imported SAST and DAST gates and is worth writing up separately.

## Format

Each entry states the evidence, not a judgement. "Not exploitable here" with
nothing behind it is the thing this file exists to avoid. The machine-readable
comment under each heading records the last evidence review and the date a fix
first became available, or `none` when no fix exists:

```text
gate: cve=CVE-YYYY-NNNNN reviewed=YYYY-MM-DD fix-available=none
```

Wrap that line in an HTML comment for a real entry, as shown under each CVE
below. Only real CVE entries use the gate comment marker because the parser
treats every marked line as policy input.

---

## hardened-python

15 findings, 5 unique CVEs. None have a fix released by Debian.

### CVE-2026-11940 — `tarfile.extractall()` filter bypass

<!-- gate: cve=CVE-2026-11940 reviewed=2026-08-23 fix-available=none -->

**Packages:** `libpython3.13-minimal`, `libpython3.13-stdlib`,
`python3.13-minimal`, `python3.13-venv` (4 findings, one CVE)
**Fix:** none released

A crafted archive can bypass the `data` and `tar` extraction filters via a
hardlink referencing a symlink stored deeper than the hardlink itself.

**Why it isn't urgent here:** the reference application (`app/main.py`) is an
HTTP server that never imports `tarfile`. It is reachable only if an application
built on this image extracts archives it did not create.

**Important for anyone deriving from this image:** that condition is about the
*application*, not the image. If yours extracts uploaded or fetched tarballs,
this finding applies to you at full severity and this entry does not transfer.
This is precisely why it isn't suppressed — a suppression would have been
inherited silently.

**Resolved by:** a Debian fix for `python3.13`, or a base image rebuild carrying
it.

### CVE-2026-15308 — `html.parser` CPU denial of service

<!-- gate: cve=CVE-2026-15308 reviewed=2026-08-23 fix-available=none -->

**Packages:** same four
**Fix:** none released

`html.parser.HTMLParser` can be driven into pathological CPU use by repeated
unterminated markup declarations.

**Why it isn't urgent here:** the reference application does not parse HTML. As
above, this is a property of the application, not the image.

**Resolved by:** a Debian fix, or an application that doesn't feed untrusted
HTML to the stdlib parser.

### CVE-2026-7210 — `xml.parsers.expat` hash flooding

<!-- gate: cve=CVE-2026-7210 reviewed=2026-08-23 fix-available=none -->

**Packages:** same four
**Fix:** none released

`xml.parsers.expat` and `xml.etree.ElementTree` seed Expat's hash-flooding
protection with insufficient entropy, so a crafted document can trigger
collisions.

**Why it isn't urgent here:** the reference application parses no XML.

**Resolved by:** libexpat 2.8.0 or later reaching the base image. Applications
that must parse untrusted XML should use `defusedxml` regardless of this CVE.

### CVE-2025-69720 — ncurses stack overflow in `infocmp`

<!-- gate: cve=CVE-2025-69720 reviewed=2026-08-23 fix-available=none -->

**Packages:** `libncursesw6`, `libtinfo6` (2 findings)
**Fix:** none released

**Why it isn't urgent here, with evidence:** the vulnerability is a stack-based
buffer overflow in `analyze_string` in `progs/infocmp.c` — that is, in the
`infocmp` *program*, not in the shared library that gets linked. This image
ships no such program:

```
$ docker run --rm --entrypoint /usr/bin/python3.13 hardened-python:latest \
    -c "import os; print([p for p in ['/usr/bin/infocmp','/usr/bin/tic','/usr/bin/tput'] if os.path.exists(p)])"
[]
```

The libraries are present because Python links them for `readline`. The code
containing the defect is not in the image at all. Trivy reports at package
granularity and cannot see that distinction, which is a good illustration of why
scanner output is evidence rather than a verdict.

This one previously *was* suppressed, with the weaker reasoning "this container
runs a headless HTTP server with no terminal interaction". That was a guess
about reachability. The binary being absent is a fact, and it's checkable.

**Resolved by:** a Debian fix for ncurses, or dropping the `readline` dependency.

### CVE-2026-14456 — OpenSSL QUIC listener memory exhaustion

<!-- gate: cve=CVE-2026-14456 reviewed=2026-08-23 fix-available=none -->

**Package:** `libssl3t64` (also present in hardened-node)
**Fix:** none released; Debian marks the stable fix as postponed

An unauthenticated peer can exhaust memory in an OpenSSL QUIC server by sending
valid Initial packets for many unknown connection IDs faster than the
application accepts them.

**Why it isn't urgent here:** neither reference application is a QUIC server.
The Python image runs a stdlib HTTP server and the Node image runs Express over
HTTP. Neither creates an OpenSSL QUIC listener or passes packets to that API.
As of the 2026-08-23 review, it is absent from CISA KEV and EPSS is 0.00465.

**Resolved by:** a Debian/OpenSSL fix, or an application that does not expose
the affected QUIC server path. Any derived image that adds QUIC must treat this
as fully reachable and cannot inherit this assessment.

---

## hardened-node

1 finding, 1 unique CVE: CVE-2026-14456, documented above because it is shared
with hardened-python. The Node 24 migration removed CVE-2026-45447, whose fix
had been available since 2026-06-09 but never reached the Node 20 distroless
image.

---

## hardened-nginx, hardened-go

No findings at CRITICAL or HIGH.
