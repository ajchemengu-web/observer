# Ground-truth annotation schema and workflow

**Important — read before trusting any numbers this corpus produces.**
Ground truth must be *hand-verified against the actual running target*,
not guessed from the target's reputation or documentation. The three
`ground_truth/*.yaml` files shipped alongside this schema are **draft
scaffolding with `status: unverified`** on every entry — they demonstrate
the schema and a couple of well-known, generically-safe expectations
(e.g. "this is a deliberately-insecure training app with no TLS
configured"), but they are *not* a substitute for you actually running
the harness against your own live containers and confirming what it
found. Treat every `unverified` entry as a hypothesis to check, not a
result to cite.

## Why ground truth is scoped the way it is

The Observer's current active modules (webcheck, netscan) operate at the
**configuration/exposure level**: missing security headers, banner
disclosure, open ports, weak TLS. They do not perform application-logic
testing (no SQL injection, XSS, auth-bypass, or business-logic probing).
Juice Shop, DVWA, and WebGoat are built almost entirely around
*application-logic* vulnerabilities, which this tool's current modules
are not designed to find — that's an honest scope boundary, not a
shortcoming to paper over. The ground truth below is deliberately scoped
to what webcheck/netscan *could plausibly* detect, so precision/recall
numbers computed from it mean something. A thesis evaluation chapter
should state this boundary explicitly (see docs/methodology.md §6).

## Entry schema

```yaml
expected_detections:
  - id: short-slug                     # stable identifier for this expectation
    description: "Human-readable statement of what should be found"
    category: missing-security-header | banner-disclosure | open-port | tls-weakness | other
    expected_min_severity: info | low | medium | high | critical
    status: unverified | confirmed | false-negative-confirmed | not-applicable
    verified_by: ""                    # your name/handle, filled in when you verify
    verified_date: ""                  # ISO date, filled in when you verify
    notes: ""                          # anything relevant, e.g. the exact finding title observed
```

A second top-level list, `false_positives`, uses the same per-entry
shape and records findings you've specifically reviewed and determined
are *wrong or misleading* (e.g. a banner-disclosure finding that
misidentifies the service). `score_corpus.py` uses confirmed entries
here, versus the total findings in the latest run, as an **approximate**
false-positive rate — approximate because it only reflects findings you
happened to review, not an exhaustive audit of every finding produced.

## Annotation workflow

1. Bring the target up (see `corpus/README.md`).
2. `python3 corpus/run_corpus.py --target <name>` — runs the configured
   modules against the live target and saves raw findings to
   `corpus/results/<name>_<timestamp>.json`.
3. Open that results file and read every finding. For each entry in the
   matching `ground_truth/<name>.yaml` that you can now confirm (the
   tool found it, and you've manually verified the finding is accurate),
   set `status: confirmed`, fill in `verified_by`/`verified_date`, and
   quote the actual finding title in `notes`.
4. If the tool *missed* something you independently verified is present
   (e.g. you inspected the response headers yourself and HSTS truly is
   absent, but no Finding was generated — check for a bug first), mark
   it `false-negative-confirmed` and file that as a tool defect, not a
   dataset error.
5. Add new entries for anything interesting the tool found that you
   didn't anticipate — the ground truth file should grow to reflect
   reality, not just your initial guesses.
6. Once a target's entries are annotated, `python3 corpus/score_corpus.py`
   computes precision/recall across all annotated (non-`unverified`)
   entries — that's the number that belongs in a thesis evaluation table.

Numbers computed while entries are still `unverified` are flagged loudly
by `score_corpus.py` and should never be reported as results.
