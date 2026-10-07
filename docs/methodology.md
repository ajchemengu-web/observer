# Cross-Module Correlation and Risk-Scoring: Methodology

This document specifies the design of The Observer's correlation engine
(`observer/correlate.py`, `observer/correlation_rules.py`) at the level of
detail needed to evaluate, reproduce, or extend it — intended as source
material for a methodology/design chapter, not end-user documentation.

## 1. Problem statement

Each scanning module (recon, web-app checks, network scan, vulnerability
scan, passive network monitor) independently emits `Finding` objects —
tuples of `(target, module, severity, title, detail)`. Treated in
isolation, these findings understate risk in two ways:

1. **Compounding**: some combinations of individually-moderate findings
   indicate a materially worse overall posture than either finding alone
   (e.g. a reachable, typically-unauthenticated data store is worse when
   the same domain also has a large, likely-unmanaged subdomain surface).
2. **Redundant volume**: a single module reporting many findings of the
   same severity (e.g. ten informational open-port notices) should not,
   by sheer count, outweigh one independently-corroborated serious
   finding from a different module.

The engine's job is to turn a `list[Finding]` for a target into a single
auditable risk score and tier, with every point traceable to either a
documented severity weight or a named rule with a stated rationale — no
opaque learned model, by design, so every score is explainable to a
human analyst.

## 2. Severity weights

```
INFO = 0.5   LOW = 2.0   MEDIUM = 5.0   HIGH = 9.0   CRITICAL = 15.0
```

This is an original, roughly-geometric mapping (not a reproduction of
CVSS, and no equivalence to CVSS is claimed) expressing the intuition
that impact/exploitability grows super-linearly across severity bands.

## 3. Per-module aggregation: decay-weighted, not summed

**Why not a naive sum.** Summing weights linearly lets volume alone
dominate: ten LOW findings (weight 2.0 each) from one module would
outweigh a single HIGH finding (9.0) from another, which is not the
intended semantics — repeated low-severity output from one source is
weaker evidence than a single independently-observed serious issue.

**Why not `sqrt(raw * anchor)` (an earlier, rejected design).** An
initial version dampened a module's raw weight-sum via
`sqrt(raw * critical_weight)`, anchored so a single CRITICAL finding
(`raw = 15`) mapped to exactly 15. This has a fatal flaw that is a useful
cautionary example: **any single concave curve pinned through both
`(0, 0)` and `(anchor, anchor)` must lie *above* the identity line for
all inputs between those two points** (a direct consequence of
concavity — the curve lies above its own secant line). Concretely, this
meant a lone INFO finding (`raw = 0.5`) was inflated to a contribution of
`sqrt(0.5 * 15) ≈ 2.74` — a 5.4x amplification — and a clean asset with
one trivial INFO finding in each of three modules scored into the
MEDIUM tier. This was caught by
`tests/test_correlate.py::test_clean_asset_with_only_info_findings_stays_low_regardless_of_module_count`
(originally written against the sqrt design, where it failed) and is
exactly the kind of defect an evaluation suite with ground-truth
expectations is supposed to surface — it would not have been obvious
from reading the formula alone.

**The formula actually used.** Within a module, findings are sorted by
severity weight descending; the worst one counts at full weight, and
each subsequent finding counts at `MODULE_DECAY ** i` of its own weight
(`MODULE_DECAY = 0.5`):

```
contribution(module) = Σ_i  weight_i · MODULE_DECAY^i      (weights sorted descending, i starting at 0)
```

This satisfies both required properties exactly:
- A module with **one** finding of any severity contributes **exactly**
  that finding's own weight — no amplification, regardless of severity.
  (`tests/test_correlate.py::test_lone_finding_of_any_severity_is_never_amplified`)
- A module with **many** same-severity findings sees strongly sublinear
  growth: ten LOW findings (naive sum 20.0) contribute
  `2.0 · (1 + 0.5 + 0.25 + … + 0.5⁹) ≈ 3.996`.
  (`tests/test_correlate.py::test_repeated_findings_in_one_module_are_dampened`)

## 4. Correlation rules (the actual contribution)

`observer/correlation_rules.py` holds a declarative catalog of rules.
Each rule is `(id, name, weight, rationale, predicate)`, where `predicate`
is a pure function of `(TargetFindings, all_findings)` returning `bool`.
A triggered rule adds its `weight` as a flat bonus to the target's raw
score. The catalog currently has six rules (see the module docstring for
each rule's full security rationale):

| id | weight | compounds |
|---|---|---|
| `exposed-unauth-datastore-plus-surface` | 10 | open Redis/Mongo/ES port + ≥10 discovered subdomains |
| `weak-transport-stack` | 6 | missing HSTS + (outdated TLS protocol or cert near expiry) |
| `legacy-service-known-cve` | 9 | an NSE-flagged CVE + a ≥MEDIUM netscan finding on the same host |
| `spoofable-mail-surface` | 5 | no SPF record + reachable port 25 |
| `unmonitored-shadow-surface` | 7 | ≥15 discovered subdomains + zero active checks run |
| `active-recon-plus-known-weakness` | 8 | a global passive-monitor scan alert + a HIGH+ finding on this target |

Each rule has a **positive and a negative control test** in
`tests/test_correlate.py` (e.g. the datastore rule is tested against both
a large and a small subdomain count, confirming the rule fires only when
both conditions hold, not on either alone). This positive/negative
pairing is the minimum bar for claiming a rule "detects" anything.

Rule weights were set by judgment, not fit to data — see §6 (limitations)
for what a stronger evaluation would require.

## 5. Normalization and tiers

The raw score (module contributions + triggered-rule bonuses) is
unbounded; it is mapped onto a 0–100 scale via a saturating exponential:

```
score = 100 · (1 − e^(−raw / K)),   K = 14.0
```

`K` was calibrated against the worked examples in §7 below so that a
synthetic "clearly compromised" asset (multiple independent findings,
four correlation rules triggered) lands in the CRITICAL band, while a
single uncorroborated CRITICAL finding alone lands in HIGH rather than
CRITICAL — i.e., the model requires either a genuinely severe lone
finding or *corroboration across modules* to reach the top tier, not
just one bad data point.

Tiers: `LOW < 25 ≤ MEDIUM < 55 ≤ HIGH < 80 ≤ CRITICAL`. These thresholds
are original to this tool; no correspondence to any external standard
(e.g. NIST, FIRST) is claimed.

## 6. Limitations (for a thesis "threats to validity" section)

- **Rule weights and `K` are hand-set, not learned or fit.** A rigorous
  follow-up would calibrate both against a labeled corpus (§7) via, e.g.,
  grid search minimizing error against analyst-assigned ground-truth
  scores, or a logistic/ranking model trained on labeled asset outcomes.
- **The rule catalog is a fixed, manually-authored list.** It is not
  exhaustive and does not generalize to compound risks it wasn't
  explicitly written for. A mining approach (e.g. association-rule
  learning over a large corpus of real findings + incident outcomes)
  could discover rules this manual catalog misses — and is the natural
  "Chapter 6: Future Work."
- **No external validation corpus yet.** The test suite validates
  *internal consistency* (the formula does what it claims to do) via
  synthetic, hand-constructed ground truth. It does not yet validate
  *external accuracy* — whether higher scores actually correlate with
  real-world exploitation likelihood or impact. That requires running
  the full pipeline against a corpus of intentionally vulnerable targets
  (DVWA, Metasploitable2/3, OWASP Juice Shop) with independently
  hand-verified vulnerability ground truth, and reporting precision/
  recall of the resulting tiers against that ground truth — the natural
  next phase of this work, and the centerpiece a thesis evaluation
  chapter would need.

## 7. Worked examples

Computed directly from `observer/correlate.py` (reproducible via
`tests/test_correlate.py::test_compromised_asset_reaches_critical_tier`
and the two simpler cases alongside it):

| scenario | raw | score | tier |
|---|---|---|---|
| Clean asset, 3 modules, INFO-only findings | 1.5 | 10.2 | LOW |
| Single uncorroborated CRITICAL finding | 15.0 | 65.8 | HIGH |
| Compromised asset, 4 correlation rules triggered | 59.0 | 98.5 | CRITICAL |

The middle row is the key calibration check: a lone serious finding is
treated as genuinely high risk (65.8, solidly HIGH) without alone
reaching CRITICAL — reaching CRITICAL requires either an even more
severe lone signal or, more interestingly, *corroboration* across
independent modules, which is exactly the property the correlation
rules are meant to capture.
