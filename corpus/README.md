# Evaluation corpus

Validates the correlation engine's *external* accuracy (does a higher
score actually correspond to a worse real target?) against intentionally
vulnerable lab applications — complementing `tests/test_correlate.py`,
which only validates *internal* consistency (does the formula do what it
claims to do) via synthetic data.

## 1. Bring up the lab targets (Docker, on a machine where it runs)

This sandboxed session's Docker daemon can't run nested containers, so
do this on your own machine (Docker Desktop on Windows/Mac, or native
Docker on Linux).

```bash
docker network create observer-lab

docker pull bkimminich/juice-shop
docker run -d --name juice-shop --network observer-lab -p 127.0.0.1:3000:3000 bkimminich/juice-shop

docker pull vulnerables/web-dvwa
docker run -d --name dvwa --network observer-lab -p 127.0.0.1:8081:80 vulnerables/web-dvwa

docker pull webgoat/webgoat
docker run -d --name webgoat --network observer-lab -p 127.0.0.1:8082:8080 webgoat/webgoat

docker ps   # confirm all three show "Up"
```

**Always bind to `127.0.0.1:`, never `0.0.0.0:` or a bare port** — these
images are deliberately full of holes and must never be reachable from
your LAN or the internet.

Teardown when done:
```bash
docker stop juice-shop dvwa webgoat
docker rm juice-shop dvwa webgoat
docker network rm observer-lab
```

## 2. Run The Observer's modules against them

```bash
pip install -r ../requirements.txt     # pyyaml is required for the corpus scripts
python3 run_corpus.py                  # all three targets
python3 run_corpus.py --target dvwa    # just one
```

This still goes through scope enforcement (a dedicated scope file local
to the corpus, not your real `~/.observer/scope.json`) and saves raw
findings + a correlated risk report to `results/<target>_<timestamp>.json`.

## 3. Annotate ground truth

**Read `ground_truth/_SCHEMA.md` first.** The three `ground_truth/*.yaml`
files are unverified drafts — you must open each result file, read every
finding, and hand-annotate which expectations are actually confirmed
before any precision/recall number means anything.

## 4. Score

```bash
python3 score_corpus.py
```

Prints precision/recall per target, computed only from annotated
(non-`unverified`) entries, with a loud warning naming how many entries
still need review. This is the table that belongs in a thesis evaluation
chapter — once it's backed by real annotation, not before.

## Scope of this corpus

The Observer's current active modules (webcheck, netscan) detect
configuration/exposure-level issues: missing headers, banner disclosure,
open ports, weak TLS. They do not do application-logic testing. Juice
Shop, DVWA, and WebGoat are built around application-logic vulnerabilities
(SQLi, XSS, broken auth, business-logic flaws) that these modules are not
designed to find — see `docs/methodology.md` §6 and each target's
ground-truth file for the explicit scope boundary. This corpus evaluates
what the tool actually claims to do, not a superset of it.
