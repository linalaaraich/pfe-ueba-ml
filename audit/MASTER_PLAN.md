# MASTER PLAN — UEBA System Audit (severity-ranked, cross-area)

**Date:** 2026-06-04 · **Branch:** `audit/ueba-system-review` · **Method:** audit → RCA → brainstorm → plan → execute → re-audit (real verification).
**Scope:** the `pfe-ueba-ml` repo only. The "live system" (GCP VM1 Wazuh + VM2 Windows/Sysmon) is **not reachable from here** — items needing it are marked `NEEDS-VM`.

Per-area detail: [training-pipeline](training-pipeline.md) · [features-contract](features-contract.md) · [integration-daemon](integration-daemon.md) · [packaging-repro](packaging-repro.md) · [tests-docs](tests-docs.md) · executed evidence: [VERIFICATION-LOG](VERIFICATION-LOG.md).

---

## Executive summary

The two earlier fixes (Colab build-backend, Autoencoder `.keras` export) are **confirmed sound** and unblock *running* the notebook. But the audit found the harder truth: **the system has never been validated on data it could actually see in production.** The reported detection performance is an artifact of synthetic data, the "portable z-score" signal is computed on three different bases (train / test / live) with no shared baseline, and the parser/daemon fail silently or crash on realistic Wazuh input. None of these are visible from a green "Run All" — which is exactly the class of bug this method targets.

**Counts (post-verification):** P0 × 3 · P1 × 9 · P2 × 8 · P3 × 7.

---

## Cross-area root causes (collapse the symptoms)

Most findings are surface expressions of **five** underlying causes. Fix the cause, not each symptom.

### RC-1 — No persisted, shared baseline; features are computed on three different populations
`z_score_files`/`z_score_logins` (the project's headline "portability" signal) are recomputed from scratch in each context:
- **train:** over the full 300-session synthetic population (notebook cell 10),
- **test:** over the *mixed normal+attack* set (cell 31) → the same normal session gets a *different* z-score than at train time (probed: z=-0.11 train vs z=-0.72 test),
- **serve:** over a rolling, FIFO-capped `df_history` that starts **empty every reboot** (daemon) → with <2 sessions/user the z-scores are 0.0 or ±0.707 *regardless of magnitude*.

The scaler/models are positional and were fit on basis (1). Bases (2) and (3) silently feed them out-of-distribution vectors.
**Collapses:** training P0(z-leakage), training P1(AE threshold on synthetic), daemon P0(cold-start), features(new-user z-score). **This is the core ML-correctness flaw.**

### RC-2 — Validated on synthetic data that is trivially separable *and* unreachable by the real parser
The attack simulators draw from ranges **disjoint** from normal on nearly every feature (files 1–30 vs 50–300; bytes 1k–50k vs 100k–5M; etc.), so *any* threshold scores ~100%. Worse, several features the models lean on **cannot take those values from real logs**: `bytes_sent` is sourced from Sysmon EID 3 which carries no byte count (≈always 0 live); `entropy_commands`/`velocity` are uniform-random magnitudes in the simulator but bounded Shannon entropy in the parser.
**Collapses:** training P0(detection=artifact), training P1(semantics≠parser), features P0(bytes_sent dead), features(entropy semantics). **The headline metric measures the generator, not the model.**

### RC-3 — Dual source of truth → silent drift
The same fact is stated in two places and one is a lie: `requirements.txt` exact pins (never installed; every path uses `pyproject` loose ranges) · `NUMERIC_FEATURES` defined independently in notebook **and** daemon (identical today, nothing guards it) · docs say **Azure / Ubuntu 24.04** (reality **GCP / 22.04**) · "**16 features**" (reality **14**) · a phantom **`ml-pipeline`** branch (everything is on `main`) · `PFE 2024` / `datetime(2024,…)` in a 2026 project.
**Collapses:** packaging P1(pins), tests-docs P0(untested contract / feature count / infra docs), notebook P1(hardcoded foreign clone URL).

### RC-4 — Silent failure & fragile parsing on the exact data it's built for
Bare `except` blocks and unguarded field access mean the system degrades to *plausible wrong answers* or crashes on real/hostile log input:
- tz-aware vs naive timestamp mix → `TypeError` crash (verified),
- non-string timestamp / non-dict `data` → `AttributeError` crash (verified; **daemon DoS vector** — `extract_raw_fields` is unguarded in the run loop),
- `fromisoformat` rejects non-colon offsets on Python 3.10 (VM1) → events silently dropped (`NEEDS-VM`),
- daemon reads a half-written JSON line at a poll boundary and advances past it → alert permanently dropped,
- daemon `seek(0,2)` at open + no persisted offset → every restart is a **blind window** (alerts during downtime never processed),
- Autoencoder exception swallowed → ≥2/3 vote silently becomes a 2/2 AND with `confidence` still reporting 1.0.

### RC-5 — Tests don't protect the invariants, and one is wrong
`test_outlier_has_high_zscore` **fails** (verified: 1.7876 > 2.0 is False) — the one test meant to prove outlier detection has been red. Zero tests cover the daemon, `predict`/ensemble, `_severity`, or the train↔serve feature-order contract (the single most important ML invariant). The `_make_alert` fixture only sets `targetUserName` while the parser prefers `subjectUserName`, masking the real "which username wins" branch.

---

## Severity-ranked master table

| # | Issue | Sev | RC | code-safe? | runs/serves-for-real? | Fixable here? |
|---|-------|-----|----|-----------|-----------------------|----------------|
| 1 | Reported detection rate is a synthetic artifact (no real-data evaluation) | **P0** | RC-2 | n/a | ❌ unproven on real data | Partial — needs real 3-day dataset (`NEEDS-VM`) |
| 2 | No shared/persisted baseline → train/test/serve z-score skew + daemon cold-start | **P0** | RC-1 | ⚠️ wrong values | ❌ predictions meaningless at warm-up | Design fix here; calibration `NEEDS-VM` |
| 3 | `bytes_sent` (and possibly other features) is a dead/constant feature on real logs | **P0** | RC-2 | ⚠️ | ❌ ≈0 live | Code here; confirm field `NEEDS-VM` |
| 4 | Train↔serve feature-order contract is duplicated and untested | P1 | RC-3/5 | ✅ today | ⚠️ unguarded | ✅ add shared constant + test |
| 5 | Failing z-score test (red suite) | P1 | RC-5 | ❌ | ❌ | ✅ fix assertion/logic |
| 6 | Parser crashes on tz-mix / non-string ts / non-dict data (daemon DoS) | P1 | RC-4 | ❌ | ❌ crashes | ✅ guards + normalize |
| 7 | Daemon restart blind window (`seek(0,2)`, no persisted offset) | P1 | RC-4 | ⚠️ | ❌ misses alerts | ✅ persist position |
| 8 | Partial-line read drops an alert permanently | P1 | RC-4 | ⚠️ | ❌ | ✅ buffer incomplete line |
| 9 | Autoencoder failure silently degrades the vote, confidence still 1.0 | P1 | RC-4 | ⚠️ | ⚠️ | ✅ surface + re-base denominator |
| 10 | `requirements.txt` pins never installed → train/serve version skew, pickle-load risk | P1 | RC-3 | ⚠️ | ⚠️ | ✅ reconcile to one source |
| 11 | Docs lie: Azure/24.04 vs GCP/22.04; "16 features" vs 14; phantom branch | P1 | RC-3 | n/a (jury-visible) | — | ✅ rewrite docs |
| 12 | `fromisoformat` drops events on VM Python 3.10 | P1 | RC-4 | ⚠️ | ❌ on VM | Code here; confirm `NEEDS-VM` |
| 13 | Notebook hardcodes foreign clone URL, no branch pin | P1 | RC-3 | ⚠️ | ⚠️ trains wrong code | ✅ parametrize |
| — | …P2/P3: `SENSITIVE_PATH` default backslash (masked by config), `new_ip` misnamed, `make train` missing nbconvert dep, deprecated `utcnow()`/ruff config, author email in metadata, `python` vs `python3`, AE threshold σ hardcoded vs config, no VM install docs | P2/P3 | mixed | — | — | ✅ mostly |

---

## Execution order & strategy

**Wave A — fix-here, safe, fully verifiable now** (no behavior risk to the thesis; I implement + verify + commit each):
#5 failing test, #6 parser guards, #4 feature-order shared constant + contract test, #8 partial-line, #7 restart offset, #9 vote degradation, #12 robust timestamp parsing, #13 notebook clone parametrization, #10 dependency reconciliation, #11 docs rewrite, and the P2/P3 cleanups.
*Verify:* `pytest` green (incl. new tests), re-run the malformed-input probes, re-execute the notebook end-to-end.

**Wave B — needs a design decision from you** (these change the *methodology/narrative* of your PFE, so I will NOT silently bake them in):
- **#1 / #2 / #3:** the synthetic-only evaluation, the frozen-baseline design, and the dead-feature set. The honest fix is to (a) generate the real 3-day dataset on VM1, (b) freeze a per-user baseline artifact from it that both notebook and daemon load, (c) drop or re-source features that are constant on real logs, and (d) report metrics on a held-out real/realistic split. I'll prepare the code scaffolding and a written plan; the calibration itself needs your real `alerts.json`.

**Wave C — `NEEDS-VM` verification checklist** (for when you're on VM1): real `alerts.json` field-shape check, `bytes_sent` reality, Python-3.10 timestamp behavior, end-to-end detect→alert on the live daemon.

## Verification protocol (the "real-induction" analog for this project)
1. **`pytest tests/ -q`** → must be fully green (currently 1 failed / 18 passed).
2. **Malformed-input probes** (see VERIFICATION-LOG) → must no longer crash.
3. **`nbconvert --execute` end-to-end (synthetic mode)** → all 3 models train, export `.keras`+`.pkl`, reload cell passes, the 4 attack scenarios are detected. (Running in background; result appended to VERIFICATION-LOG.)
4. **`NEEDS-VM`** items deferred to Wave C with an explicit checklist.

> A fix is "done" only when its root cause is dead under (1)–(3) with fresh evidence, not when it merely compiles.
