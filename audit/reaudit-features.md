# Re-audit (round 2) — Feature Pipeline & Baseline/Calibration

Area: `src/ueba/features/parse_logs.py`, `src/ueba/features/baseline.py`,
`tests/test_features.py`, `tests/test_baseline.py` (+ cross-checks against
`simulate.py`, `integration/daemon.py`, `notebooks/ueba_ml_pipeline.ipynb`).
Mode: ANALYSIS ONLY, read-only, light numeric probes (numpy 1.26 + scipy 1.11
available; pandas / sklearn / tensorflow NOT importable → pandas-dependent claims
re-derived in pure numpy, TF-dependent claims reasoned + marked NOT-VERIFIABLE).

---

## 5-line model + contracts

1. **parse_logs** turns Wazuh `alerts.json` → raw events → per-user sessions →
   14-feature numeric vectors, in a frozen column order (`NUMERIC_FEATURES`).
2. **baseline.compute/apply** freezes per-user μ/σ (ddof=0) once on normal data and
   re-applies them identically at train (notebook), data-gen (simulate) and serve
   (daemon) → z-scores invariant to batch composition; global fallback for unseen users.
3. **calibrate_ae_threshold** sets the AE anomaly cutoff = p-th percentile of
   *validation* reconstruction errors (μ+kσ fallback when <20 val points).
4. **Invariant**: the SAME error metric (per-sample MSE, `mean((x-recon)^2)`) and the
   SAME z-score basis (frozen baseline, ddof=0) must be used at train and serve.
5. **Contract**: scalers/models are positional → feature order and z-score basis must
   never drift between notebook ↔ simulate ↔ daemon.

---

## Severity table

| # | Severity | File / locus | Issue (one line) |
|---|----------|--------------|------------------|
| F1 | Medium | notebook cell 26/27 (val split) feeds calibrate_ae_threshold | AE validation set = last 20% un-shuffled; on the real-data path sessions are ordered by username → val ≈ one user → percentile FP-bound is calibrated on a non-representative slice |
| F2 | Medium | baseline.calibrate_ae_threshold | NaN/inf in val_errors → `np.percentile` returns NaN silently → daemon `mse > NaN` always False → AE permanently mute (no warning) |
| F3 | Low-Med | baseline.compute_baseline | NaN in a source column propagates into frozen baseline.json (`mean`/`std`=NaN); `json.dumps` emits bare `NaN` (non-strict JSON) and `_z` then silently yields 0.0 for the whole user |
| F4 | Low | notebook `simulate_normal_session` / `simulate_insider_threat_session` | is_night NOT derived from hour (hardcoded 0 / random) — the is_night-from-hour fix (c0c11b4) reached parse_logs+simulate.py but NOT the notebook synthetic generators; default `USE_REAL_DATA=False` train path still uses them |
| F5 | Low | baseline.apply_baseline_zscores | `df.iterrows()` per row → O(n) Python-level loop; fine for daemon (1 row) but a perf footgun on full-dataset calls (simulate/notebook on large real data) |
| F6 | Info | baseline.compute_baseline | `if len(grp) > 0 else 0.0` is dead code (groupby never yields empty groups) |
| F7 | Info | parse_logs._parse_timestamp | naive-normalization keeps wall-clock and DROPS offset (does not convert to UTC) — correct for hour/is_night, but mixed-tz sources would be inconsistent |

No High/Critical findings in scope. Counts: Critical 0, High 0, Medium 2, Low 3
(F4/F5 low, F3 low-med), Info 2.

---

## CONFIRMED-FINE (probed, do not re-flag)

- **calibrate_ae_threshold bounds FP.** Probed on skewed lognormal: empirical
  `(val > thr).mean()` = 0.0100–0.0200 at p99 for n=50..5000 (target ~0.01). The
  percentile genuinely bounds FP to ~(100−p)% on asymmetric errors. Direction matches
  daemon (`mse > threshold`) and notebook (`> ae_threshold`).
- **Fallback path correct.** `[0.1,0.2,0.3]` (n<20) with fallback_mean=0.2, std=0.05,
  σ=3 → 0.35 = μ+3σ exactly. Empty val with no fallback → 0.0. all-equal n≥20 → that
  constant. percentile=100 on finite data → max → 0 FP (strict `>`). All sound.
- **AE error metric is train/serve identical.** Notebook cells 27/30/38 and daemon
  `predict` (line 188) both compute per-sample `np.mean((x-recon)^2)`; threshold loaded
  from the same `ae_threshold.json`. NOT-VERIFIABLE end-to-end (TF absent) but code paths
  are byte-identical.
- **z-score basis is train/serve identical & batch-invariant.** Notebook (cell 11),
  simulate.py (line 192) and daemon (`to_scaled_vector`, line 234) all call
  `apply_baseline_zscores` against the SAME frozen baseline.json, ddof=0. Re-derived in
  numpy: frozen-stats z for value 50 is identical alone vs in a {50,300,250} batch
  (28.2843); old `add_zscores` (ddof=1, sliding population) gave 0.0 vs −1.1339 → exactly
  the RC-1 drift the baseline fixes. `add_zscores` (ddof=1) now survives ONLY as the
  daemon's degraded fallback when baseline.json is missing — and the daemon logs a loud
  warning in that case (daemon line 86).
- **ddof consistency.** compute_baseline std uses ddof=0; `_z` divides by that same std;
  matches scipy `zscore(ddof=0)` to 4 dp. No mixed-ddof z-score path remains on the
  primary (baseline-present) flow.
- **unseen user / std=0 / std-NaN never divide by zero.** `_z` guards `std > 0`
  (NaN > 0 is False) → returns 0.0; unseen user falls back to global stats; std=0 → z=0.
  Tests test_baseline.py cover all three.
- **parse_logs robustness.** `_parse_timestamp` rejects non-str/empty/garbage → None;
  handles Z, offset-without-colon, fractional seconds. extract_raw_fields isinstance
  guards on data/rule/agent/win/process prevent AttributeError DoS. session-gap, entropy
  (Shannon, 0 for empty/singleton, log2(4)=2 for uniform), velocity (min duration clamp
  to 1) all correct.
- **feature_health** flags all-NaN / constant / all-zero columns as dead (nunique=0 →
  dead True). Correct.

## NOT-VERIFIABLE (VM/TF-only)

- Exact AE reconstruction-error magnitudes and whether real-data thresholds land where
  intended (needs trained `autoencoder.keras` + TF).
- Keras 3 load in daemon `_load_autoencoder` (TF absent here; degradation path reasoned-OK).
- End-to-end notebook execution (sklearn/TF absent).

---

## Per-issue detail

### F1 — AE validation slice is per-user-skewed on the real-data path (Medium)
**Audit.** `calibrate_ae_threshold` is statistically sound, but it can only bound FP if
its input `_val_errors` is a representative sample of normal behaviour. The notebook
builds the val set as `X_val_ae = X_scaled[split_idx:]` (last 20%, `shuffle` NOT applied
before the split — `autoencoder.fit(..., shuffle=True)` shuffles *training batches* only,
not the held-out array). On the real-data path, `parse_alerts_to_dataframe` →
`group_by_session` sorts events by `(username, timestamp)`, so sessions — and therefore
rows of `X_scaled` — are grouped by user. The trailing 20% is then the alphabetically
last user(s) only.
**RCA.** Calibration quality is an upstream-ordering problem, not a bug in the function.
A single-user tail has a different (often narrower) error distribution than the
population → p99 of that slice can be too low (over-alert) or too high (miss). The unit
test passes because it feeds i.i.d. lognormal directly, bypassing the ordering.
**Brainstorm.** (a) shuffle X_scaled before the 80/20 split with the fixed SEED;
(b) compute val errors on a stratified-by-user sample; (c) calibrate on full-dataset
errors (loses the held-out property but is representative); (d) at minimum, log the val
set's user-count so skew is visible.
**Plan.** Notebook-side fix (out of my three files): `idx = rng.permutation(len(X_scaled));
X_tr, X_val = X_scaled[idx[:split]], X_scaled[idx[split:]]`. No change to baseline.py.

### F2 — NaN/inf val_errors silently mute the AE (Medium)
**Audit.** `np.percentile([nan,...])` and `np.percentile([inf,...])` both return `nan`
(probed). `calibrate_ae_threshold` returns that NaN unguarded; it is written to
ae_threshold.json; daemon computes `mse > NaN` → always False → AE never votes anomaly,
silently, with no degradation flag (it still counts as an evaluated model).
**RCA.** No finiteness check on the validation errors. In practice AE recon errors on
finite scaled input are finite, but a diverged/NaN-weight AE, or an inf feature reaching
the scaler, produces NaN errors → the calibration hides the failure instead of surfacing it.
**Brainstorm.** Drop non-finite errors before percentile; if none remain, fall back to
μ+kσ on finite training errors; raise/log if the result is non-finite.
**Plan.** `val_errors = val_errors[np.isfinite(val_errors)]` at top; re-check `.size`;
final `return` guarded so a non-finite result is replaced by the fallback (or raises).

### F3 — NaN leaks into the frozen baseline (Low-Med)
**Audit.** If any source column row is NaN (real CSV reload, missing field, coerced
numeric), `grp.mean()/grp.std()` → NaN → stored in baseline.json. `json.dumps(NaN)`
emits the bare token `NaN` (probed) — accepted by Python `json.loads` but invalid per the
strict JSON spec, so external consumers may reject baseline.json. Downstream `_z` then
returns 0.0 for that user (NaN>0 False), silently flattening the z-score signal.
**RCA.** parse_logs always emits ints so the primary pipeline is safe; the exposure is
the real-data / CSV-reload path and any future numeric coercion. No NaN sanitisation in
compute_baseline.
**Brainstorm.** `grp.dropna()` (or `np.nanmean/nanstd`) before computing; coerce a
non-finite mean/std to 0.0 so JSON stays strict and the fallback is explicit.
**Plan.** In compute_baseline, drop NaN per group; store `mean = m if isfinite(m) else 0.0`.

### F4 — notebook synthetic generators don't derive is_night from hour (Low)
**Audit.** The is_night-from-hour fix (commit c0c11b4) corrected parse_logs.build_features
and simulate.py.simulate_session (both `int(hour < START or hour >= END)`), but the
NOTEBOOK still has `simulate_normal_session` with `'is_night': 0` hardcoded (while hour ∈
9–18) and `simulate_insider_threat_session` with is_night drawn at random then hour from
it (and hour=18 mislabeled night=0). With the default `USE_REAL_DATA=False`, training uses
these inconsistent generators.
**RCA.** The fix didn't touch the notebook's inline simulators; simulate.py is the
intended replacement but is only used when the CSV is generated separately.
**Brainstorm/Plan.** Either delete the notebook inline simulators and always source
`USE_REAL_DATA=False` data from `simulate.simulate_dataset`, or apply the canonical
is_night rule inside the two notebook functions. Notebook-side; no change to my files.

### F5 — iterrows in apply_baseline_zscores (Low)
**Audit.** `for _, row in df.iterrows()` builds a Series per row; O(n) Python overhead.
Harmless in the daemon (1 row) but slow on full-dataset calls (simulate/notebook on large
real data).
**RCA.** Row-wise design chosen for clarity over the vectorised `df.groupby(...).transform`.
**Plan.** Vectorise: map per-user mean/std onto columns, fill unseen users with global,
compute `(x-mean)/std` with `std.where(std>0)`; round. Behaviour-equivalent, batch-invariant.

### F6 — dead branch (Info)
`if len(grp) > 0 else 0.0` in compute_baseline never hits the else (groupby groups are
non-empty). Single-element groups give population std 0.0 (probed) → handled by `std>0`.
Cosmetic; remove for clarity.

### F7 — timestamp tz semantics (Info / CONFIRMED-FINE)
`_parse_timestamp` strips tzinfo keeping wall-clock (10:00+02:00 → naive 10:00, offset
dropped, NOT converted to 08:00 UTC). This is the RIGHT choice for hour/is_night (analyst
cares about local time-of-day) and prevents the aware/naive comparison crash in
group_by_session. Caveat: if alerts mix timezones from different agents, the same instant
yields different hours (probed: 23:00+00:00 vs 20:00−03:00 → hours 23 vs 20). Wazuh
per-agent timestamps are consistent, so this is acceptable; documenting the assumption is
the only suggested follow-up.

---

## Probe log (numpy/scipy, reproducible)
- FP bound: lognormal n∈{50,200,1000,5000}, p99 → empirical FP {0.0200,0.0100,0.0100,0.0100}.
- Boundaries: empty→0.0; all-equal(n≥20)→const; fallback 0.1/0.2/0.3→0.35; p100→max;
  NaN/inf in errors → NaN (F2).
- z-score: frozen ddof=0 matches scipy zscore(ddof=0) to 4dp; value 50 alone == in batch
  (28.2843); old ddof=1 sliding → 0.0 vs −1.1339 (RC-1 drift confirmed).
- compute_baseline single-element group std(ddof=0)=0.0; NaN col → bare `NaN` JSON token (F3).
- _parse_timestamp: wall-clock kept, offset dropped; bad inputs → None.
