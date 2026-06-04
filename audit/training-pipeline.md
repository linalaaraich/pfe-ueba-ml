# Audit — TRAINING PIPELINE (`notebooks/ueba_ml_pipeline.ipynb`)

Area: 43-cell Colab/local training notebook for the Portable UEBA system.
Scope: every cell read line-by-line + cross-checked against `src/ueba/integration/daemon.py`,
`src/ueba/features/parse_logs.py`, `src/ueba/config.py`, `pyproject.toml`, `requirements.txt`.
Method: read-only. `py_compile` of extracted code = OK. No heavy-ML install, no live run (orchestrator does that).

**Mental model (5 lines):**
1. Cell 2 detects Colab, clones a HARD-CODED repo URL, `pip install -e .`. Cell 4 imports + tries `from ueba...`.
2. Cell 6 toggles `USE_REAL_DATA` (default False → 300 synthetic "normal" sessions; True → `data/dataset.csv`).
3. Cells 10/16 build 14 NUMERIC_FEATURES, fit a `StandardScaler` on normal-only, save `scaler.pkl`.
4. Cells 18/21/24-26 train IsolationForest, OneClassSVM (subsample), Keras Autoencoder; AE threshold = μ+3σ of recon error.
5. Cells 29/31-32 build a synthetic attack test set, run the ≥2/3 ensemble vote, print a classification report; cells 35-42 export/reload/scenario-test. Serve side = `daemon.py` (must consume the same artifacts identically).

---

## Summary table (highest severity first)

| # | Title | Sev | code-safe? | runs-for-real? | One-line RCA |
|---|-------|-----|-----------|----------------|--------------|
| 1 | Z-scores recomputed on the mixed test set → leakage + train/serve skew | **P0** | yes (executes) | **NO (metrics invalid)** | `add_zscores` is re-run per-population; test z-scores use attack-inflated μ/σ, daemon uses rolling-history μ/σ — three different regimes, none matches training. |
| 2 | Reported "detection rate" is an artifact of trivially-separable synthetic data | **P0** | yes | **NO (results not credible)** | Attack simulators draw from disjoint ranges vs normal on nearly every feature; metrics measure simulator design, not model skill. |
| 3 | `entropy_commands` / `velocity` synthetic values do not match `parse_logs` semantics | **P1** | yes | **NO on real data** | Scaler+models fit on uniform-random synthetic features; real parser produces Shannon-entropy (≈0–2) and a different velocity → distribution shift at serve time. |
| 4 | Hard-coded clone URL `assia-xnz/pfe-ueba-ml` (stale/foreign repo) | **P1** | depends on URL | **maybe (clones wrong/old code)** | Colab path clones a fixed GitHub URL, not the branch under audit; trains last-pushed public code, not local fixes. |
| 5 | Autoencoder threshold (μ+3σ) calibrated on 300 synthetic rows → unstable on real data | **P1** | yes | **NO (FP rate unknown)** | 3σ on tiny, low-variance synthetic recon errors yields a threshold with no statistical guarantee for real traffic. |
| 6 | OCSVM trained on a `np.random.choice` subsample → silent reproducibility gap | **P2** | yes | partial | Subsample index draw consumes shared global RNG; ordering/run-all dependence makes the saved model run-sensitive. |
| 7 | `nu`/`contamination`=0.05 hard-codes 5% anomalies into a "normal-only" trainer | **P2** | yes | partial | Self-fulfilling 5% anomaly rate on clean data; flags 5% of genuinely-normal sessions by construction. |
| 8 | Markdown/section says "Export des modèles (.pkl)" but AE is `.keras` | **P3** | yes | yes | Doc drift after the keras-format fix. |

---

## Issue 1 — Z-scores recomputed on the mixed test set (LEAKAGE + train/serve skew) — P0

**Audit.**
Training (cell 8/10): all 300 synthetic rows have `username='user_normal'`, so `add_zscores`
computes `z_score_files`/`z_score_logins` over the 300 normal rows.
Test (cell 31, lines 906-908):
```python
# Ajout z-scores (calculés sur le dataset de test)
if 'z_score_files' not in df_test.columns:
    df_test = add_zscores(df_test)
```
`df_test` = 120 normal + 80 attack, all still `user_normal`. So the z-score for every test row
(including the normal ones) is computed against a μ/σ inflated by the attack rows.
Daemon (`daemon.py` `to_scaled_vector`, lines 186-191) computes z-scores over the rolling
`df_history` window (≤500 sessions) — a third, time-varying basis.

Probe (no pandas needed) demonstrating the skew:
```
Train z-basis:        mean=16.0 std=9.1
Test mixed z-basis:   mean=80.9 std=91.1
normal row (15 files) z on train basis:      -0.11
normal row (15 files) z on mixed test basis: -0.72
attack row (250 files) z on mixed test basis: 1.86
```
The same normal session gets z=-0.11 at train time vs z=-0.72 at test time. The scaler
(fit on train z-distribution) is then applied to test z-values from a different distribution.

**RCA.** Root cause: z-scoring is a *population* statistic but is recomputed independently per
dataset instead of being frozen at training time. There is no stored per-user (μ, σ) baseline;
`add_zscores` is stateless and re-derives the baseline from whatever rows it is handed. This is
classic test-set contamination (test normals "see" the attacks) AND train/serve skew (daemon
uses a rolling window). The reported metrics therefore do not reflect deployable behavior.

**Brainstorm.**
- (A) Fit per-user (μ, σ) on training normals, persist alongside the scaler (e.g. `zbaseline.json`),
  and have notebook-test + daemon both apply `(x-μ)/σ` from that frozen baseline. Tradeoff: small
  schema addition; correctly mirrors a real UEBA "personal baseline". **Recommended.**
- (B) Drop `z_score_*` from NUMERIC_FEATURES entirely (let the StandardScaler do the standardizing).
  Tradeoff: loses the per-user behavioral signal that is the whole point of UEBA.
- (C) Compute test z-scores only over `df_test_normal` then map onto attacks. Tradeoff: still not
  what the daemon does; fixes leakage but not serve skew.

**Plan.**
1. In `parse_logs`, add `fit_user_baseline(df_normal) -> {user:{files:(μ,σ),logins:(μ,σ)}}` and
   `apply_user_baseline(df, baseline)`; persist `models/zbaseline.json`.
2. Notebook cell 10 uses fit+save; cell 31/32 uses apply (no recompute); daemon loads + applies.
3. Verify: assert a fixed normal session yields identical `z_score_files` in cell 10, cell 32, and
   a daemon unit test (tolerance 1e-6). Re-run notebook and confirm the classification report
   changes (it will — that proves the leak was real).

---

## Issue 2 — Reported detection rate is an artifact of trivially-separable synthetic data — P0

**Audit.** Simulators (cell 7) draw normal vs attack from near-disjoint ranges on almost every feature:
- `nb_files_accessed`: normal `randint(1,30)` vs insider `randint(50,300)` (no overlap).
- `bytes_sent`: normal `1k–50k` vs insider `100k–5M` vs malware `50k–2M` (no overlap with normal).
- `nb_processes`: normal `3–15` vs malware `20–100` (no overlap).
- `entropy_commands`: normal `0–1.5` vs insider `2.0–3.5` vs malware `3.0–5.0` (disjoint).
- `is_night`/`sensitive_path_access`/`new_ip` flipped wholesale for attacks.

Cell 42 then prints `Taux de détection : {tp/(tp+fn):.1%}` as the headline result.

**RCA.** Root cause: the "evaluation" measures the *gap the author hard-coded into the generators*,
not the models' ability to find anomalies. Any thresholding method (even `nb_files>30`) scores ~100%.
Combined with Issue 1, a high recall here is doubly non-informative. This is the single biggest
"what embarrasses us if the supervisor runs this" risk: a near-perfect score on data engineered to
be perfect.

**Brainstorm.**
- (A) Make simulators *overlap* the boundary (e.g. insider `nb_files` `randint(25,120)`, bytes
  ranges that straddle normal) so detection becomes non-trivial and metrics become meaningful.
  Recommend, plus explicitly frame the notebook result as a *sanity check on synthetic data*, not a
  performance claim. **Recommended.**
- (B) Report on real labelled data from the VM (NOT VERIFIABLE WITHOUT VM) — the only truly credible
  number; keep synthetic only as a smoke test.
- (C) Add a trivial baseline (single-rule classifier) to the report so the reader sees the ensemble
  isn't beating a one-liner — honest framing.

**Plan.**
1. Widen/overlap attack ranges in cell 7; document ranges in the markdown.
2. Add markdown above cell 32: "Synthetic separability is by design; real metrics require VM data."
3. Verify: after overlap, confirm recall drops below 100% and that the ensemble beats the trivial
   `nb_files>30` baseline — otherwise the ML adds nothing.

---

## Issue 3 — `entropy_commands` / `velocity` synthetic semantics ≠ `parse_logs` — P1 (train/serve skew)

**Audit.**
- Synthetic `entropy_commands`: `round(random.uniform(0,1.5/2.0-3.5/3.0-5.0),4)` (cell 7).
- Real (`parse_logs._entropy`, lines 239-247): Shannon entropy over the *list of command lines in a
  session*, bounded by `log2(n_distinct_commands)`. A session with one command → 0.0; a few repeated
  commands → typically 0–2. Synthetic malware uses 3.0–5.0, which is **not reachable** unless a single
  session contains ≥8–32 distinct command strings.
- Synthetic malware `velocity = random.uniform(5,30)` (cell 7, line 319) but normal/insider use
  `nb_files/duration` AND real `build_features` (line 282) uses `nb_files/duration_min`. So even within
  the synthetic set, malware velocity has different semantics than the parser.

**RCA.** The scaler and all three models are fit on synthetic feature *magnitudes* that the real
feature extractor will never produce. On real data the standardized inputs shift, recon error
changes, and IF/OCSVM decision boundaries (fit in scaled space) no longer correspond to "normal".
Root cause: the synthetic generator was written to "look anomalous" rather than to match the actual
`build_features` output distribution.

**Brainstorm.**
- (A) Generate synthetic command_line *lists* and run them through the real `_entropy`/velocity code so
  synthetic features are produced by the same functions as production. **Recommended** — guarantees
  parity by construction.
- (B) Clamp synthetic ranges to the parser's realistic output (entropy 0–2, velocity = files/duration).
  Cheaper but still two code paths that can drift.

**Plan.**
1. Refactor cell 7 to emit raw events and call `build_features`+`_entropy` (import from package).
2. Verify: `df_normal[['entropy_commands','velocity']].describe()` ranges fall inside what
   `parse_logs` produces on a small fixture alerts.json.

---

## Issue 4 — Hard-coded clone URL `assia-xnz/pfe-ueba-ml` — P1

**Audit.** Cell 2, lines 64-66:
```python
['git','clone','--quiet','https://github.com/assia-xnz/pfe-ueba-ml.git', REPO_DIR]
```
On Colab this always clones that fixed public repo (default branch), then `pip install -e .` from it.
The audited branch `fix/colab-training-blocker` and any local fixes are NOT what runs unless they
were pushed to that repo's default branch.

**RCA.** Reproducibility / "runs-for-real" hazard: the notebook trains whatever code is at a foreign,
fixed URL, not the reviewed code. If that repo is private, stale, renamed, or behind, Colab Run-All
either fails at clone or silently trains old logic. The clone also has no branch pin.

**Brainstorm.**
- (A) Parameterize `REPO_URL` and `REPO_BRANCH` in the config cell (cell 6) with the real owner/branch,
  and `git clone -b $BRANCH`. **Recommended.**
- (B) Prefer Google-Drive-mounted source so the notebook runs the user's actual working tree.

**Plan.**
1. Confirm the correct canonical repo+branch with the student; set URL/branch in cell 2.
2. Verify: fresh Colab Run-All clones the intended branch (print `git rev-parse HEAD` after clone)
   and `pip install -e .` succeeds. (NOT FULLY VERIFIABLE HERE — needs a live Colab run.)

---

## Issue 5 — AE threshold μ+3σ calibrated on 300 low-variance synthetic rows — P1

**Audit.** Cell 26, lines 755-762: threshold = `errors.mean()+3*errors.std()` over the 300 normal
recon errors; saved to `ae_threshold.json`. Train/val split (cell 25) is the sequential first-240/last-60
of identically-distributed normals, so val ≈ train and the AE memorizes a narrow band. 3σ on ~300
points has a wide confidence interval; on real, higher-variance traffic the same multiplier will
mis-set the false-positive rate.

**RCA.** Threshold calibration sample size and representativeness. The σ estimate is from synthetic
data that doesn't match production (Issue 3), so the 0.3% tail assumption (μ+3σ) is meaningless for
real recon errors.

**Brainstorm.**
- (A) Calibrate threshold from a *held-out* set of real normals using a target FP quantile (e.g. 99th
  percentile) rather than μ+3σ; make σ-multiplier come from `config.detection.ae_threshold_sigma`
  (already exists in config but the notebook hard-codes 3). **Recommended.**
- (B) Keep μ+3σ but compute on a true holdout, and report the resulting FP rate so it's visible.

**Plan.**
1. Read sigma from config in cell 26; compute threshold on a holdout not used to fit the AE.
2. Verify: print fraction of holdout normals above threshold; should ≈ expected tail. Re-run.

---

## Issue 6 — OCSVM subsample uses shared global RNG (reproducibility) — P2

**Audit.** Cell 21, lines 604-606:
```python
max_samples_ocsvm = min(2000, len(X_scaled))
idx_sample = np.random.choice(len(X_scaled), max_samples_ocsvm, replace=False)
```
With 300 rows, `min(2000,300)=300` and `replace=False` → the "subsample" is a *full permutation* of all
300 rows (no actual subsampling at this size; only reorders). The draw consumes the global NumPy RNG
seeded once in cell 4; any added/removed RNG call upstream (or out-of-order execution) shifts it.

**RCA.** Uses the shared global RNG instead of a dedicated `np.random.default_rng(SEED)`; at the
synthetic size the subsample is also a no-op that just shuffles, which is harmless now but masks the
intent and is fragile if data grows or upstream RNG usage changes.

**Brainstorm.**
- (A) Use a local `rng = np.random.default_rng(SEED)` for the subsample; skip subsampling when
  `len(X_scaled) <= 2000`. **Recommended.**
- (B) Pass the full `X_scaled` to OCSVM at this size and gate subsampling behind a size check only.

**Plan.** Replace the draw with a local Generator + size guard. Verify two consecutive Run-Alls
produce a byte-identical `one_class_svm.pkl` (or identical preds on a fixed input).

---

## Issue 7 — `nu`/`contamination`=0.05 bakes 5% anomalies into a normal-only trainer — P2

**Audit.** IsolationForest `contamination=0.05` (cell 18) and OCSVM `nu=0.05` (cell 21) on a dataset
declared "normal only". By definition both will then label ~5% of clean training rows as anomalies
(cells 18/21 print this "taux d'anomalie détecté"). Config has `detection.contamination: 0.05` but the
notebook hard-codes the literal instead of reading config.

**RCA.** Conceptual mismatch between "train on normal only" and a contamination prior that forces a
positive anomaly rate on that same clean data → guaranteed false positives by construction; value not
sourced from config (drift risk).

**Brainstorm.**
- (A) Read `contamination`/`nu` from `config` and document that 5% is the *expected operational* FP
  budget, not a property of the training set. **Recommended.**
- (B) Lower contamination or use `contamination='auto'` for IF and tune `nu` against the FP budget.

**Plan.** Source both from config; print expected vs observed FP. Verify ensemble FP on normals
matches the configured budget.

---

## Issue 8 — Section title "Export des modèles (.pkl)" but AE is `.keras` — P3

**Audit.** Cell 34 markdown: "## 12. Export des modèles (.pkl)". Cell 26 correctly saves
`autoencoder.keras` + `ae_threshold.json` (the already-applied fix). Title and a couple of comments
still imply pickle for all models.

**RCA.** Documentation drift after the keras-format fix.

**Brainstorm.** (A) Retitle to "Export des modèles (.pkl / .keras)". (B) Add one line listing each
artifact + format. Recommend (A)+(B). **Plan.** Edit markdown; verify cell 35 inventory matches.

---

## CONFIRMED FINE (checked, genuinely healthy)

- **NUMERIC_FEATURES order parity:** notebook (cell 10) and `daemon.NUMERIC_FEATURES` are byte-identical
  14-feature lists in the same order — scaler/feature-order alignment is correct (probe confirmed
  `nb_feat == daemon_feat`). This is the most important train/serve invariant and it holds.
- **Already-applied fix #1 (build-backend):** `pyproject.toml` → `build-backend = "setuptools.build_meta"`,
  `[tool.setuptools.packages.find] where=["src"]`. Sound; `pip install -e .` will find `ueba`.
- **Already-applied fix #2 (no AE pickling):** cell 26 saves `.keras` + `ae_threshold.json`; cell 36 and
  `daemon._load_autoencoder` both reload via `keras.models.load_model` + JSON threshold. Consistent
  across train and serve. Sound.
- **AE recon-error formula identical** in cell 26, cell 29 (`ensemble_predict`), cell 36, cell 38, and
  `daemon.predict` (`np.mean((X-recon)**2, axis=1)` vs `np.mean(power(...))` scalar) — same math, same
  `> threshold → anomaly`, same sklearn `-1/1` convention. No skew here.
- **Scaler fit-on-normal / transform-on-test:** cell 16 `fit_transform` on normals; cell 32
  `scaler.transform` on test; cell 38 `scaler.transform` per scenario; daemon `scaler.transform`.
  Correct direction (no refit on test). The ONLY scaling problem is upstream z-score inputs (Issue 1/3).
- **Out-of-order safety nets:** cells 7/13 use `globals().get('WORK_HOUR_START',9)`; cell 10 defines
  inline `add_zscores` only if the package import failed; cell 10 initializes missing features to 0.
  Reasonable idempotency guards.
- **Syntax:** all 29 code cells extracted and `py_compile` clean (no syntax/indent errors).
- **Attack-scenario dicts (cells 38-41):** keys cover all 14 NUMERIC_FEATURES (incl. `z_score_files`,
  `z_score_logins`) with correct names; `predict_session` uses `session_features.get(f,0)` in
  NUMERIC_FEATURES order → vector is well-formed and order-correct. (Their *values* are hand-picked to
  be obvious anomalies — same caveat as Issue 2, but mechanically correct.)
- **Adversary lens:** the obfuscated command strings (`powershell -enc ...`, `regsvr32 ... scrobj.dll`,
  `mshta javascript:eval(atob(...))`) are only ever stored as DataFrame string values / printed; never
  `eval`/`exec`/`subprocess`-ed. No code-execution footgun. `subprocess` is used only for git/pip with
  list-form args (no shell=True). Safe.
- **Keras 3 / numpy2 drift:** imports use `from tensorflow import keras` and `tf.keras.callbacks`
  (compatible with TF≥2.16/Keras3 that Colab ships); BatchNorm+Dropout on 240 train rows will *warn* but
  runs; `model.save('.keras')` is the Keras-3-native path. Expected to Run-All on Colab CPU.

---

## NOT VERIFIABLE WITHOUT VM / LIVE-RUN

- **Colab Run-All end-to-end success:** syntax is clean and the logic should execute on Colab CPU, but
  this depends on (a) the hard-coded clone URL (Issue 4) actually resolving to current code, and (b)
  Colab's exact TF/Keras/numpy versions. Needs the orchestrator's live Colab run to confirm zero cells
  throw. Most-likely-to-throw cell if the URL is bad: **cell 2** (`pip install -e .` after a failed/old
  clone). No other cell has a syntactic or obvious-runtime defect.
- **Real-data path (`USE_REAL_DATA=True`):** requires `data/dataset.csv` produced by `parse_logs` on
  VM1's `/var/ossec/logs/alerts/alerts.json`. The CSV is gitignored and not present. Cannot validate
  real feature distributions, real z-score baselines, or true detection metrics from here.
- **Daemon end-to-end on live alerts:** `extract_raw_fields`/`group_by_session`/`build_features` against
  actual Wazuh/Sysmon JSON shape is VM-dependent; the train/serve skew (Issues 1 & 3) can only be
  *quantified* once real `dataset.csv` exists.
- **True model quality:** because synthetic data is trivially separable (Issue 2) and z-scores leak
  (Issue 1), the only credible performance number must come from labelled real data — NOT VERIFIABLE
  WITHOUT VM.
