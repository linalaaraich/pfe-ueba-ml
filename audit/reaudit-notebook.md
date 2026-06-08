# Re-audit (round 2) — NOTEBOOK & MODELING CONFIG

Scope: `notebooks/ueba_ml_pipeline.ipynb` (45 cells, 19 code), `tests/test_model_config.py`,
`config/config.yaml` (detection block). ANALYSIS ONLY — no edits. Notebook not executed
(no TF install); cells parsed via AST + read line-by-line; daemon/baseline read for parity.

Branch: `audit/ueba-system-review`.

---

## 0. Intended train -> export flow (5-line model)

1. Load normal data (synthetic 300 sessions, single user `user_normal`) -> `df_normal`.
2. Compute FROZEN per-user baseline (mu/sigma, ddof=0) -> `baseline.json`; derive z-scores from it.
3. Fit `StandardScaler` on normal -> scale; fit IF + OCSVM (contamination/nu/gamma from config).
4. Train AE on 80/20 split; calibrate threshold = 99th percentile of VALIDATION recon errors.
5. Export scaler.pkl, isolation_forest.pkl, one_class_svm.pkl, autoencoder.keras,
   ae_threshold.json, baseline.json. Daemon reloads the SAME six artifacts.

VERDICT: the notebook DOES use all four fixes end-to-end. Frozen baseline is used for BOTH
train (cell 11) and test (cell 33) z-scores; baseline.json IS exported (cell 11); AE threshold
DOES use `calibrate_ae_threshold` on validation percentile (cell 27, not mu+3sigma);
contamination/nu/gamma DO come from config (cells 6/19/22). No cell still uses the OLD per-batch
`add_zscores` or hardcoded 0.05 on the primary path. The remaining findings are cosmetic/edge,
not silent-bug-grade.

---

## Severity table

| # | Sev | Title | Cell(s) | Dims |
|---|-----|-------|---------|------|
| 1 | P2 | Stale comments/print contradict the code ("5%", "mu+3sigma") | 19,22,27 | CODE-SAFE / runs |
| 2 | P2 | z-score ddof mismatch on the DEGRADED (no-baseline) path: train ddof=0 vs serve fallback ddof=1 | 11 vs daemon | CODE-SAFE / parity-on-fallback |
| 3 | P3 | AE threshold default skew: daemon falls back to 0.05 if ae_threshold.json missing; notebook never writes 0.05 | 27 vs daemon L105 | CODE-SAFE |
| 4 | P3 | Per-model "anomaly rate on normal" (cell 30) computed IN-SAMPLE on training X_scaled | 30 | honesty nuance |
| 5 | P3 | OCSVM trained on a 2000-row subsample with `np.random.choice` (no fixed RNG re-seed at cell) -> Run-All reproducibility depends on cell order | 22 | reproducibility |
| 6 | P3 | `test_model_config.py` re-trains its OWN models inline; does NOT load the notebook's exported artifacts -> guards config VALUES, not the shipped models | test | meaningful-but-narrow |
| 7 | P4 | Single-user synthetic baseline: per-user path never exercises the multi-user / global-fallback branch | 7/8/11 | jury optics |

CONFIRMED-FINE: baseline frozen + reused train&test; baseline.json exported; calibrate_ae_threshold
wired; contamination/nu/gamma config-driven; FP measured on held-out normal; synthetic caveat present;
NUMERIC_FEATURES single-sourced; AE saved as .keras + reload test; all cells AST-parse.

NOT-VERIFIABLE-HERE: actual Colab Run-All numerics (FP%/recall), TF training convergence,
real `import ueba` resolution on Colab runtime. Marked Colab-run-confirmation NOT-VERIFIABLE-HERE.

---

## Issue 1 — Stale comments/print contradict the (correct) code  [P2]

AUDIT. Code is right, prose is wrong — exactly the kind of thing a jury reads aloud.
- Cell 19 L527: `contamination=CONTAMINATION,  # 5% d'anomalies supposées...` — value is now 0.01.
- Cell 22 L598: `nu=OCSVM_NU,  # Proportion maximale d'anomalies attendues (5%)` — now 0.01.
- Cell 27 L759: `print(f'Seuil d'anomalie (μ + 3σ) : {ae_threshold:.6f}')` — the threshold is now the
  99th VALIDATION percentile (mu+sigma is only the <20-point fallback). The printed label lies.

RCA: comments/labels not updated when contamination lowered (commit 7f4f782) and AE calibration
rewired (commit 7cba6b3). Pure documentation drift.

BRAINSTORM: (a) fix the three strings; (b) print the actual config values so the label can't drift;
(c) add a markdown note above each model citing config.yaml as source of truth.

PLAN: edit L527 -> `# contamination depuis config (0.01)`, L598 -> `# nu depuis config (0.01)`,
L759 -> `Seuil AE (p{AE_PCT} validation)` and print `AE_PCT`. No logic change.

## Issue 2 — z-score ddof mismatch on the no-baseline fallback path  [P2]

AUDIT. Primary path is consistent: notebook cell 11 and daemon `to_scaled_vector` both call
`apply_baseline_zscores` -> `baseline._z` (population, ddof=0). BUT the FALLBACK differs:
- notebook cell 10 inline `add_zscores` uses `stats.zscore(x, ddof=1)`;
- daemon falls back to `parse_logs.add_zscores`, also ddof=1;
- frozen baseline uses ddof=0 (`grp.std(ddof=0)`, baseline.py L51/56).
So if baseline.json is ever absent at serve time, z-scores are computed on a different sigma basis
than the scaler/models were fit with (which were fit on ddof=0 baseline z-scores).

RCA: two independent z-score implementations with different ddof. The frozen-baseline design makes
them agree ONLY when baseline.json is present; the degraded path silently diverges.

BRAINSTORM: (a) make `add_zscores` and baseline share ddof (pick ddof=0 everywhere, as baseline.py
already documents as the chosen convention); (b) have the daemon treat missing baseline.json as a
hard error rather than a silent ddof-skewing fallback (it is the shipped invariant); (c) document
that the fallback is best-effort only.

PLAN: align `parse_logs.add_zscores` + notebook inline fallback to ddof=0; OR (lower-risk) leave
fallback but log loudly. This is the daemon owner's call — flag as cross-area parity note. Impact
is bounded because the intended path (baseline present) is correct.

## Issue 3 — AE threshold default 0.05 skew  [P3]

AUDIT. daemon L105 `thr = 0.05` if `ae_threshold.json` missing/illisible. Notebook always writes the
calibrated value, so on the normal flow there is no skew. The 0.05 default is a legacy magic number
unrelated to the new calibration scale (validation MSE percentile, typically O(0.1-1) on scaled data).
A missing JSON would therefore produce an arbitrary, possibly-too-low threshold -> FP spike, silently.

RCA: pre-calibration default never revisited. Low risk (artifact always exported together).

PLAN: when the JSON is missing, either disable the AE vote (None) or derive a percentile from a
shipped sample — do not pin a stale scalar. Cosmetically, also move 0.05 out of code into config.

## Issue 4 — In-sample per-model "anomaly rate on normal"  [P3]

AUDIT. Cell 30 prints per-model + ensemble anomaly rates on `X_scaled` = the TRAINING normal set.
These are in-sample numbers (IF/OCSVM saw this data; AE saw 80% of it). They are framed as
"sur données NORMALES" which a reader may conflate with the held-out FP rate.
The HONEST FP number (cell 34, confusion matrix) IS on held-out normal (120 fresh sessions from a
later date, never in training) — that part is correct and the synthetic caveat (cell 32 markdown)
is present.

RCA: cell 30 is a sanity/exploration cell, not an evaluation cell, but its wording overlaps the
evaluation claim.

PLAN: relabel cell 30 output as "taux in-sample (diagnostic)" and let cell 34 own the FP claim.
No leakage in the reported metric — only a labeling ambiguity.

## Issue 5 — OCSVM subsample reproducibility  [P3]

AUDIT. Cell 22 L592 `np.random.choice(len(X_scaled), 2000, replace=False)` draws from the global
NumPy RNG. SEED is set once in cell 4; any intervening RNG consumer (e.g. jitter in cell 23 viz,
or re-running cells out of order) changes which subsample is drawn -> different OCSVM each Run-All.
Not a correctness bug (model is saved & loaded), but "results not exactly reproducible" was an
earlier complaint (DATASET_HEALTH.md). With n=300 synthetic, `min(2000,300)=300` so ALL rows are
used and the draw is just a shuffle — currently harmless, but becomes live on real/larger data.

PLAN: pass `np.random.RandomState(SEED)` for the choice, or skip subsampling when n<=2000.

## Issue 6 — test_model_config.py: meaningful but narrow  [P3]

AUDIT. `test_config_has_tuned_detection_values` asserts contamination/nu/gamma == 0.01 — a real
regression guard against config drift (NOT tautological; it reads config.yaml).
`test_low_fp_and_high_detection_with_config_values` re-simulates a dataset, re-fits IF+OCSVM with
the config values, and asserts FP < 12% (OCSVM), ensemble FP < 6%, detection > 90% on disjoint
synthetic attacks. Good: it proves the LOWERED params still separate. Caveats:
- It does NOT exercise the notebook's exported artifacts, nor the AE, nor calibrate_ae_threshold,
  nor the frozen-baseline z-scores. So it guards the config numbers and the sklearn behavior, but
  not train/serve parity of the SHIPPED models.
- It uses `np.random.RandomState(0).shuffle` and seed=42 sim -> deterministic; fine.
- `ae_threshold_percentile`/`ae_threshold_sigma` from config are NOT asserted anywhere here
  (covered separately in test_baseline.py::calibrate_ae_threshold).

VERDICT: meaningful regression guard for contamination/nu/gamma; not a parity test.
PLAN (optional): add an assertion on `ae_threshold_percentile == 99.0` and a smoke test that loads
exported models if present.

## Issue 7 — Single-user synthetic baseline  [P4]

AUDIT. All synthetic sessions use the default `user='user_normal'`, so baseline.json has exactly one
per_user entry; the global-fallback branch of `apply_baseline_zscores` is never hit in the demo.
On real Wazuh data there will be many users; the per-user/global logic is sound (read in baseline.py)
but untested by the notebook run. Jury optic: "your portable per-user baseline only ever saw one
user." The realistic multi-profile simulator exists (`ueba.features.simulate.simulate_dataset`,
used by the TEST) but the NOTEBOOK still builds normals via the single-user inline
`simulate_normal_session` (cell 8).

PLAN: switch cell 8 synthetic branch to `simulate_dataset(n_users=..., days=...)` so the notebook
demonstrates multi-user baselines and matches what test_model_config.py exercises. Coherence win.

---

## Lens notes

- ARCHITECT (train<->serve parity — key invariant): PASS on the primary path. Same NUMERIC_FEATURES
  (single source, imported both sides), same scaler (exported/loaded), same frozen-baseline z-score
  basis (apply_baseline_zscores both sides), same AE threshold (ae_threshold.json), same vote logic
  (>=2). Divergence only on degraded fallbacks: ddof (Issue 2) and AE default 0.05 (Issue 3).
- ML-PIPELINE: calibrated percentile threshold + contamination 0.01 + realistic-attack separation
  are COHERENT (lower contamination -> fewer in-sample flags; percentile threshold bounds AE FP;
  test proves attacks still separate). No contradiction.
- DATA-INTEGRITY: no scaler/baseline fit on test. Scaler fit on train normal only (cell 17);
  baseline computed on train normal only (cell 11); test transformed with frozen scaler+baseline
  (cells 33-34). FP on held-out normal. The only in-sample framing is cell 30 (Issue 4).
- DOCS-WRITER: markdown caveat (cell 32) honest. Three stale inline strings (Issue 1) are the only
  code/claim mismatches.
- FRESH-EYES (what embarrasses at the jury): (a) printed "mu+3sigma" label while code uses percentile
  (Issue 1) — most likely to be caught live; (b) single-user baseline (Issue 7); (c) "anomaly rate
  on normal" being in-sample (Issue 4).

## Two dimensions
- CODE-SAFE? YES — all cells AST-parse; no static NameError/order-trap on a clean top-to-bottom
  Run-All (local-only constants guarded with `globals().get(...)`; `_find_repo_root` + sys.path make
  `import ueba` robust; baseline/scaler/AE all defined before use).
- RUNS-FOR-REAL? Likely coherent and NON-LEAKY on a clean Colab Run-All (parity + held-out FP hold
  statically). Exact numerics NOT-VERIFIABLE-HERE (no TF). No leakage found.
