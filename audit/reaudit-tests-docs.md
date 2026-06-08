# Re-Audit (Round 2) — TEST QUALITY & DOCS CONSISTENCY

Area: `tests/*` + `README.md`, `CONTEXT.md`, `DATASET_HEALTH.md`, `docs/DATA_AND_DEMO_SETUP.md`
Branch: `audit/ueba-system-review`  ·  Date: 2026-06-08  ·  Mode: ANALYSIS ONLY (no edits/commits)

## Verification environment
- `python` (system) lacks pandas/sklearn. Full deps live in `/tmp/uv` venv (pandas 3.0.3, sklearn 1.9.0, numpy 1.26.4, scipy 1.11.4, pytest 9.0.3).
- The `ueba` package is **not installed** in that venv and there is **no `conftest.py` / no `pythonpath` in pyproject**, so `pytest` from a clean venv FAILS collection with `ModuleNotFoundError: No module named 'ueba'` (8 collection errors). It only passes if `ueba` is importable (editable install, as in root's env, or `PYTHONPATH=src`).
- **Real pytest count (with `PYTHONPATH=src`): `64 passed in ~5.5s`.** The "64 passing" claim is reproducible *only* with the package on the path. See INFRA-1.

## Severity counts
- HIGH: 2
- MEDIUM: 5
- LOW: 4
- CONFIRMED-FINE: notable solid tests listed at end
- NOT-VERIFIABLE: 2

## Severity table

| Title | Sev | Meaningful? | Verified? | One-line RCA |
|-------|-----|-------------|-----------|--------------|
| DATASET-HEALTH-STALE: §2/TL;DR + §6 conclusion contradict shipped config | HIGH | yes | yes (ran) | Report's headline FP/"6 constant features" + "OCSVM stays ~20%" predate gamma=0.01 & contamination=0.01 now in config.yaml |
| DOC-COUNT-16-vs-19: docs say "16 features/columns", CSV exports 19 | HIGH | yes | yes (ran) | `DATASET_COLUMNS` has 19 entries; README/CONTEXT never updated |
| COVERAGE-DAEMON-E2E: no test wires baseline→to_scaled_vector→predict | MED | yes | yes (grep) | `to_scaled_vector`, `emit_alert`, `_severity`, `run()` are 0% tested |
| COVERAGE-THRESHOLD-PARITY: train↔serve AE threshold parity untested | MED | yes | yes (read) | notebook calibrates percentile; daemon default 0.05; no test asserts the written `ae_threshold.json` is consumed |
| DOC-CONFIG-BLOCK: README & CONTEXT still print `contamination: 0.05`/`nu=0.05` | MED | yes | yes (read) | config.yaml is 0.01; doc YAML snippet + prose not updated |
| INFRA-1: suite green depends on editable install / PYTHONPATH not encoded | MED | yes | yes (ran) | no conftest/pythonpath → fresh `pytest` errors on import |
| TAUTOLOGY-OLD-RECOMPUTE: `test_old_recompute_was_not_invariant` proves nothing about current code | MED | partial | yes (read) | asserts behavior of the legacy `add_zscores`, which the daemon no longer uses when baseline present |
| WEAK-UNSEEN-USER: `test_unseen_user_falls_back_to_global` only asserts `isinstance(float)` | LOW | weak | yes (read) | passes even if fallback value is wrong/garbage |
| WEAK-SIMULATE-BOUNDS: range asserts (e.g. sensitive 0<..<0.6) too loose | LOW | weak | yes (ran) | actual 0.335; a regression to 0.59 would still pass |
| OTRF-UNASSERTED-FIELDS: e2e test never asserts bytes_sent/new_ip | LOW | partial | yes (ran) | `bytes_sent=0` (known dead-on-real) and `new_ip=0` go unchecked |
| DOC-DRIFT-MISC: README structure tree, AE seuil text, branch/`16 sections` | LOW | yes | yes (read) | tree lists only `test_features.py`; CONTEXT says AE seuil μ+3σ, "13 sections", "14 tests" |

---

## HIGH findings

### DATASET-HEALTH-STALE — DATASET_HEALTH.md is now STALE vs the improved pipeline
**Audit (evidence).**
- TL;DR (lines 5-9): headline verdict = "**10–20 % de faux positifs**" and "**6 features sur 14 constantes (mortes)**". §2.A table (line 32) and §2.C (lines 56-64) repeat 10%/20%/10% FP.
- §6 (lines 143-154) DOES add a "multi-profil" update table but its only rows are `contamination 0.05` and `0.01` — and it still states, in bold: "**One-Class SVM reste à ~20 % de FP quel que soit `nu`** (sur-ajuste avec `gamma='scale'`)".
- BUT `config/config.yaml:23` now ships `ocsvm_gamma: 0.01` (and `contamination/ocsvm_nu: 0.01`). I reproduced the FP table on `simulate(8 users, 45 days, seed=42)`, 70/30 split:

  | cont | gamma | IF FP | OCSVM FP | Ensemble |
  |------|-------|-------|----------|----------|
  | 0.05 | scale | 4.7% | 26.4% | 4.7% |
  | 0.05 | 0.01  | 4.7% | 8.1%  | 3.4% |
  | 0.01 | scale | 1.4% | 26.4% | 1.4% |
  | **0.01** | **0.01 (shipped)** | **1.4%** | **3.4%** | **0.7%** |

  The shipped config gives **OCSVM FP = 3.4%**, not ~20%. The report's central remaining warning ("SVM reste à ~20%") is FALSE for the configuration the project actually ships. The §6 table omits the gamma=0.01 row entirely, so a reader concludes the SVM is still broken.
**RCA.** The doc was written incrementally (sections appended), and the `ocsvm_gamma` fix landed in config.yaml AFTER §6 was authored. The headline TL;DR was never reconciled with sections 6-7. `test_model_config.py` (which asserts gamma=0.01 and OCSVM FP < 0.12) silently encodes the NEW reality, so code+tests moved on while the doc froze.
**Brainstorm.** (a) Rewrite TL;DR to reflect post-fix numbers; (b) add the gamma=0.01 row to §6 and strike the "reste à ~20%" claim; (c) mark §2 explicitly as "BEFORE — historical, see §6/§7 for current"; (d) regenerate all FP numbers from one script committed alongside.
**Plan (doc-owner).** Replace TL;DR FP figure with measured ensemble ~0.7-1.9%, replace "6/14 constantes" with "0 constantes (générateur multi-profils)", and remove/annotate the stale OCSVM-20% paragraph. Keep §2 as labelled history.

### DOC-COUNT-16-vs-19 — "16 features/columns" is wrong; CSV exports 19
**Audit.** `parse_logs.DATASET_COLUMNS` (parse_logs.py:60-71) has **19** entries (verified at runtime: 19 columns; `otrf` and `simulate` both report "19 colonnes"). simulate adds `label` → 20.
- README.md:140 "exporte **16 colonnes** par session".
- CONTEXT.md:65 "(16 features par session)", §5 title "Les **16** features UEBA extraites" (line 107), line 110 "on calcule 16 features", parse_logs step "calcule les 16 features" (line 190).
The real split: **14** numeric ML features (`NUMERIC_FEATURES`, correct everywhere) + 5 non-ML columns (`timestamp, username, process_name, command_line, session_duration_min`) = 19.
**RCA.** Older revision had 16 CSV columns; `session_duration_min` and others were added without updating the prose. The "16" is a frozen legacy count.
**Brainstorm/Plan.** Change "16 colonnes/features" → "19 colonnes (dont 14 features numériques ML)". Cheap, mechanical; a jury counting the CSV header would catch this instantly.

---

## MEDIUM findings

### COVERAGE-DAEMON-E2E — the serve-path money path is untested
**Audit.** `grep` over `tests/`: no reference to `to_scaled_vector`, `emit_alert`, `_severity`, or `run`. `test_daemon.py` tests `predict()` with hand-built `_Model` stubs and `AlertsWatcher` I/O, but NOTHING exercises: features dict → `apply_baseline_zscores` → `scaler.transform` → `predict` → `emit_alert`. The exact train/serve z-score parity that `baseline.py` exists to fix is never asserted through the daemon's `to_scaled_vector(baseline=...)` branch. `_severity` (HIGH/MEDIUM/LOW logic, daemon.py:247-257) is entirely unverified — a regression flipping HIGH↔LOW would stay green.
**RCA.** Tests target leaf units; the integration seam (`to_scaled_vector`) was skipped because it needs a scaler + baseline fixture.
**Plan.** Add a test: build a baseline from a tiny df, scale a known session, assert the z-scores match `apply_baseline_zscores` output and that `predict` over stub models yields the expected vote; add `_severity` truth-table test.

### COVERAGE-THRESHOLD-PARITY — train↔serve AE threshold parity not protected
**Audit.** `calibrate_ae_threshold` is unit-tested (test_baseline.py:73-94, genuinely good — FP bound and skew-robustness verified). But the *parity* is not: notebook writes `ae_threshold.json` from the calibrated percentile; daemon reads it (daemon.py:101-126) with hardcoded fallback `0.05`. `test_corrupt_ae_threshold_does_not_crash` asserts the fallback `0.05` — i.e. the test pins the *degraded* path, not the *consumed-from-disk* path. No test writes a calibrated value and asserts the daemon uses it. If the notebook key name drifts (`"threshold"`), serve silently falls to 0.05.
**RCA.** Threshold production (notebook) and consumption (daemon) live in different artifacts; no contract test bridges them.
**Plan.** Test that a valid `ae_threshold.json` `{"threshold": X}` is loaded into `UEBAModels.ae_threshold == X`.

### DOC-CONFIG-BLOCK — README & CONTEXT still show contamination 0.05 / nu 0.05
**Audit.** README.md:128 YAML block `contamination: 0.05 # Taux d'anomalies attendu`; CONTEXT.md:143 "`contamination=0.05`", :149 "`nu=0.05`", :298 "Pourquoi `contamination=0.05` ?", :157 AE "Seuil : μ + 3σ". config.yaml ships `0.01/0.01/0.01` and `ae_threshold_percentile: 99.0`. `test_model_config.test_config_has_tuned_detection_values` asserts 0.01 — docs contradict the test.
**Plan.** Update both YAML snippet and prose to 0.01; update AE seuil description to "percentile p99 de validation (repli μ+3σ)".

### INFRA-1 — green depends on an editable install not captured in the repo
**Audit.** No `conftest.py`, no `[tool.pytest.ini_options] pythonpath`. From the deps venv `/tmp/uv`, `pytest -q` → 8 collection ERRORS (`No module named 'ueba'`). With `PYTHONPATH=src` → 64 passed. The advertised "64 passing" is environment-dependent (works only because root previously ran `pip install -e .`).
**RCA.** `src/` layout requires either an editable install or `pythonpath=["src"]`; neither is committed.
**Plan.** Add `pythonpath = ["src"]` to `[tool.pytest.ini_options]` (or a one-line conftest) so the suite is reproducible from a clean checkout. (Owner: not me — flagging.)

### TAUTOLOGY-OLD-RECOMPUTE — a test that protects dead behavior
**Audit.** test_baseline.py:47-52 `test_old_recompute_was_not_invariant` asserts the *legacy* `add_zscores` (population-dependent) gives `z_alone != z_in_batch`. It demonstrates the OLD bug but protects nothing in the current serve path: when a baseline exists, `to_scaled_vector` never calls `add_zscores`. It is a documentation-test, not a guard — it would stay green even if the daemon's baseline branch were deleted.
**RCA.** Written to narrate RC-1, kept as a "test". Not harmful, but it pads the count without protecting current behavior.
**Plan.** Keep it but rename to clarify it's a characterization of the deprecated path; the real protective test is `test_zscore_invariant_to_batch_composition` (which IS meaningful).

---

## LOW findings

### WEAK-UNSEEN-USER
test_baseline.py:54-58 asserts only `isinstance(z, float)`. For a NEW_USER with value 10 and global mean≈10, the fallback z is ~0; the test would pass for ANY finite float, including a wrong fallback. Strengthen by asserting the value equals the global-baseline z.

### WEAK-SIMULATE-BOUNDS
test_simulate.py:30-36 uses loose ranges (`0 < sensitive < 0.6`; actual 0.335). A generator regression that doubled the sensitive rate to 0.59, or halved night activity, would still pass. Tighten to expected ±band around measured values (night≈0.05, weekend≈0.008, sensitive≈0.34, new_ip≈0.04).

### OTRF-UNASSERTED-FIELDS
test_otrf.py:64-75 e2e asserts files/sensitive/failed/processes (all verified correct at runtime) but never `bytes_sent` (=0, the known dead-on-real-Sysmon feature, RC-2) nor `new_ip` (=0). The data-integrity risk the otrf module documents (bytes_sent always 0) is therefore unprotected by assertion. Add `assert row["bytes_sent"] == 0` with a comment so a future "fix" that fabricates bytes is caught.

### DOC-DRIFT-MISC
- README structure tree (lines 63-64) lists only `tests/test_features.py`; there are 8 test files. CONTEXT §11 tree also lists only `tests/test_features.py`.
- CONTEXT.md:223 "**14 tests** unitaires" for test_features.py — actual is 20 tests in that file (verified: `test_features.py ....................` = 20).
- CONTEXT.md:211 "notebook en **13 sections**" and :157 AE "μ + 3σ" — both predate the percentile-calibration change.
- CONTEXT.md:323 "Branche principale : `main`" — fine as a statement, but the working branch is `audit/ueba-system-review`; no drift per se, noted for completeness.
- GCP / 2-VM / Wazuh 4.9.2 infra claims (README §Stack, CONTEXT §1) are consistent across docs and with the systemd/SETUP runbooks — no drift there.

---

## CONFIRMED-FINE (earned green)
- `test_daemon.py::TestAlertsWatcher` — genuinely strong: partial-line hold, restart-resume, rotation (new inode), malformed-skip, and **copytruncate** (lines 153-166) all exercise real `AlertsWatcher` I/O against tmp files and would fail if the watcher regressed. copytruncate is covered.
- `test_daemon.py::TestPredictRobustness` — real value: degraded vote surfaced (`evaluated_models<expected_models`), confidence over voters-not-loaded, no-crash on `_Boom`. Protects RC-4.
- `test_daemon.py::test_daemon_uses_the_shared_constant` + `test_feature_count_is_14` — true train/serve feature-order contract; fails if daemon diverges from `parse_logs.NUMERIC_FEATURES` or count ≠ 14.
- `test_baseline.py::test_zscore_invariant_to_batch_composition` and `TestCalibrateAEThreshold::test_controls_false_positive_rate` — meaningful: the latter asserts `(val>t).mean() <= 0.02` on lognormal errors (real FP bound). Verified passes.
- `test_otrf.py` end-to-end field mapping — verified against a realistic 6-event Sysmon/Security stream; counts (files=2, sensitive=2, failed=1, processes=1) are correct.
- `test_model_config.py` — runs real IF+OCSVM on simulated data and asserts FP/detection bounds with the SHIPPED config values; this is the test that proves the config is tuned (and is the canary the stale doc ignores).
- `test_config.py` — covers empty/comments/missing file + independent-copy (deepcopy) — solid.

## NOT-VERIFIABLE
- DATASET_HEALTH §7 Autoencoder FP table (μ+3σ 9.2% → p99 4.1%): requires TensorFlow (excluded per instructions). Cannot reproduce. The *mechanism* (`calibrate_ae_threshold`) is unit-verified, but the specific AE FP figures are NOT-VERIFIABLE here.
- DATASET_HEALTH §2 "300 normal + 80 attaques, 1 profil" historical run: predates current `simulate.py`; cannot reproduce the old generator (replaced). Treated as labelled history, but the TL;DR promoting those numbers as the current verdict is the STALE finding above.

---

### Bottom line
The 64 green tests are *mostly* earned — the daemon watcher, vote robustness, feature-order contract, baseline invariance and calibration FP-bound are real, meaningful guards. The weak spots are (1) **no end-to-end serve-path test** (`to_scaled_vector`/`_severity`/`emit_alert` untested) and (2) the suite's reproducibility depends on an editable install not captured in-repo. The bigger problem is **docs**: DATASET_HEALTH.md's headline verdict and its OCSVM-20% conclusion are STALE (contradicted by the shipped gamma=0.01 config, FP measured at 3.4%/0.7%), and the "16 features/columns" count is wrong (actual 19). A jury reading DATASET_HEALTH would be told the system has 6 dead features and 10-20% FP that the current code has already fixed.
