# Audit — TESTS + DOCUMENTATION DRIFT

Area: `tests/test_features.py`, `README.md`, `CONTEXT.md`, code comments/docstrings.
Repo: `/home/lina/pfe-ueba-ml`, branch `fix/colab-training-blocker`.
Mode: READ-ONLY static analysis. `pytest` was NOT run — `python3 -c "import numpy,pandas,scipy,pytest"` FAILS (no pandas/numpy in this env), so test execution is left to the orchestrator. All "verified?" claims below are by code reading + arithmetic only.

## STEP 1 — What the docs CLAIM (5-line model)

1. Wazuh on VM1 writes `alerts.json`; `parse_logs.py` turns it into sessions and **"16 features"** per session into `dataset.csv`.
2. A Colab/Jupyter notebook trains 3 unsupervised models (IsolationForest, OneClassSVM, Keras Autoencoder) + a StandardScaler and exports them to `models/`.
3. `daemon.py` tails `alerts.json` in real time, scales the same features, runs the 3 models, votes ≥2/3, and emits alerts to `/var/log/ueba_alerts.json`.
4. Infra is described as **Azure / Ubuntu 24.04 LTS** (2 VMs), branch **main**, repo `assia-xnz/pfe-ueba-ml`.
5. `tests/test_features.py` = **"14 tests"** covering `parse_logs` helpers; docs assert the system is portable via z-scores/entropy.

---

## SEVERITY-RANKED FINDINGS

| # | Title | Sev | Doc-accurate? / Code-safe? | Verified? | One-line RCA |
|---|-------|-----|----------------------------|-----------|--------------|
| 1 | Infra docs say Azure / Ubuntu 24.04; reality is GCP / Ubuntu 22.04 | P0 | NO (doc inaccurate) | Verified (per brief + grep) | Docs never updated after the Azure→GCP migration |
| 2 | "16 features" claim is wrong & internally inconsistent; models use 14 | P0 | NO (doc inaccurate) | Verified (arithmetic) | Feature count copy-pasted, never reconciled with `NUMERIC_FEATURES`/`DATASET_COLUMNS` |
| 3 | ZERO tests for the train/serve feature-order contract (highest data-integrity risk) | P0 | code-safe today, but unprotected | Verified (read) | Test file only touches `parse_logs` helpers |
| 4 | `_make_alert` fixture diverges from real Wazuh login schema (only `targetUserName`, code prefers `subjectUserName`) | P1 | masks parser bug class | Verified (read) | Fixture is a simplified strawman, not a real 4624 event |
| 5 | Banner/simulators hard-code "PFE 2024" / `datetime(2024,...)` in a 2026 project | P1 | cosmetic-to-real mix | Verified (read) | Year hard-coded; jury-visible staleness |
| 6 | ZERO tests for daemon, `predict`/ensemble vote, `to_scaled_vector`, `_severity` | P1 | unprotected | Verified (read) | Coverage stops at feature helpers |
| 7 | Phantom "ml-pipeline" branch (user's mental model) vs actual `main`/`fix/colab-...` | P1 | doc/mental drift | Verified (`git branch`) | Work landed on main, not the imagined branch |
| 8 | README still lists `autoencoder.pkl` framing / "Vote ≥2/3 → models/*.pkl"; AE is `.keras`, not pkl | P2 | partially inaccurate | Verified (read) | Diagram predates the Keras-pickle fix |
| 9 | Tests use tz-aware datetimes; notebook simulators use tz-NAIVE `datetime(2024,...)` | P2 | latent inconsistency | Verified (read) | Two code paths build sessions differently |
| 10 | No test for cold-start z-scores / single-history-row path in daemon | P2 | unprotected edge | Verified (read) | `add_zscores` single-row tested in isolation only |
| 11 | `emit_alert` uses deprecated `datetime.utcnow()` | P3 | code smell | Verified (read) | Pre-3.12 idiom |
| 12 | Unreproducible/absent detection-rate claims | P3 (would be P0 if any were stated) | NONE STATED | Verified (grep) | Docs honestly defer numbers to "à faire" |
| 13 | `test_outlier_has_high_zscore` asserts `> 2.0` but ddof=1 gives z≈1.79 → test FAILS | P1 | test is WRONG | Verified (arithmetic, ddof=1) | Threshold copied for population std; code uses sample std |

---

## PER-ISSUE DETAIL

### 1 — Infra docs: Azure / Ubuntu 24.04 vs GCP / Ubuntu 22.04  (P0)
**Audit:**
- `README.md:17` ASCII diagram header `VM1 — Ubuntu 24.04`.
- `README.md:224-225` Stack table: `Cloud | Microsoft Azure (2 VMs)` and `OS | Ubuntu 24.04 LTS / Windows Server 2022`.
- `CONTEXT.md:16` heading `### Infrastructure Azure (2 VMs)`; `CONTEXT.md:20` table row `VM1 | Ubuntu 24.04`.
- Project brief (authoritative): migrated to **GCP**, **VM1 Ubuntu 22.04**, VM2 Windows Server 2022.
**RCA (FRESH-EYES SKEPTIC / DOCS-WRITER):** The migration Azure→GCP and the OS downgrade 24.04→22.04 happened in infra but the docs were never re-synced. A jury member reading "Microsoft Azure" while the demo runs on GCP is a credibility hit, and "Ubuntu 24.04" is simply false.
**Brainstorm:** (a) Edit both files to GCP / Ubuntu 22.04 — **recommend**. (b) Add a one-line "Infra" note saying "originally Azure, migrated to GCP" to preserve history. (c) Parameterise infra into a single table referenced by both docs to prevent re-drift.
**Plan:** Replace the 4 strings (README:17, README:224-225, CONTEXT:16, CONTEXT:20). Verify: `grep -ri "azure\|24.04" README.md CONTEXT.md` returns nothing.

### 2 — "16 features" is wrong and internally inconsistent; models use 14  (P0)
**Audit:**
- `README.md:138` heading "## Features UEBA (16 features)"; `CONTEXT.md:105` "## 5. Les 16 features UEBA extraites"; `CONTEXT.md:64` "(16 features par session)".
- Reality (`parse_logs.py:57-68`): `DATASET_COLUMNS` = 19 cols → minus `timestamp`+`username` = **17 feature columns** exported.
- Model input (`daemon.py:63-71` and notebook cell 10/16): `NUMERIC_FEATURES` = **14**.
- The 3 exported-but-not-modelled columns: `process_name`, `command_line` (text), `session_duration_min`.
- README's own 16-row table is inconsistent with itself: it lists `process_name`/`command_line` as "features" (text, never fed to the model) and OMITS `session_duration_min` (which IS exported).
**RCA (ARCHITECT / DATA-INTEGRITY):** Three different counts (14 numeric / 16 claimed / 17 exported) coexist. The "16" is a stale headline that matches neither the CSV schema nor the model contract.
**Brainstorm:** (a) Restate as "17 columns exported per session; **14 numeric features** consumed by the models (3 text/meta columns are exported for triage but not modelled)" — **recommend**. (b) Just change 16→14 (simpler but loses the export/model distinction). (c) Generate the feature table from `DATASET_COLUMNS`/`NUMERIC_FEATURES` to keep docs honest.
**Plan:** Fix README:138 + table, CONTEXT:64/105/108. Verify against `len(NUMERIC_FEATURES)==14` and `len(DATASET_COLUMNS)-2==17`.

### 3 — No test for the train/serve feature-order contract  (P0 coverage gap)
**Audit:** Train side builds `X` via `df_normal[NUMERIC_FEATURES]` (notebook cell 16). Serve side builds the vector via `daemon.py:190` `np.array([... for f in NUMERIC_FEATURES])`. These two `NUMERIC_FEATURES` lists are **defined independently** (notebook cell 10 vs `daemon.py:63`). I verified by reading that today they are identical (same 14 names, same order). But there is **no test** asserting this — if anyone edits one list, the scaler/models silently receive mis-ordered columns and predictions become garbage with no error.
**RCA (DATA-INTEGRITY):** The single most important correctness invariant of the whole ML system (column order = scaler/model training order) is enforced only by manual copy-paste discipline across two files, and is untested.
**Brainstorm:** (a) Import `NUMERIC_FEATURES` from one source of truth (e.g. `parse_logs`/a constants module) into both daemon and notebook, then test equality — **recommend**. (b) Persist the feature-name list alongside the scaler (`models/feature_order.json`) and assert it at daemon load. (c) Add a test that scales the same row two ways and compares.
**Plan:** Add `test_feature_order_contract` asserting `daemon.NUMERIC_FEATURES == <single source>` and `len==14`; ideally also assert it equals the scaler's `n_features_in_`. Verify: test fails if either list is reordered.

### 4 — `_make_alert` fixture diverges from real Wazuh schema  (P1 test-correctness)
**Audit:** `tests/test_features.py:27-52`. The fixture only sets `eventdata.targetUserName`. But `extract_raw_fields` (`parse_logs.py:149-155`) resolves username as `subjectUserName` **first**, then `targetUserName`. On a real Windows 4624/4625 event BOTH fields exist and differ (`subjectUserName` = who initiated, often `SYSTEM`/the auth source; `targetUserName` = the account). The test `test_username_lowercased` passes only because `subjectUserName` is absent in the fixture, so the code falls through to `targetUserName`. A real event would exercise the `subjectUserName` branch, which **no test covers**. Likewise `event_id` is read from `data.win.system.eventID` (`parse_logs.py:139,143`) — the fixture matches that key, good — but there is no test for the Sysmon-shape or the `data.id` fallback (`parse_logs.py:145`).
**RCA (DATA-INTEGRITY / FRESH-EYES):** The fixture is a simplified strawman, so the tests validate the parser against a shape the parser will rarely see in production, masking the realistic "which username wins" bug class.
**Brainstorm:** (a) Add a realistic 4624 fixture with BOTH `subjectUserName` and `targetUserName` and assert which one is chosen — **recommend** (also forces a product decision on which is correct). (b) Add a Sysmon-shaped fixture (eventID "1"/"3") to cover the process/network branches. (c) Capture one redacted real `alerts.json` line as a golden fixture.
**Plan:** Add `test_subject_username_preferred` + a Sysmon process fixture. Verify event_id extraction and process_name/command_line capture in `_update_session`.

### 5 — Hard-coded 2024 dates / "PFE 2024"  (P1, jury-visible)
**Audit:** `daemon.py:312` banner `"... PFE 2024"`. Notebook simulators default `base_date = datetime(2024, 1, 15, ...)` (cells 7, 31). Code comments/docstrings say "Auteur : Assia — PFE Cires...". Current date 2026-06-04.
**Correctness check:** The date logic that MATTERS (`is_night` from `hour`, `is_weekend` from `weekday()`, z-scores, velocity) does **not** depend on the absolute year — `datetime(2024,1,15)` is a Monday and the simulators add weekday offsets, so weekend/night flags are still internally consistent. So the 2024 base date is **cosmetic for model correctness**. The "PFE 2024" banner is purely cosmetic but **embarrassing in a 2026 defense**.
**RCA (FRESH-EYES SKEPTIC):** Stale year strings make the project look unmaintained; not a functional bug.
**Brainstorm:** (a) Change banner to "PFE 2025/2026" and leave simulator base dates (they're arbitrary) — **recommend**. (b) Make simulator `base_date` default to `datetime.now()` for realism. (c) Leave as-is and note it's cosmetic.
**Plan:** Edit `daemon.py:312`. Verify: `grep -rn "2024" src/` shows only intentional refs.

### 6 — No tests for daemon / predict / ensemble / to_scaled_vector / _severity  (P1 coverage)
**Audit:** `tests/` imports only from `parse_logs`. Untested high-risk behaviors:
- `predict` vote tallying & the `>= threshold_votes` boundary (`daemon.py:124-174`) — e.g. with only 2 models loaded, `is_anomaly` uses `votes>=2` while `confidence=votes/nb_models`; the degraded-model path is untested.
- `_severity` escalation logic (`daemon.py:197-207`): HIGH requires `nb_failed_logins>=5`, but `_make_alert`/README brute-force narrative implies a different threshold; untested.
- `to_scaled_vector` (`daemon.py:180-191`) cold-start (empty `df_history`) and the `float(... or 0)` NaN-guard — untested.
- `AlertsWatcher` logrotate/inode-rotation path (`daemon.py:266-290`) — untested.
**RCA (DATA-INTEGRITY / ARCHITECT):** The entire serving path (the part graded as "the system works") has 0% test coverage.
**Brainstorm:** (a) Add unit tests with stub models (objects exposing `.predict`/`.decision_function`) to test `predict` vote math and `_severity` boundaries — **recommend**. (b) Integration test feeding a tiny `alerts.json` through `extract→group→build→to_scaled_vector` with a fitted dummy scaler. (c) Defer (accept risk) — not advisable for a defended project.
**Plan:** Add `tests/test_daemon.py`: vote boundary (2 vs 3 models), `_severity` HIGH/MEDIUM/LOW, cold-start vector. Verify thresholds match README/CONTEXT severity table.

### 7 — Phantom "ml-pipeline" branch  (P1 drift)
**Audit:** `git branch -a` → `main`, `fix/colab-training-blocker`, `origin/main`. No `ml-pipeline` anywhere. CONTEXT.md:321 / README assume `main`. The user's mental model references a non-existent `ml-pipeline` branch.
**RCA (IT-OPERATOR):** Mismatch between the user's mental branch and reality; anyone following the user's instructions to "check ml-pipeline" finds nothing.
**Brainstorm:** (a) Document explicitly in CONTEXT.md that all ML work lives on `main` (and the current WIP on `fix/colab-training-blocker`), no `ml-pipeline` — **recommend**. (b) Create an `ml-pipeline` branch pointer to satisfy the mental model (not recommended — adds confusion). 
**Plan:** Add a "Branches" note to CONTEXT.md §11. Verify: `git branch -a`.

### 8 — README diagram/AE references predate the Keras-pickle fix  (P2)
**Audit:** `README.md:32` "Vote ≥ 2/3 → models/*.pkl" implies all models are pkl. `README.md:160` correctly lists `autoencoder.keras` (good), but the "Workflow" in CONTEXT.md:271 `scp models/autoencoder.keras` is correct while README's diagram glob `*.pkl` is misleading. The daemon (`daemon.py:94-113`) and notebook (cell 26) confirm AE is saved/loaded as `.keras`, never pickled — comment at `daemon.py:95-97` and notebook explicitly say so. So no live `autoencoder.pkl` reference remains, but the `*.pkl` shorthand in the README diagram is inaccurate now that one of three models is not a pkl.
**RCA (DOCS-WRITER):** Diagram shorthand `*.pkl` was written when AE was (incorrectly) pickled; the fix corrected code+CONTEXT workflow but not the README diagram.
**Brainstorm:** (a) Change diagram line to "→ models/ (.pkl + .keras)" — **recommend**. (b) Leave (low impact). 
**Plan:** Edit README:32. Verify: no remaining claim that AE is a pkl.

### 9 — tz-aware tests vs tz-naive simulators  (P2)
**Audit:** Tests use `datetime(..., tzinfo=timezone.utc)` and `fromisoformat(...+00:00)` (tz-aware), matching `extract_raw_fields` which produces tz-aware ts (`parse_logs.py:132`). But the notebook simulators build sessions from tz-NAIVE `datetime(2024,1,15)` (cells 7/31). `build_features` only uses `.hour`/`.weekday()`/subtraction, all tz-agnostic, so it works on both — but the two data-generation paths are inconsistent, and any future code that compares real (aware) vs simulated (naive) timestamps would raise `TypeError: can't subtract offset-naive and offset-aware`.
**RCA (DATA-INTEGRITY):** Latent landmine; harmless today because no cross-path datetime arithmetic happens.
**Brainstorm:** (a) Make simulators tz-aware (`tzinfo=timezone.utc`) to match the parser — **recommend**. (b) Add a test asserting `build_features` is tz-safe both ways. 
**Plan:** Edit simulator base dates; add note. Verify: subtraction across paths doesn't raise.

### 10 — No cold-start / single-history-row z-score test in the serving path  (P2)
**Audit:** `add_zscores` single-row→0 is tested in isolation (`test_features.py:206-213`). But the daemon's real cold-start (`to_scaled_vector` with empty `df_history`, `daemon.py:187`) concatenates one row and computes z-scores on n=1 → 0, then scales. This whole path is untested; a regression in `to_scaled_vector` (e.g. NaN leaking from z-scores) would silently produce wrong vectors.
**RCA (DATA-INTEGRITY):** The unit test proves the helper, not the integration that actually runs at daemon startup.
**Brainstorm:** (a) Test `to_scaled_vector` with empty history + a fitted dummy scaler asserting finite, length-14 output — **recommend**. (b) Add a NaN-guard assertion.
**Plan:** In `tests/test_daemon.py`, add cold-start vector test. Verify: output has no NaN, len 14.

### 11 — Deprecated `datetime.utcnow()`  (P3)
**Audit:** `daemon.py:213` `datetime.utcnow().isoformat() + "Z"`. Deprecated since 3.12; should be `datetime.now(timezone.utc)`. Cosmetic but will emit warnings on 3.12+ (project targets 3.10+).
**Brainstorm:** (a) Switch to `datetime.now(timezone.utc)` — **recommend**. (b) Suppress warning. 
**Plan:** Edit line, ensure trailing "Z" handling stays valid.

### 12 — No unreproducible detection-rate claims (good)  (P3 / would be P0 if violated)
**Audit:** Grepped README/CONTEXT for accuracy/precision/recall/F1/"taux de détection" with numbers. CONTEXT.md:309 explicitly lists "measure real detection rates" under §10 "Ce qui reste à faire". No fabricated metrics found. This is the correct, defensible posture.
**Note:** If the student later adds a results table to the report, it MUST be reproducible from the notebook — currently the notebook only shows synthetic-data anomaly rates, not validated detection metrics.

---

## CONFIRMED FINE
- **Train/serve `NUMERIC_FEATURES` lists are currently identical** (daemon.py:63-71 vs notebook cell 10/16): same 14 names, same order. Contract holds *today* (but see Finding 3 — untested).
- **Pytest will collect & imports resolve** (statically): `pyproject.toml:65-67` sets `testpaths=["tests"]`; imports in `test_features.py:12-20` (`_entropy, add_zscores, build_features, extract_raw_fields, group_by_session, _new_session, _update_session`) all exist in `parse_logs.py`. No missing symbols. (Not executed — pandas absent in this env.)
- **`_entropy` tests are correct:** empty/single→0.0 (matches `parse_logs.py:241`), uniform 4-way → log2(4)=2.0 (`test:174-177`), skewed<uniform (`test:179-182`) — all mathematically sound.
- (z-score outlier test is NOT fine — moved to Finding 13 below.)
- **Sessionization gap test** (`test:104-110`): 2h01 gap > 60min → 2 sessions; matches `group_by_session` logic (`parse_logs.py:188-189`). Correct.
- **Two-users test** (`test:112-120`): correct, matches per-(user,ts) sort + user-change split.
- **`_make_alert` event_id path** matches `data.win.system.eventID` read order — the eventID plumbing itself is fine.
- **No live `autoencoder.pkl` reference** in code; AE is `.keras` end-to-end (daemon + notebook consistent). The pickle fix is real.
- **README install/run steps are executable in principle:** `pip install -e .` (pyproject is valid), `make export-dataset/run-daemon/test` targets all exist (Makefile:29-46) and invoke real module paths. Entry points `ueba-export`/`ueba-daemon` map to real `main()` functions.

### 13 — `test_outlier_has_high_zscore` is WRONG: asserts `> 2.0`, actual z ≈ 1.79  (P1 test-correctness)
**Audit:** `tests/test_features.py:202-204`. Data `[10,12,8,11,100]`. The helper uses `stats.zscore(x, ddof=1)` (**sample** std, `parse_logs.py:297`). Hand-computed (Python, exact): mean=28.2; ddof=1 std=40.165 → z(100)=**1.788**; ddof=0 std=35.924 → z(100)=1.999. The assertion `df["z_score_files"].iloc[-1] > 2.0` therefore **fails** under the ddof=1 the code actually uses (it would only ~pass with population std, and even then borderline at 1.999 < 2.0).
**RCA (DATA-INTEGRITY):** The `> 2.0` threshold was written assuming population std / a "2 sigma" rule of thumb, but the implementation uses sample std (ddof=1) on n=5, which inflates the denominator and drops the z below 2. Classic test/impl mismatch — the one test meant to prove outlier detection works does not.
**Brainstorm:** (a) Lower the assertion to `> 1.5` (robust to ddof, still proves the outlier is flagged) — **recommend**. (b) Make the outlier larger (e.g. 1000) so z clears 2.0 under ddof=1. (c) Assert relative: outlier's z is the max and ≫ the others. 
**Plan:** Change threshold to `> 1.5` OR bump outlier value; re-run. Verify: `python3 -m pytest tests/test_features.py::TestAddZscores::test_outlier_has_high_zscore -q`.
**ORCHESTRATOR: please confirm by running** the above; my arithmetic (no scipy in audit env) says it currently FAILS.

---

## NOT VERIFIABLE (without execution / external info)
- Whether the full `pytest` suite passes (pandas/numpy/scipy not importable in this audit env — orchestrator must run). Highest-priority single check: the z-score outlier test above.
- Whether `make train` (nbconvert execute) runs end-to-end on Colab (needs TF 2.16 + GPU/CPU runtime; notebook not executed here).
- Whether the GitHub repo `assia-xnz/pfe-ueba-ml` exists / is current (no network used).
- Real Wazuh `alerts.json` field shapes for 4624/Sysmon (fixture realism in Finding 4 is inferred from Wazuh schema knowledge, not from a captured sample in-repo).
- Actual detection rates (none claimed; nothing to reproduce — see Finding 12).
