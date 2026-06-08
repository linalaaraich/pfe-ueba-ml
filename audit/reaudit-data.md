# Re-Audit (Round 2) — DATA GENERATION & ADAPTERS

Scope: `src/ueba/features/simulate.py`, `otrf.py`, `health.py` + their tests.
Method: line-by-line + Architect / ML-pipeline / Adversary / Data-integrity / Fresh-eyes lenses.
Env: numpy/scipy importable; **pandas NOT importable** here → dataframe behaviours reasoned analytically, hour/entropy/separability maths verified numerically with numpy.
Source-of-truth contract = `parse_logs.py` (`DATASET_COLUMNS`, `NUMERIC_FEATURES`, `build_features` semantics), `baseline.py` (frozen z-scores, ddof=0), and the notebook `USE_REAL_DATA` path.

## 5-line mental model
1. `simulate.py` → multi-profile **normal** baseline CSV (`label=0`), z-scores via frozen baseline (ddof=0). Replaces the old constant-feature synthetic.
2. `otrf.py` → adapts flat OTRF/Mordor Sysmon JSON into the same raw-event dict as `parse_logs.extract_raw_fields`, then reuses sessions→features→z-scores. Output is an **unlabeled** features CSV.
3. `health.py` → dataset diagnostic (dead/constant/near-constant/NaN/dups/correlation/separability + verdict text).
4. Notebook `USE_REAL_DATA=True` loads `data/dataset.csv` as `df_normal` only (defaults `label=0`), **recomputes z-scores via `compute_baseline`/`apply_baseline_zscores`**, attacks still come from inline synthetic generators (cells 33). OTRF is *not* wired in as labeled attacks.
5. Daemon consumes `NUMERIC_FEATURES` positionally with the frozen `baseline.json`.

## Severity summary
- P0: 0
- P1: 1
- P2: 4
- P3: 4

## Top severity-ranked findings

| # | Title | Sev | code-safe? | valid-data? | one-line RCA |
|---|-------|-----|------------|-------------|--------------|
| 1 | `health` trivial-separability uses all-data std → structurally blind to binary perfectly-separating features (the exact RC-2 signal) | P1 | yes | **no** (false "all-clear") | wrong denominator (between-class variance in std) defeats the RC-2 guard |
| 2 | OTRF output has **no `label`**; notebook treats whole CSV as normal → attack captures silently trained as baseline | P2 | yes | **no** | missing label contract + no labeling path; docs say OTRF is attack-oriented |
| 3 | OTRF uses `add_zscores` (ddof=1) while frozen-baseline contract = ddof=0; CSV z-scores inconsistent (and silently overwritten by notebook) | P2 | yes | partial | adapter predates frozen-baseline refactor; cosmetic-but-misleading divergence |
| 4 | `simulate` hour-branches crash / go constant under non-default work-hours config | P2 | **no** (IndexError) | no | `rng.choice([])` when night-list empty; inverted clamp when `END<=START` |
| 5 | `health.separation_sigma` denominator understates separation for ALL features (not just binary) → "trivial" threshold rarely trips | P2 | yes | no | same pooled-all-std defect as #1, continuous case |
| 6 | OTRF `_get_ci` is flat-only → nested/winlogbeat OTRF exports yield silent empty features | P3 | yes | partial | top-level lowercase map only; no nested traversal |
| 7 | `simulate` tiny-n / few-days / single-profile → constant features (is_weekend, is_night, new_ip, sensitive) | P3 | yes | no (only tiny configs) | low role probabilities + <6 days has no weekend; round-robin misses profiles when n_users<5 |
| 8 | OTRF `bytes_sent` hard-coded 0 → dead feature in every OTRF dataset | P3 | yes | partial | Sysmon EID3 carries no byte counter (known RC-2); acceptable but undocumented in-CSV |
| 9 | `simulate` velocity tail: `gauss(45,25)` clamped to 1.0 min → rare huge velocity outliers in "normal" | P3 | yes | minor | unbounded-low duration inflates `nb_files/duration` |

---

## Finding 1 — health trivial-separability blind to binary separators (P1)

**Audit** (`health.py:96-105`):
```python
sd = col.std(ddof=0) or 1.0
sep.append({"feature": f, "separation_sigma": round(abs(mu_a - mu_n) / sd, 2)})
...
trivial = [s for s in sep if s["separation_sigma"] > 3.0]
```
`sd` is the std over the **whole column** (normal ∪ attack), so when classes are far apart the between-class spread is *inside* the denominator. Verified numerically:
- Perfect binary separator (normal all 0, attack all 1): max `separation_sigma ≈ 2.0` (≈2.68 at the test's 200/40 imbalance) — **mathematically can never exceed ~3**.
- Test fixture `nb_files_accessed` [5,6,7,5] vs [300,280,310,290]: all-data std → `sep≈1.997` (< 3), whereas within-class pooled std → `≈36`.

DATASET_HEALTH.md §B states attacks separate "surtout via `new_ip`, `is_night`" — exactly the binary features this metric structurally cannot flag. So the RC-2 guard reports "no trivial separability" on precisely the trivially-separable datasets it exists to catch. `test_separability_reported_with_labels` only asserts the top-feature *ordering* (ranking is monotone, so it survives) — it never checks the sigma value, so the defect is untested.

**RCA**: *wrong-denominator / pooled-variance error*. Standardizing by total std (which grows with the mean gap) instead of within-class (pooled) std collapses the effect size.

**Brainstorm**:
1. (recommend) Use pooled within-class std (Cohen's d): `sd = sqrt((var_n+var_a)/2)`; keep `or 1.0` guard. Optionally drop the σ framing for binary features and use rate-difference / AUC instead.
2. Use a non-parametric separability (point-biserial corr or per-feature ROC-AUC) — robust to binary/heavy-tail, threshold e.g. AUC>0.95.
3. Lower the "trivial" threshold AND switch denominator — threshold alone won't fix the binary ceiling.

**Plan**:
- Change denominator to within-class pooled std in `audit_dataframe`.
- Add a test asserting a 0/1 perfect separator is flagged `trivially_separable`.
- Verify: re-run health on a labeled simulate+attack set; `new_ip`/`is_night` should now appear in `trivially_separable_features`.

## Finding 2 — OTRF produces no label; whole CSV consumed as normal (P2, valid-data)

**Audit** (`otrf.py:133-151` produces only `DATASET_COLUMNS`, no `label`; notebook cell 8: `if 'label' not in df_normal.columns: df_normal['label'] = 0`; docstrings `simulate.py:23-24`, `otrf.py` claim "attacks come from OTRF / baseline + real attacks combined"). The notebook attack set (cell 33) is still inline `simulate_insider_threat_session`/`simulate_malware_session`; there is no code path that loads an OTRF attack capture as `label>0`.

**RCA**: *missing-contract / dead-promise*. OTRF emits unlabeled features; the only consumer assumes label=0. Running `otrf.py` on an ATT&CK attack dataset and pointing `dataset.csv` at it trains attacks AS baseline (poisons the normal model and inflates "100% detection" artifact, the very RC-2 problem).

**Brainstorm**:
1. (recommend) Add `--label N` (default 0) CLI flag to `otrf.py` and emit a `label` column; document "attack captures → `--label 1`". Cheap, makes intent explicit.
2. Provide a small "combine" helper/notebook cell that loads normal (simulate) + OTRF-attack (labeled) into `df_test`.
3. At minimum, fix the docstrings to stop claiming OTRF attacks are auto-combined.

**Plan**: add label flag + column; update docstrings + DATA_AND_DEMO_SETUP §1.3; test that `--label 1` yields `label==1`. Verify: `health --label label` shows two classes.

## Finding 3 — OTRF z-scores use ddof=1, contradicting frozen-baseline ddof=0 (P2)

**Audit** (`otrf.py:145` `df = add_zscores(df)` → `parse_logs.add_zscores` uses `stats.zscore(..., ddof=1)`; `baseline.py:51,56` frozen baseline uses `std(ddof=0)`; `simulate.py:192` correctly uses `apply_baseline_zscores(df, compute_baseline(df))`).

So `simulate.py` and `otrf.py` write **different** `z_score_*` for identical inputs, and both differ from what the daemon serves (frozen ddof=0). Mitigant: notebook cell 11 recomputes z-scores from `compute_baseline(df_normal)` regardless, so the CSV's z-scores are overwritten before training → not a live train/serve skew today. But it is a latent footgun: any consumer that trusts the CSV z-scores (or a future path that skips recompute) gets inconsistent values, and `otrf.py` diverges from the stated "single source" invariant.

**RCA**: *refactor lag* — `otrf.py` was not migrated to the frozen baseline when `simulate.py`/daemon were.

**Brainstorm**:
1. (recommend) Make `otrf.py` mirror `simulate.py`: `apply_baseline_zscores(df, compute_baseline(df))`.
2. Drop z-score columns from both writers entirely (notebook recomputes anyway) and document that the CSV is "pre-zscore".

**Plan**: swap to baseline z-scores in `parse_otrf_to_dataframe`; verify ddof=0 numerically on the test events.

## Finding 4 — simulate hour logic crashes / degenerates on non-default work hours (P2, code-safe NO)

**Audit** (`simulate.py:114-120`):
```python
hour = rng.choice([h for h in range(24) if h < WORK_HOUR_START or h >= WORK_HOUR_END])  # 116-117
lo, hi = WORK_HOUR_START, WORK_HOUR_END - 1                                              # 119
hour = min(hi, max(lo, int(rng.gauss((lo + hi) / 2, 2))))                                # 120
```
`WORK_HOUR_START`/`WORK_HOUR_END` come from `config.yaml` (parse_logs:44-46). Edge configs:
- `start=0, end=24` (24h ops) → night-list empty → `rng.choice([])` raises **IndexError** (verified empty list).
- `end <= start` (misconfig) → `lo>hi` → clamp inverts, `hour` pinned to `hi` → constant hour → constant `is_night`.
Default 9/18 is safe (night-list len 15).

**RCA**: *unvalidated config boundary* — assumes a proper-subset work window.

**Brainstorm**:
1. (recommend) Guard: if night-list empty, force daytime branch; assert/clamp `start < end` at module load with a clear error.
2. Fall back to a fixed reasonable window when config is degenerate.

**Plan**: add guards in `simulate_session`; verify with `WORK_HOUR_START=0,END=24` and `START=10,END=10`.

## Finding 5 — separation_sigma understates separation for continuous features too (P2)

Same root as #1 but the continuous case (verified: fixture gives 1.997σ). The `separability_top` ranking is still monotone/usable, but the `>3.0` "trivial" flag and the verdict line almost never fire → the RC-2 warning is effectively dormant. Fixed by the same denominator change as #1; listed separately because it affects the reported numbers users read, not just the boolean flag.

## Finding 6 — OTRF `_get_ci` is flat-only (P3)

**Audit** (`otrf.py:47-55`): builds `{k.lower(): v}` over **top-level** keys only. Real OTRF Security-Datasets host files are mostly flat capitalized Sysmon keys (the common case works — tests cover it), but winlogbeat/ELK-shipped variants nest under `Event.System.EventID` / `winlog.event_data.*`. For those, every `_get_ci` returns `None` → `event_id=""`, `username="unknown"`, empty paths → sessions still build but features are garbage/empty. Failure is **silent** (no warning, just sparse output). Docstring/docs acknowledge "flat" and point to the health tool, which softens severity.

**Brainstorm**:
1. (recommend) Add a shallow nested-fallback: also flatten one level of `Event`/`winlog`/`data.win.eventdata` before lookup.
2. Emit a `[WARN]` when >X% of records yield `event_id==""` so silent-empty becomes visible.

**Plan**: extend `_get_ci` or pre-flatten; add a nested-format test; verify the WARN fires on an all-empty extraction.

## Finding 7 — simulate constant features on tiny/short/single-profile configs (P3)

**Audit** (`simulate.py:172` `roles[i % len(roles)]`; `:175-186` weekend gating). With `n_users<5` not all profiles appear; with `days<6` from the Monday default start there is **no weekend** → `is_weekend` constant 0 (verified for days=2); with 1 low-activity profile (`bureau`: p_night .03, p_sensitive .05, p_new_ip .04) and few sessions, `is_night`/`new_ip`/`sensitive_path_access` can all be 0 → constant. The headline tests use 8 users / 30 days where this never triggers, so it's a caveat not a default-path bug.

**Brainstorm**: (recommend) document minimum recommended config (≥days to cover a weekend, ≥5 users) and/or warn when generated set has constant numeric features (reuse `health.audit_dataframe`). Alternatively guarantee ≥1 weekend by extending span.

**Plan**: add a post-generation `audit_dataframe` warning in `main()`; verify tiny config emits the warning.

## Finding 8 — OTRF bytes_sent hard 0 → dead feature (P3)

`otrf.py:96-98` sets `bytes_sent=0` (documented RC-2: Sysmon EID3 has no byte counter). Correct given the data, but every OTRF dataset then carries a guaranteed dead feature into training (notebook zeros it, models down-weight). Acceptable; recommend a one-line stderr note when running OTRF so users know to drop/re-source it. Health tool already flags it.

## Finding 9 — simulate velocity low-duration tail (P3)

`simulate.py:125` `duration = max(1.0, rng.gauss(45,25))`. Lower clamp at 1.0 min with up to ~40 files → `velocity` up to ~40, a fat right tail inside "normal". Not wrong (real short bursts exist) but can let normal velocity overlap attack velocity and/or create outliers the AE/IF flag → contributes to residual FP. Consider a softer floor (e.g. 5 min) or clamping velocity. Low priority.

---

## CONFIRMED-FINE (verified, do not re-flag)
- **is_night derived from hour, canonical rule** (`simulate.py:121`) — matches `parse_logs.build_features:343` exactly; verified daytime branch (hours clamped 9..17) can never yield is_night=1, night branch always does. Test `test_is_night_derived_from_hour` is a genuine contract test.
- **Column / dtype contract** — `simulate_dataset` emits every `DATASET_COLUMNS` entry + `label`; `apply_baseline_zscores` adds `z_score_files/logins`; all 14 `NUMERIC_FEATURES` and the notebook `required_cols` present (verified by set-diff). Column order follows `DATASET_COLUMNS`.
- **WORK_HOUR_START/END imported from parse_logs** (`simulate.py:39-44`) → simulate stays in sync with config (within the boundary caveat of Finding 4).
- **Determinism / seeding** — single seeded `random.Random(seed)` threaded through; no global `random`/`np.random` use; rounding deterministic → `test_reproducible_with_seed` (`a.equals(b)`) holds.
- **simulate label honesty** — every row `label=0`; the simulator only claims to produce normal. (The dishonesty risk is in OTRF, Finding 2, not here.)
- **OTRF flat field mapping (common case)** — `EventID/event_id/Id`, `Image/NewProcessName/ProcessName`, `TargetFilename/ObjectName`, `SubjectUserName/TargetUserName/User/AccountName`, `IpAddress/SourceIp`, `DestinationIp`; case-insensitive; `DOMAIN\user` split + lowercase. Matches `extract_raw_fields` output keys; tests exercise EID 1/11/4663/4624/4625/3.
- **OTRF UtcTime handling** (`otrf.py:58-63`) — `"YYYY-MM-DD HH:MM:SS.mmm"` → first space→`T`, then `_parse_timestamp` (3.10-safe strptime fallbacks). Verified test `test_utctime_format_parsed`.
- **OTRF robustness** — non-dict→None, missing timestamp→None, gzip via suffix, JSON-array vs NDJSON, empty file→[]; per-line JSON errors warned not fatal.
- **health empty/tiny guards** — `if n else 0.0` on mean/min/max/std/nonzero/nan; `duplicated` guarded by `if features and n`; corr guarded `len>=2 and n>=3`; separability guarded by both classes present; std `or 1.0`. No division-by-zero or KeyError in `verdict` (`rep["n_rows"]` always set, rest via `.get`).
- **health constant/near-constant/dead** logic correct (`nunique<=1` constant; `std<1e-9` near-constant; `nunique<=1 or nonzero==0` dead). Test covers it.
- **baseline z-score division guard** (`baseline.py:67`) — std<=0 → z=0.

## NOT-VERIFIABLE here (no pandas / no TF / no live data)
- Actual end-to-end FP/detection numbers in DATASET_HEALTH.md §6/§7 (require TensorFlow + full notebook run). Reasoned plausible; not re-executed.
- Whether real downloaded OTRF datasets are flat vs nested in the user's specific captures (Finding 6 severity depends on this).
- `df.equals` byte-exact reproducibility across pandas versions (logic is deterministic; pandas dtype inference not runnable here).
- Whether lowered contamination/nu (0.01) + realistic normal "overshoots into missing attacks" — needs the model run; analytically the binary attack signals (new_ip/is_night) remain strong, so missed-attack risk is low, but unverified here.
