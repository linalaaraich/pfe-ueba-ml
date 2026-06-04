# Audit — Integration Daemon + Config

**Area:** `src/ueba/integration/daemon.py`, `src/ueba/config.py`, `config/config.yaml`
**Branch:** `fix/colab-training-blocker`
**Date:** 2026-06-04
**Scope:** ANALYSIS ONLY. No edits. Daemon runs on GCP VM1 (not reachable) — live behaviors marked **NOT VERIFIABLE WITHOUT VM**.

## Mental model (5 lines)
1. `run()` polls `alerts.json` every `poll_seconds` via `AlertsWatcher` (tail-f with inode rotation handling).
2. New raw events → `group_by_session` → `build_features` (from `parse_logs`) → `to_scaled_vector` (recompute z-scores over rolling `df_history`, then `scaler.transform`).
3. `predict()` runs IsolationForest + OneClassSVM + Keras AE, majority vote ≥2/3 → `is_anomaly`.
4. Anomalies → `emit_alert` appends JSON line to `/var/log/ueba_alerts.json`.
5. **Contracts:** (a) daemon `NUMERIC_FEATURES` order MUST equal notebook cell-10 order (scaler/models are positional); (b) z-scores at serve time must be statistically comparable to training (`add_zscores`, per-username, ≥2 sessions); (c) AE loaded as native `.keras`, `predict()` returns reconstructions.

## Verified contracts
- **Feature order: MATCH.** Daemon `NUMERIC_FEATURES` (daemon.py:63–71) is byte-identical in names AND order to notebook cell 10 `NUMERIC_FEATURES`. Training matrix `X_normal = df_normal[NUMERIC_FEATURES]` (cell 16) ⇒ scaler/IF/OCSVM/AE all trained in this exact column order. **CONFIRMED FINE.**
- **AE load fix: CORRECT.** `_load_autoencoder` (daemon.py:94–113) loads `autoencoder.keras` via `keras.models.load_model`, never pickle — matches notebook cell 26 `autoencoder.save('.keras')`. `predict()` (daemon.py:155–156) calls `models.autoencoder.predict(X, verbose=0)` and computes `np.mean((X-recon)^2)`; notebook uses `np.mean(..., axis=1)` per row — **mathematically identical for a single (1,N) row**. Threshold read from `ae_threshold.json` key `"threshold"` matches notebook cell 26 dump. **CONFIRMED FINE** (code-safe; live load NOT VERIFIABLE WITHOUT VM but logic correct).

---

## Severity-ranked findings

| # | Title | Severity | Code-safe? | Runs-for-real? | One-line RCA |
|---|-------|----------|-----------|----------------|--------------|
| 1 | Cold-start z-scores meaningless; baseline never persisted across restarts | **P0** | yes (no crash) | predictions silently wrong | `df_history` starts empty every boot; per-user z-score needs ≥2 sessions, else 0 / ±0.707 — train/serve skew |
| 2 | `seek(0,2)` on open skips alerts that arrived while daemon was down | **P1** | yes | misses real anomalies | initial seek-to-end + no persisted pos = data gap on every restart/crash |
| 3 | Per-username z-score in rolling buffer ≠ training distribution | **P1** | yes | predictions skewed | history mixes all users; a user's first-ever session always gets z=0; ddof=1 on 2 samples gives ±0.707 regardless of magnitude |
| 4 | `predict` swallows AE exceptions but lowers `nb_models` denominator inconsistently | **P1** | yes | confidence/vote distortion | AE crash → caught, `result["autoencoder"]` stays None → denominator drops to 2, but a 1-vote IF+OCSVM anomaly now needs 2/2 |
| 5 | Partial-line read at poll boundary can drop/corrupt a JSON line | **P1** | yes | occasional dropped alert | `read_new` reads to EOF mid-write; `pos=tell()` after half-line then re-reads from middle next poll |
| 6 | `datetime.utcnow()` deprecated (3.12+) + naive tz, `+ "Z"` is misleading | **P2** | yes | works, wrong-ish ts | deprecated API; appends "Z" to a tz-naive local-UTC value |
| 7 | `if models.iso_forest:` truthiness on estimator object | **P2** | yes | works today | relies on sklearn `__bool__`; fragile vs explicit `is not None` |
| 8 | Alert file append: no flush/lock, no dir creation, datetime in hot path | **P2** | yes | mostly fine | concurrent writers / crash-mid-write could interleave; `/var/log` may need root |
| 9 | `load_config` can return `None` on empty YAML; defaults bypassed when file exists-but-empty | **P2** | partial | crash on `cfg.get` | `yaml.safe_load` returns None for empty file; not coalesced to `_DEFAULTS` |
| 10 | Singleton `get_config` ignores `path` after first call; `_DEFAULTS.copy()` is shallow | **P3** | yes | minor | global cache + shallow copy = nested-dict mutation leaks |
| 11 | Hardcoded ANSI colors written only to log, MEDIUM==LOW color; cosmetics | **P3** | yes | cosmetic | non-TTY/systemd journal gets escape codes |
| 12 | Daemon has no self-observability / staleness check; silent on model age | **P3** | yes | ops blind spot | SRE: nothing pages if models are stale or input stops flowing |

---

## Issue 1 — Cold-start z-scores meaningless; baseline never persisted (P0)

**Audit (evidence):**
- `run()` daemon.py:327–328 `history: list = []`, `df_history = pd.DataFrame()` — **empty on every boot**. Never read from / written to disk.
- `to_scaled_vector` daemon.py:186–191: builds `combined = concat(df_history, row)`, calls `add_zscores(combined)`, takes `.iloc[-1]`.
- `add_zscores` parse_logs.py:288–306: `df.groupby('username')[col].transform(stats.zscore(x, ddof=1) if len(x)>1 else 0.0)`.
- Training: notebook cell 16 computes z-scores over the **full 300-session synthetic dataset** (cell 8/10), where each simulated user has many sessions ⇒ z-scores span a realistic distribution. `scaler.fit` (cell 16) learns mean/std of those realistic z-scores.

**Quantified skew (deterministic, reasoned — pandas not installed here, no heavy install):**
- First session of any user: `len(x)==1` ⇒ `z_score_files = z_score_logins = 0.0`, **always**, regardless of whether the user accessed 5 or 5000 files.
- Second session: `len(x)==2`, `ddof=1` ⇒ the two z-scores are **always exactly ±0.7071** (zscore of 2 points is ±1/√(1·... ) → ±0.707 by construction), again **independent of magnitude**. So a 300-file spike and a 11-file session both yield +0.707.
- Training distribution of `z_score_files` had real spread (e.g. outliers at ±2..±4). The scaler centered/scaled on that. At serve time the daemon feeds 0 or ±0.707 into those two columns for the entire warm-up window ⇒ those two scaled features are pinned near a constant, far from where the models expect signal. **The two z-score features — the project's headline "portability" features (CONTEXT.md:124–129, 293–294) — are effectively dead for early traffic and never reach training-like spread until many sessions per user accumulate in RAM.**
- Because `history` lives only in RAM and is capped at `history_size` (500, FIFO), a busy multi-user VM evicts a given user's sessions; that user can repeatedly fall back to the 1–2 session regime ⇒ chronic skew, not just at boot.

**RCA (named): Train/serve baseline skew + non-persistent state.** Training z-scores derive from a large per-user population; serve z-scores derive from an empty/small rolling buffer that resets on restart and is shared/evicted across users. The z-score feature semantics differ between fit and transform time.

**Brainstorm:**
1. **Persist a per-user baseline (mean/std of nb_files & nb_failed_logins) to disk**, load on boot, compute z-score against that fixed baseline instead of a rolling recompute. (Recommended — matches training intent, restart-safe, O(1).)
2. Persist the rolling `df_history` (parquet/pickle) on shutdown + periodically; reload on boot. (Partial — still wrong for first-ever user, still recompute-based.)
3. Warm-up gate: suppress/flag predictions until each user has ≥N sessions; mark early alerts low-confidence. (Mitigation, not a fix.)
4. Export the exact per-user baseline statistics from the notebook alongside the models and ship them as a model artifact. (Best alignment with training — recommend combining with #1.)

**Plan:**
- Add `models/baselines.json` (or part of training export): `{username: {files_mean, files_std, logins_mean, logins_std}}`.
- `to_scaled_vector` computes `z = (x-mean)/std` from that fixed baseline; fall back to 0 only for genuinely unseen users (and log it).
- **Verify:** offline, scale the same session with (a) empty history vs (b) full baseline; assert scaled z-columns differ; assert predictions stable across daemon restart. Live: NOT VERIFIABLE WITHOUT VM.

---

## Issue 2 — `seek(0,2)` on open skips alerts that arrived while down (P1)

**Audit:** `AlertsWatcher.open` daemon.py:259–264: on open, `self._file.seek(0,2); self._pos = tell()` — positions at EOF. `run()` calls `watcher.open()` once at startup (daemon.py:331). There is **no persisted `_pos`** anywhere.

**Edge/state:** Every start (boot, crash-restart, systemd restart) jumps to end-of-file ⇒ all alerts written between the previous stop and the new start are **never processed**. The seek-to-end is intended for steady-state tail-f, but combined with no checkpoint it creates a guaranteed blind window on every restart. For a security tool this means an attacker active during a restart is invisible.

**RCA: Non-checkpointed tail with seek-to-end.** Idempotency/at-least-once is violated downward (alerts can be missed).

**Brainstorm:**
1. Persist `(inode, pos)` to a state file; on open, if inode matches and pos≤size, resume from pos instead of EOF. (Recommended — closes the gap, still avoids reprocessing.)
2. On first boot only seek-to-end; on restart, process from start of current file. (Risk: reprocess duplicates after rotation.)
3. Accept the gap but log loudly how many bytes were skipped at startup. (Observability mitigation.)

**Plan:** add checkpoint file next to alert output; load in `open()`, save in `read_new()` and on SIGTERM. **Verify:** write N lines, start daemon (consumes), stop, write M more, restart → assert M processed, 0 reprocessed. Live: NOT VERIFIABLE WITHOUT VM.

---

## Issue 3 — Per-username z-score over a shared rolling buffer ≠ training (P1)

**Audit:** `add_zscores` groups by `username` (parse_logs.py:295). In the notebook the same grouping runs over a stable 300-row dataset; in the daemon it runs over `df_history` (mixed users, FIFO-capped at 500, daemon.py:366–368). Concatenating one new `row` and recomputing means the new session **participates in its own z-score**, and the population is whatever happens to be in the buffer — not the training population.

**RCA: Same as Issue 1's mechanism, distinct symptom — population mismatch.** Even in warm state, a user with few rows in the buffer (because of eviction or low activity) gets distorted z-scores. This is the structural reason Issue 1 is P0; called out separately because the fix (fixed baseline) also resolves the eviction problem.

**Brainstorm/Plan:** subsumed by Issue 1 recommendation (fixed per-user baseline). **Verify:** same as Issue 1.

---

## Issue 4 — AE exception swallowed; vote denominator becomes inconsistent (P1)

**Audit:** daemon.py:153–166: AE wrapped in `try/except Exception` → on error, logs a `warning` and leaves `result["autoencoder"] = None`. Then daemon.py:168–172: `nb_models = count of non-None` ⇒ drops to 2; `is_anomaly = votes >= threshold_votes` where `threshold_votes` is fixed at 2 (config `ensemble_threshold: 2`).

**Branch analysis:**
- AE persistently failing (e.g., TF/CUDA OOM, shape mismatch) ⇒ system silently becomes a 2-model ensemble needing **2/2** votes ⇒ effectively an AND of IF and OCSVM ⇒ recall drops, but **no error surfaces** beyond a per-session WARNING that looks transient.
- `confidence = votes/nb_models` then reports e.g. 2/2 = 1.0, masking that a model is down.
- The other two models use `if models.iso_forest:` (no try/except, daemon.py:139,146) — if IF/OCSVM `.predict` raises on bad input, the **whole session loop iteration is uncaught here** and propagates up; but the `to_scaled_vector` call is guarded (daemon.py:351–354) while `predict` itself is **not** guarded in `run()` (daemon.py:356). A crash in IF/OCSVM predict ⇒ unhandled exception ⇒ daemon **dies** (see also Issue: no top-level guard).

**RCA: Inconsistent failure handling — AE failures degrade silently, IF/OCSVM failures crash; vote threshold not adjusted to live model count.** Hides model-down condition; SRE blind.

**Brainstorm:**
1. Treat any model failure uniformly: count attempted-vs-succeeded models, and if `nb_models < 3` raise an ERROR (not WARNING) with rate-limiting; optionally degrade `threshold_votes` proportionally. (Recommended.)
2. Wrap `predict()` call in `run()` in try/except like `to_scaled_vector` so one bad session can't kill the daemon. (Recommended, complementary.)
3. Make AE absence a hard startup failure (it's a core model). (Stricter; matches "fail loud".)

**Plan:** add success counters + ERROR on degraded ensemble; guard `predict` in the loop. **Verify:** feed input that makes AE raise → assert daemon stays up, logs ERROR, confidence reflects 2 models honestly. Live: NOT VERIFIABLE WITHOUT VM.

---

## Issue 5 — Partial-line read at poll boundary (P1)

**Audit:** `read_new` daemon.py:280–289: `seek(pos)`, iterate `for line in self._file`, then `self._pos = self._file.tell()`. Wazuh appends to `alerts.json`; if a poll fires while a line is half-written, iteration yields a partial line. The partial is `json.loads`-failed and **silently dropped** (daemon.py:287–288 `except JSONDecodeError: pass`), AND `tell()` advances past the partial ⇒ the **rest of that line on the next poll starts mid-JSON** and is also dropped ⇒ one alert permanently lost.

**RCA: No newline-terminated-read guarantee.** Reading to EOF instead of to last complete `\n`.

**Brainstorm:**
1. Only consume up to the last newline: read block, split, keep trailing fragment in a buffer, set `pos` to start-of-fragment. (Recommended — standard tail discipline.)
2. Re-seek to `pos` and retry next poll if last char isn't `\n`. (Simpler, costs a poll.)

**Plan:** buffer incomplete trailing line; advance `pos` only past complete lines. **Verify:** unit test feeding a file with a trailing partial line then completing it → assert exactly one parsed alert, none dropped. Live: NOT VERIFIABLE WITHOUT VM (depends on Wazuh write atomicity).

---

## Issue 6 — `datetime.utcnow()` deprecated + misleading "Z" (P2)

**Audit:** daemon.py:213 `datetime.utcnow().isoformat() + "Z"`. `utcnow()` is deprecated since Python 3.12 (emits DeprecationWarning, slated for removal) and returns a **tz-naive** datetime; appending "Z" claims UTC but the object carries no tz. (parse_logs uses tz-aware `fromisoformat(...replace("Z","+00:00"))`, so there's an internal inconsistency in tz handling.)

**RCA: Deprecated API + naive/aware mismatch.**

**Brainstorm:** (1) `datetime.now(timezone.utc).isoformat()` (already ends with `+00:00`, drop manual "Z") — recommended. (2) Keep "Z" but use `.replace(tzinfo=timezone.utc)`.
**Plan:** swap call; **Verify:** assert no DeprecationWarning, timestamp is tz-aware. Code-safe today; will warn/break on future Python.

---

## Issue 7 — Estimator truthiness `if models.iso_forest:` (P2)

**Audit:** daemon.py:139,146 use `if models.iso_forest:` / `if models.ocsvm:` and daemon.py:153 `if models.autoencoder:`. These rely on the object being truthy. sklearn estimators are truthy, but a Keras model's `__bool__`/`__len__` is not guaranteed; relying on truthiness instead of `is not None` is a footgun (a model defining `__len__`→0 would be skipped). `is_ready` (daemon.py:116–118) correctly uses `is not None` — inconsistent within the file.

**RCA: Implicit truthiness vs explicit None check.**
**Brainstorm/Plan:** use `is not None` everywhere (recommend). **Verify:** static; behavior unchanged for current objects. **CONFIRMED FINE at runtime today**, flagged as robustness.

---

## Issue 8 — Alert append: no flush/lock/dir-create, datetime per call (P2)

**Audit:** `emit_alert` daemon.py:242–246 opens output in `"a"` mode per alert, writes one line, relies on context-manager close to flush. No `os.makedirs` for the parent of `/var/log/ueba_alerts.json`; if dir missing → `IOError` caught (daemon.py:245) and alert **lost** (only logged). No file lock — if any other process/instance writes concurrently, lines could interleave (append is atomic only for writes < PIPE_BUF and full-line). `ensure_ascii=False` (daemon.py:244) is correct for French/Unicode usernames but requires consumers to read UTF-8.

**RCA: Best-effort single-writer assumption; missing dir handling.**
**Brainstorm:** (1) `Path(output).parent.mkdir(parents=True, exist_ok=True)` once at startup (recommend). (2) Keep file open + `flush()`/`os.fsync` for durability. (3) Advisory `fcntl.flock` if multi-writer possible.
**Plan:** create dir at startup, keep handle open with line-buffering. **Verify:** start with missing dir → assert dir created and alert written. Live durability NOT VERIFIABLE WITHOUT VM.

---

## Issue 9 — `load_config` returns None on empty YAML (P2)

**Audit:** config.py:67–68 and 73–74: `return yaml.safe_load(f)`. `yaml.safe_load` returns **None** for an empty or all-comment file. Then `run()` does `cfg.get("wazuh", {})` (daemon.py:301) ⇒ `AttributeError: 'NoneType' has no attribute 'get'` ⇒ daemon crash at startup. The docstring (config.py:84) promises "Ne lève jamais d'exception" — violated transitively. The `path`-given branch returns `_DEFAULTS.copy()` only when the file **doesn't exist**, not when it's empty/invalid.

**RCA: Missing None-coalesce after `safe_load`.**
**Brainstorm:** (1) `return yaml.safe_load(f) or _DEFAULTS.copy()` in both branches (recommend). (2) Deep-merge loaded config over `_DEFAULTS` so partial configs also work (better — a config missing a section currently yields `cfg.get("daemon", {})` → `{}` → falls back to per-key defaults, which works, but a present-but-empty section silently loses keys). Recommend deep-merge.
**Plan:** coalesce + optional deep-merge. **Verify:** empty file and partial file both return usable dict; daemon starts. **CONFIRMED issue is code-safe to reproduce: empty config.yaml ⇒ crash.**

---

## Issue 10 — Singleton ignores path; shallow copy (P3)

**Audit:** config.py:83–88 `get_config` caches `_cfg` on first call and ignores any later `path` arg. daemon `main()` (daemon.py:390) calls `get_config()` when no `--config`, fine; but any second caller passing a path silently gets the first config. Also `_DEFAULTS.copy()` (config.py:69,76) is a **shallow** copy — nested dicts are shared; a caller mutating `cfg["daemon"]["poll_seconds"]` would corrupt `_DEFAULTS` for the process.

**RCA: Global singleton + shallow copy.**
**Brainstorm:** (1) `copy.deepcopy(_DEFAULTS)` (recommend). (2) Document/forbid mutation. (3) Make `get_config(path)` re-load when path differs from cached.
**Plan:** deepcopy defaults; **Verify:** mutate returned cfg, assert `_DEFAULTS` unchanged. Low impact in current single-caller flow → P3.

---

## Issue 11 — ANSI colors in logs; MEDIUM==LOW color (P3)

**Audit:** daemon.py:235 `colors = {"HIGH": red, "MEDIUM": yellow, "LOW": yellow}` — MEDIUM and LOW are the same color. Escape codes are embedded in `log.warning` text (daemon.py:237–241); when running under systemd/journald or redirected to a file, raw `\033[..m` sequences pollute logs.

**RCA: Cosmetic / TTY assumption.**
**Brainstorm:** (1) gate colors on `sys.stdout.isatty()` (recommend). (2) Distinct MEDIUM color. **Plan:** isatty guard. **Verify:** redirect stdout → assert no escape codes. P3.

---

## Issue 12 — No daemon self-observability / staleness check (P3, SRE lens)

**Audit:** Startup checks `models.is_ready()` (daemon.py:316) and exits(1) if no models — **good, fails loud on missing models.** But: (a) no check on model **age/version** — a stale model from months ago loads silently; (b) no heartbeat / "no input for N minutes" warning — if Wazuh stops writing, the daemon happily sleeps forever with no signal; (c) no metric/counter of sessions processed or alerts emitted; (d) per-session `log.info` (daemon.py:357) is the only signal, lost in volume.

**RCA: Minimal observability of the daemon itself (3am-page gap).**
**Brainstorm:** (1) emit a periodic heartbeat log + counters; warn if no new alerts for K polls (recommend). (2) record model mtime/hash at load and log it. (3) export Prometheus textfile / write a status file.
**Plan:** add heartbeat + idle warning. **Verify:** run with no input → assert idle warning fires. Live NOT VERIFIABLE WITHOUT VM.

---

## Adversary lens (alerts.json is attacker-influenceable log data)

- **Crash via crafted fields:** `extract_raw_fields` (parse_logs.py:126–174) is defensive (`_get_nested`, `_parse_int`, `.strip().lower()` on guaranteed-non-None via `or "unknown"`). A non-dict `data`/`rule`/`agent` value (e.g. `"data": "x"`) ⇒ `data.get` → `AttributeError`. `extract_raw_fields` is **not** wrapped in try/except inside the daemon's comprehension (daemon.py:346) ⇒ a single crafted alert with `"data": []` would raise and **kill the daemon** (the loop body up to `to_scaled_vector` is unguarded for extract/group/build). **This is an attacker DoS vector if alerts.json content is influenceable.** (Belongs partly to parse_logs audit, but the daemon's missing guard is the amplifier.) Severity here: **P1-adjacent**; recommend wrapping `extract_raw_fields`/`group_by_session`/`build_features` per-batch in try/except with logging.
- **DoS via volume:** unbounded `new_alerts` per poll → all loaded into memory (`read_new` appends all lines, daemon.py:281–287). A burst of millions of lines (log injection) ⇒ memory blowup. Recommend a per-poll line cap.
- **Alert-file poisoning:** `username` is taken from attacker-controlled event fields and written verbatim into `ueba_alerts.json` (daemon.py:216) with `ensure_ascii=False`; downstream consumers must treat as untrusted (newline already stripped by JSON encoding, so log-injection into the alert file is limited — JSON escapes `\n`). **CONFIRMED FINE** for the alert file itself.

## Data-integrity lens
- Re-processing after rotation: on inode change, `read_new` resets `pos=0` and reads the **new** file from start (daemon.py:269–275). Correct for rotation. But if logrotate uses copytruncate (same inode, file shrinks), inode is unchanged and `seek(pos)` with pos>size ⇒ seek past EOF, reads nothing until file grows back past old pos ⇒ **silent gap** until catch-up. Recommend detecting `size < pos` ⇒ reset to 0. (P2 robustness.)

## Dead paths / fresh-eyes
- `import os`? not present — fine. `np`/`pd` used. No dead imports in daemon.
- `history` (list) and `df_history` are both maintained; `df_history` rebuilt from `history` every session (daemon.py:368) — O(n) rebuild each session, fine at 500 cap but wasteful; not a bug.
- `_severity` reads raw (un-scaled) `features` dict (daemon.py:197–207) — correct, thresholds are on raw counts; consistent. **CONFIRMED FINE.**
- config.yaml values vs code defaults: every default in `config.py:_DEFAULTS` matches `config.yaml` (alerts_path, session 60, models_dir, poll 30, history 500, ensemble_threshold 2, level INFO). `daemon.run` reads `daemon.history_size` (default 500) — matches. **CONFIRMED FINE.**
- Note: `behavior.sensitive_path` default differs subtly: config.py `"C:\\Sensitive\\"` vs parse_logs fallback `r"C:\Sensitive\\"` (double backslash) — but config.yaml is authoritative when present, so on VM1 it's `'C:\Sensitive\'`. Minor; flagged only if parse_logs runs without config. (P3, parse_logs territory.)

## CONFIRMED FINE (summary)
- Feature-order train/serve contract (Issue-free).
- AE `.keras` load fix and `predict()` MSE math.
- Vote counting logic (−1=anomaly), `_severity` thresholds on raw features.
- config.yaml ↔ defaults consistency.
- Missing-models startup: exits(1), fails loud.
- SIGTERM/SIGINT handlers set graceful `running=False`.

## NOT VERIFIABLE WITHOUT VM
- Actual model loading (`models/` is empty here — only `.gitkeep`), so IF/OCSVM/AE `.predict` shapes and the AE TF import path are reasoned, not executed.
- Wazuh write atomicity (Issue 5 partial-line) and logrotate mode (Issue: copytruncate gap).
- Real alerts.json schema variance (Adversary crash vector depends on field types Wazuh actually emits).
- pandas/scipy not installed in this audit env (no heavy installs) → cold-start z-score numbers (Issue 1) are derived analytically, not run.
