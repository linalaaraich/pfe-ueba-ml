# Re-Audit (Round 2) — Daemon & Config (serving)

Scope: `src/ueba/integration/daemon.py`, `src/ueba/config.py`, `config/config.yaml`,
`tests/test_daemon.py`, `tests/test_config.py`. Branch `audit/ueba-system-review`.
Method: 5-line model + contracts; line-by-line; lenses (Architect / SRE-3am /
Adversary / Data-integrity / Fresh-eyes); two dims CODE-SAFE? + RUNS-ON-VM?
Watcher behavior confirmed by **real induction** on temp files (numpy present;
pandas/sklearn/tensorflow absent → model-path items marked NOT-VERIFIABLE-WITHOUT-VM).

## 5-line model
1. `AlertsWatcher` tails `alerts.json` in binary mode, persisting a byte offset so
   restarts resume without replaying or skipping; handles rotation (inode) and
   copytruncate (size<pos → reset), holds partial trailing lines.
2. `UEBAModels` loads scaler + IF + OCSVM + AE(.keras) + frozen baseline +
   ae_threshold, tolerating every missing/corrupt artifact except a missing scaler
   (which makes `is_ready()` false → daemon exits).
3. `predict` runs each model under its own try/except, distinguishes
   expected-vs-evaluated, surfaces a degraded vote loudly, votes ≥ threshold.
4. `to_scaled_vector` builds a 14-feature vector using the frozen baseline z-scores
   (or sliding window fallback) and applies the fitted scaler.
5. `run` polls, guards extraction/vectorization per-alert, emits alerts, caps history.

## Contracts
- Feature order = single source `parse_logs.NUMERIC_FEATURES` (14). OK.
- Offset = bytes; advance only over bytes ending in `\n`. Mostly OK (see D-1).
- Config: every consumer supplies its own default via `.get(k, default)`; yaml is
  source of truth at runtime. `_DEFAULTS` is a fallback only when yaml is fully absent.

## Severity table
| ID | Sev | Title | CODE-SAFE? | RUNS-ON-VM? |
|----|-----|-------|-----------|-------------|
| D-1 | HIGH | copytruncate + regrow-past-old-pos before next poll → silent data loss / blind window | NO (data integrity) | data loss on VM under logrotate |
| D-2 | MEDIUM | Restart after same-inode truncate+rewrite to ≤ old size during downtime → missed alerts | NO (data integrity) | reproducible on VM |
| D-3 | MEDIUM | `to_scaled_vector` does not sanitize NaN (`x or 0` keeps NaN) → silent per-model failures / degraded vote | partial | sliding-window path only |
| D-4 | LOW | `config.py _DEFAULTS` stale & divergent from yaml (contamination 0.05 vs 0.01; missing ocsvm_nu/ocsvm_gamma/ae_threshold_percentile) | yes (masked) | Colab/no-yaml only |
| D-5 | LOW | Partial-yaml is returned un-merged with defaults (no deep-merge) | yes (masked today) | future footgun |
| D-6 | LOW | `df_history = pd.DataFrame(history)` rebuilt every session (O(n) each poll, n≤history_size) | yes | minor CPU on VM |
| D-7 | INFO | `emit_alert` uses `expected_models` (loaded) as vote denominator; fine but differs from `confidence` denominator (evaluated) — intentional, document | yes | n/a |

Counts: HIGH 1, MEDIUM 2, LOW 3, INFO 1.

---

## D-1 (HIGH) — copytruncate + regrow past old offset = silent data loss

**Audit.** `read_new` detects copytruncate via `elif st.st_size < self._pos: self._pos = 0`
(daemon.py:369-372). This only fires while the truncated file is *still smaller than
the previous offset*. With a 30s poll, logrotate copytruncate (truncate to 0, Wazuh
keeps writing) can grow the file past the old offset before the next poll. Then
`st_size >= _pos`, the reset is skipped, the watcher seeks to the stale byte offset
mid-stream, and everything before that offset in the **new** content is skipped — and
because the seek lands mid-line, even the straddling line is mangled.

**Confirmed (real induction).**
```
A read1: [{'n': 1}]                 # pos -> 8
# truncate to 0, write 20 bytes:  {"AA":11}\n{"BB":22}\n
size now 20 >= old pos 8 -> blind window
A read2 (want AA,BB): [{'BB': 22}]   # {"AA":11} SILENTLY LOST
```
The existing test `test_copytruncate_no_blind_window` passes only because it writes
*after* the read that observes size<pos; it never exercises regrow-within-one-poll.

**RCA.** The size<pos heuristic conflates "smaller now" with "was truncated". The only
robust copytruncate signals are: (a) file identity is the same inode but content
changed, or (b) tracking a content fingerprint (e.g. first N bytes / device+inode+ctime).
A byte offset alone cannot distinguish "appended" from "truncated-then-regrown".

**Brainstorm.** (1) Use `st.st_ctime`/`st_mtime` + size monotonicity: if size grew but
the bytes at `_pos-1` are no longer `\n`, suspect truncation. Fragile. (2) Track inode
**and** a small header fingerprint (first 64 bytes hashed): on mismatch with size not
strictly ≥ previous-recorded-size-at-that-fingerprint, reset to 0. (3) Reopen the path
by name each poll (already effectively done) and compare `st_size` to a *persisted
high-water size*: if `st_size < last_known_size` OR header-hash changed → reset to 0.
(4) Pragmatic: prefer `create`/rename rotation (logrotate default, inode change — already
handled) and document that copytruncate must pair with a shorter poll; still loses data.
Option (2)/(3) (header fingerprint) is the correct fix.

**Plan.** Persist `{inode, pos, head_hash, size}` in state. In `read_new`, after
stat: if inode changed → reset (as today). Else compute head hash of first
min(64,size) bytes; if it differs from stored head_hash (truncate+rewrite) **or**
`st_size < self._pos` → reset `_pos=0` and re-fingerprint. Update head_hash whenever
`_pos` was 0. Add a regression test: truncate→write>oldpos within one read cycle must
return all new lines. Mark partially NOT-VERIFIABLE end-to-end without a VM running
logrotate, but the unit-level repro above is deterministic.

## D-2 (MEDIUM) — restart over same-inode shrink-or-equal rewrite during downtime

**Audit.** `open()` does `self._pos = min(saved.pos, size)` when `saved.inode == inode`
(daemon.py:350-352). If, while the daemon is down, the file is truncated and rewritten
to a size ≤ the saved offset on the **same inode** (copytruncate during downtime, or any
in-place rewrite), `min` clamps to the new size and the fresh content below the old
offset is never read.

**Confirmed.**
```
E read1: []                          # first run skips history (correct)
inode same=True size1=8 size2=8
E read2 (should be e:2): []          # new {"e":2} MISSED after restart
```

**RCA.** Same root cause as D-1: offset clamping assumes the file only ever grows on a
given inode. `min(pos,size)` protects against pos>size but not against "same size,
different content".

**Brainstorm/Plan.** Same fingerprint fix as D-1 closes this: in `open()`, if the
persisted head_hash does not match the current head bytes, treat as rotation → `_pos=0`.
If hashes match and `pos<=size`, resume at pos. Single mechanism fixes D-1 and D-2.

## D-3 (MEDIUM) — NaN not sanitized in `to_scaled_vector`

**Audit.** Line 240: `float(last.get(f, 0) or 0)`. Intent: coerce missing/None/0 to 0.
But `nan or 0` evaluates to `nan` (NaN is truthy), so a NaN feature passes through to
`scaler.transform`, then to `model.predict`, where sklearn raises → caught per-model →
degraded vote with no clear cause.

**Confirmed.** `float(nan or 0) -> nan`; `None or 0 -> 0`; `{}.get('x',0) or 0 -> 0`.
Missing keys / None / 0 are fine; only NaN leaks.

**RCA.** The baseline path (`apply_baseline_zscores`) is NaN-safe (std=0→z=0), so this
only bites the **sliding-window fallback** (`add_zscores`) when std=0 on the live window
could yield NaN, or any upstream NaN in `build_features`. Still a silent data-integrity
gap that masquerades as a model failure.

**Plan.** Replace with an explicit NaN-safe coercion, e.g.
`v = last.get(f, 0); v = 0.0 if v is None or (isinstance(v,float) and math.isnan(v)) else float(v)`
or `np.nan_to_num(vec)` before `scaler.transform`. Add a unit test feeding a NaN feature.

## D-4 (LOW) — stale/divergent `_DEFAULTS`

**Audit.** `config.py:_DEFAULTS["detection"]` has `contamination: 0.05` (yaml says
`0.01`), `ae_threshold_sigma`/`ensemble_threshold`/`ae_latent_dim` only, and **lacks**
`ocsvm_nu`, `ocsvm_gamma`, `ae_threshold_percentile` that yaml carries.
Confirmed via key diff:
```
IN yaml but NOT in defaults: ['detection.ae_threshold_percentile','detection.ocsvm_gamma','detection.ocsvm_nu']
```
**RCA.** Defaults were not updated when yaml gained the tuned params. **Masked today**
because the notebook reads `_DET.get(key, 0.01/0.01/0.01/3.0/99.0)` with correct
hardcoded fallbacks (verified), and the daemon only reads `ensemble_threshold` (present).
So in a no-yaml Colab run the correct values still come from the *consumer* defaults, not
`_DEFAULTS`. **Plan.** Sync `_DEFAULTS["detection"]` to yaml (set contamination 0.01, add
the 3 keys) so config.py is not a second, lying source of truth.

## D-5 (LOW) — no deep-merge of partial yaml

**Audit.** `load_config` returns `loaded` verbatim when it is a dict (config.py:73);
defaults are used only when yaml is absent/empty/invalid. A partial yaml (user deletes
e.g. the whole `daemon:` block) yields a dict missing those keys. **Masked today**
because every daemon consumer uses `.get(k, default)`. **RCA/Plan.** Footgun for future
code that does `cfg["daemon"]["poll_seconds"]`. Recommend a recursive merge of `loaded`
over a deepcopy of `_DEFAULTS` so the returned config is always complete. Low because
no current consumer indexes without a default.

## D-6 (LOW) — `df_history` rebuilt each session

**Audit.** Line 488 `df_history = pd.DataFrame(history)` reconstructs the full frame
every processed session (history capped at `history_size`, default 500). O(n) per
session; harmless at this scale but pure waste. Only used by the sliding-window fallback
(`to_scaled_vector` baseline-absent path). **Plan.** When `models.baseline` is present
(the recommended config), `df_history` is unused — skip building it entirely. Otherwise
acceptable as-is.

## D-7 (INFO) — denominator inconsistency is intentional

`confidence = votes/evaluated_models` (predict, line 211) but the human log in
`emit_alert` prints `votes/expected_models` (line 291). This is deliberate (operator sees
"2/3 models loaded") but worth a one-line comment to avoid a future "bug" report.

---

## CONFIRMED-FINE (re-verified, do not re-flag)
- **Partial trailing line held**: confirmed — incomplete final line not consumed, offset
  not advanced past it, completed on next poll. (`test_partial_line_is_held_then_completed`
  + my induction.)
- **First-run skips existing history**: confirmed (`_pos = size` on no-state open).
- **Late file creation** (daemon starts before Wazuh writes alerts.json): confirmed —
  `open()` no-ops, `read_new` adopts the new inode from pos 0, reads all. (probe3)
- **Rename rotation (inode change)**: confirmed — new file read from 0 including small files.
- **Restart resume without blind window** for the normal append-during-downtime case:
  confirmed (`test_restart_resumes_no_blind_window`). Only the *truncate-during-downtime*
  variant (D-2) fails.
- **File deleted mid-poll**: confirmed no crash, returns `[]`, retains old fh/pos.
- **Malformed / non-JSON lines**: skipped, not fatal (`json.JSONDecodeError` swallowed).
- **predict robustness**: a single model raising does not crash the loop; degraded vote
  surfaced loudly via `log.error`; confidence denominator = evaluated_models; threshold
  `votes >= threshold_votes`. (tests pass logically; verified by reading + test design.)
- **UEBAModels tolerance**: corrupt `ae_threshold.json` → default 0.05, AE disabled, no
  crash; missing baseline → `None` → sliding-window fallback with a warning; missing IF/
  OCSVM/AE tolerated. Missing **scaler** → `is_ready()` False → daemon `sys.exit(1)`
  (fails loud — correct). AE load wrapped in broad except (TF absent or version skew →
  degrade, not crash). (`TestUEBAModelsDegradation`; logic re-read.)
- **config robustness**: empty/comments-only/missing yaml → defaults; returned config is
  a deepcopy (mutation cannot poison the global default). (`test_config.py`.)
- **Signal handling**: SIGTERM/SIGINT set `running[0]=False` for a clean drain+close.
- **extract_raw_fields guarded in loop**: confirmed — line 461-464 wraps it in try/except
  *and* `parse_logs` itself guards non-dict sub-fields (defense in depth). alerts.json is
  attacker-influenceable; a malformed/hostile alert cannot crash the loop.
- **Unbounded read DoS**: `read()` reads the whole new tail into memory each poll. With a
  bounded poll and normal Wazuh volume this is fine, but note: a hostile actor able to
  append GBs between polls could OOM the process (no per-read cap). Lower priority than D-1
  but worth a future bounded-read (e.g. read in capped chunks). Flagging as a known limit,
  not a new issue here.

## NOT-VERIFIABLE-WITHOUT-VM
- End-to-end predict/vote/emit with real scaler+IF+OCSVM+AE artifacts (pandas/sklearn/
  tensorflow absent in this env). Logic verified by reading + unit tests; numeric behavior
  on real models needs the VM.
- AE `.keras` load path (needs tensorflow); degradation path is exercised (TF absent →
  warning + disabled) and confirmed correct.
- D-1 under a real `logrotate ... copytruncate` cron on the VM (unit-level repro is
  deterministic and shown above).
