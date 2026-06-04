# Audit — Feature Engineering & the Wazuh Data Contract

**Scope:** `src/ueba/features/parse_logs.py` (the module that turns `alerts.json` into `dataset.csv` + per-user z-scores).
**Consumers:** `notebooks/ueba_ml_pipeline.ipynb` (training) and `src/ueba/integration/daemon.py` (real-time scoring).
**Method:** line-by-line read, hand-traced edge cases, light read-only probes (Python 3.12, `py_compile`, `datetime`/string logic — pandas/scipy are NOT installed in this sandbox so DataFrame paths were reasoned, not executed). Live Wazuh/Sysmon JSON not reachable → schema reasoning marked **NOT VERIFIABLE WITHOUT VM**.

---

## 0. Mental model (5 lines)

1. `load_alerts` reads the file as one UTF-8 blob, tries array-parse if it starts with `[`, else NDJSON line-by-line.
2. `extract_raw_fields` pulls timestamp/user/event_id + a flat field bag from each alert via Wazuh/Sysmon key paths; returns `None` if unusable.
3. `group_by_session` sorts by (user, ts) and cuts a new session on user change or >60-min inactivity gap.
4. `build_features` computes 16 features per session (time flags, counts, sensitive-path, velocity, entropy, duration).
5. `add_zscores` adds per-user z-scores for files & failed logins; pipeline reorders to `DATASET_COLUMNS` and writes CSV.

**Contract this module promises callers:** "Given a real Wazuh `alerts.json`, emit one row per user-session with the 14 `NUMERIC_FEATURES` the models consume, populated with *real, discriminative* values, in a stable column order, without crashing or silently dropping/duplicating sessions." Several parts of this contract are **broken on real data** (see P0s) while passing on the synthetic notebook data.

---

## Severity-ranked findings

| # | Title | Severity | code-safe? | runs-for-real? | One-line RCA |
|---|-------|----------|-----------|----------------|--------------|
| 1 | `bytes_sent` is a dead feature on real data (Sysmon EID 3 has no `data.bytes_sent`) | **P0** | yes | **NO** | exfil-volume feature reads a field Wazuh never emits → always 0 live, but models trained on big synthetic values |
| 2 | Mixed tz-aware/naive timestamps crash `group_by_session` | **P0** | **NO** | **NO** | `@timestamp`/`predecoder` fallbacks yield naive datetimes; subtracting from aware ones raises `TypeError` mid-run |
| 3 | `SENSITIVE_PATH` default `C:\Sensitive\\` ≠ config `C:\Sensitive\` → substring never matches | **P0** | yes | **NO** | hardcoded default has a literal double backslash; sensitive-file detection silently fails if config not loaded |
| 4 | Sysmon event field names likely wrong-cased / wrong-path for Wazuh decoders | **P0** | yes | **NO** | Wazuh emits `data.win.eventdata.image` etc. but casing/keys vary by decoder; mismatched → process/file/cmd features empty |
| 5 | `extract_raw_fields` crashes on non-string timestamp / non-string user | **P1** | **NO** | maybe | `.replace("Z",...)` and `.strip().lower()` assume `str`; an int/null field raises `AttributeError`, not the intended `None` |
| 6 | `event_id` not normalized to a canonical type; Wazuh EID is string but matching is brittle | **P1** | yes | partial | works only because every `WINDOWS_EVENT_IDS` entry is a string; an int eventID elsewhere would silently never match |
| 7 | `new_ip` is misnamed — it means "≥2 IPs this session", not "unseen IP" | **P1** | yes | yes | no cross-session IP history; CONTEXT claims "IP inconnue apparaît" — feature cannot mean that |
| 8 | `fromisoformat` Python-version-sensitive (offset-no-colon / nanoseconds) | **P1** | depends | **NO** on <3.11 | real Wazuh offsets are `+0100` (no colon); only Python 3.11+ parses them → silent total event drop on older interpreters |
| 9 | `nb_processes` / process features double-count Security 4688 + Sysmon 1 | **P2** | yes | yes | both EIDs map to `process`; same process logged twice inflates counts vs synthetic baseline |
| 10 | Corrupt/huge file handling: whole-file `read_text`, array-parse-all-or-nothing | **P2** | yes | partial | a single bad char early in an array file silently falls through to NDJSON mode and drops everything |
| 11 | `add_zscores` brand-new/one-session user → z=0 (no anomaly signal possible) | **P2** | yes | yes | cold-start user always normal; documented but worth flagging as detection blind spot |
| 12 | `command_line` / `process_name` exported as raw text but never fed to models | **P3** | yes | yes | columns exist in CSV, excluded from `NUMERIC_FEATURES`; entropy is the only signal derived |
| 13 | `is_night` boundary `>= WORK_HOUR_END` makes 18:00 "night" | **P3** | yes | yes | inclusive end boundary; defensible but undocumented vs "9h-18h" wording |
| 14 | Silent drops: `extract_raw_fields` returns `None` for any missing ts with no count of how many dropped | **P3** | yes | yes | data-integrity observability gap |

**Counts:** P0 = 4, P1 = 4, P2 = 3, P3 = 3.

---

## Per-issue detail

### 1. `bytes_sent` is a dead feature on real data — P0 (code-safe: yes / runs-for-real: NO)

**Audit.** `parse_logs.py:172` `"bytes_sent": _parse_int(data.get("bytes_sent") or 0)` and `:232-233`:
```python
if eid in WINDOWS_EVENT_IDS["network"]:   # EID "3"
    s["bytes_sent_total"] += ev.get("bytes_sent", 0)
```
`bytes_sent` is sourced *only* from `data.bytes_sent` and accumulated only for Sysmon EID 3.

**RCA (named): Synthetic-only field path.** Sysmon Event ID 3 (`Network connection detected`) does **not** contain a bytes-transferred field at all — its schema is `SourceIp/SourcePort/DestinationIp/DestinationPort/Protocol/Initiated/Image`, no byte counts. Wazuh's Sysmon decoder therefore never produces `data.bytes_sent`. So on real data `bytes_sent` is **always 0**. Meanwhile the notebook (`simulate_*`) injects `bytes_sent` in the 1e3–5e6 range, and it is a member of `NUMERIC_FEATURES` (daemon `:67`, notebook). The models *learn to rely on* a feature whose live value is a constant 0 → on real data this dimension carries zero information and, after `StandardScaler` fit on synthetic data, real 0s map to a large negative z, potentially flagging *every* real session as anomalous (or being ignored — either way garbage). **This is the canonical "trained on synthetic, dead on real" failure the task warned about.** NOT VERIFIABLE WITHOUT VM, but follows directly from the documented Sysmon EID3 schema.

**Brainstorm.**
- (a) Drop `bytes_sent` from `NUMERIC_FEATURES` entirely (retrain) — honest, removes a misleading dimension. Recommended short-term.
- (b) Re-source a real volume proxy: count of EID3 network connections (`nb_network_conn`), or sum DNS (EID22) queries, as an exfil/C2 proxy. Recommended medium-term (gives a real, discriminative signal).
- (c) If true byte volume is required, ingest a different source (Sysmon EID 3 does not have it; would need NetFlow / Zeek / firewall logs) — out of scope for this pipeline.

**Plan.** 1) Confirm on VM1: `grep '"id":"3"' alerts.json | head` and check for any `bytes_sent`/byte field (expect none). 2) Replace feature with EID3 connection count in `_update_session`/`build_features`. 3) Retrain notebook. **Verify:** real `dataset.csv` shows non-constant `bytes_sent`/`nb_network_conn`; `df.bytes_sent.nunique() > 1`.

---

### 2. Mixed tz-aware / naive timestamps crash `group_by_session` — P0 (code-safe: NO / runs-for-real: NO)

**Audit.** `:128` timestamp comes from `alert.get("timestamp") or _get_nested(alert, "@timestamp")`. `:132` `datetime.fromisoformat(timestamp_str.replace("Z","+00:00"))`. Top-level Wazuh `timestamp` carries an offset (aware); but other shapes (e.g. a `@timestamp` lacking offset, or decoder-normalized fields) can be **naive**. `:188` then does `(ts - current.get("last_ts", ts)).total_seconds()`.

**Probe (Python 3.12):**
```
aware - naive -> TypeError: can't subtract offset-naive and offset-aware datetimes
```

**RCA (named): tz-awareness contamination.** If even one event in a run is naive while another is aware (same user, adjacent in sorted order), the gap subtraction raises `TypeError` and the **entire pipeline crashes** (`parse_alerts_to_dataframe` has no guard). `sorted()` at `:182` also raises `TypeError` comparing aware vs naive within the same username key. The synthetic notebook never hits this (all synthetic ts are uniform). On real mixed-source Wazuh data this is a live crash risk.

**Brainstorm.**
- (a) Normalize all timestamps to UTC-aware at extraction: after parse, `if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)`. Recommended — one line, deterministic.
- (b) Strip tz entirely (force naive) — loses DST/offset correctness, and `hour` feature becomes wrong for non-UTC agents.
- Recommend (a) and additionally store/compare in UTC so `hour` reflects the agent's intended local time only if you first convert (note: Wazuh `timestamp` is already agent-local-with-offset; converting to UTC would shift `hour`! See verify step).

**Plan.** 1) Add tz-normalization in `extract_raw_fields` right after `:132`. 2) Decide `hour` semantics: keep agent-local hour (`ts.hour` of the original offset-aware value) — UTC conversion would corrupt `is_night`/`hour`. 3) Guard `parse_alerts_to_dataframe` to skip-and-count un-subtractable events. **Verify:** craft a mixed alerts.json (one `+0100`, one naive) → currently `TypeError`; after fix → 1–2 sessions, no exception; `hour` unchanged for the offset event.

---

### 3. `SENSITIVE_PATH` default has a double backslash — P0 (code-safe: yes / runs-for-real: NO when config absent)

**Audit.** `:41` `SENSITIVE_PATH = _cfg.get("behavior",{}).get("sensitive_path", r"C:\Sensitive\\")`. The raw string `r"C:\Sensitive\\"` is literally `C:\Sensitive\\` (two trailing backslashes). config.yaml `:16` is `'C:\Sensitive\'` → `C:\Sensitive\` (one). Matching at `:259` `if SENSITIVE_PATH.lower() in p.lower()`.

**RCA (named): default/config drift via escaping.** A real file path is `C:\Sensitive\secret.docx` (single backslashes). The substring `c:\sensitive\\` (double) is **not** contained in `c:\sensitive\secret.docx`, so when config loads the default (the `try: get_config()` at `:31-35` swallows *all* exceptions into `_cfg = {}`), `nb_sensitive_files` and `sensitive_path_access` are always 0. The unit test (`test_features.py:151`) passes only because it relies on config.yaml being loaded (single backslash). If `ueba.config` import fails on VM1 (e.g. PyYAML missing, cwd issue) the bare `except` hides it and the sensitive-path detector silently dies — the single most important insider-threat feature.

**Note also:** even the *config* value `C:\Sensitive\` is a fragile substring match; a path like `C:\SensitiveData\x` would false-positive, and case is handled but separator variants (`/`) are not.

**Brainstorm.**
- (a) Fix the default to a single backslash `r"C:\Sensitive" + "\\"` or just `r"C:\Sensitive\\"[:-1]` — clearer: set default to `"C:\\Sensitive\\"`-as-one-backslash i.e. `r"C:\Sensitive" "\\"`. Simplest correct literal: `"C:\\Sensitive\\"` is still double; use `"C:" + chr(92) + "Sensitive" + chr(92)` or document. **Recommend:** default `r"C:\Sensitive"` (no trailing sep) + match with `.startswith`/normalized comparison.
- (b) Don't swallow the config-load exception silently (`:34`) — log a WARNING so a failed config (which activates the broken default) is visible. Recommend both.

**Plan.** 1) Change default to a value that equals the config (single backslash). 2) Replace bare `except Exception` at `:34` with logged warning. 3) Normalize path separators + case before substring test. **Verify:** with `_cfg={}`, `build_features` on a session with `["C:\\Sensitive\\x.docx"]` must give `nb_sensitive_files==1` (currently 0).

---

### 4. Sysmon/Windows eventdata field paths likely mismatch real Wazuh decoder output — P0 (code-safe: yes / runs-for-real: NO) — NOT FULLY VERIFIABLE WITHOUT VM

**Audit.** `:139-140` `data.get("win",{}).get("system",{})` and `...eventdata`. Fields read: `subjectUserName/targetUserName/ipAddress` (`:150-163`), `targetFilename/objectName` (`:164`), `image/parentImage/commandLine` (`:166-171`).

**RCA (named): decoder-shape assumption.** Wazuh's Sysmon integration nests under `data.win.eventdata.*` and `data.win.system.*`, but the **key casing and presence depend on the decoder/ruleset version**. Common real shapes: `data.win.eventdata.image`, `data.win.eventdata.targetFilename`, `data.win.eventdata.commandLine`, `data.win.system.eventID` — these match. **But:** (i) `subjectUserName`/`targetUserName` for Security 4624/4625 are under `data.win.eventdata` only when the Security channel is Sysmon-style decoded; classic Wazuh Security decoding often exposes user as `data.win.eventdata.targetUserName` *or* `data.dstuser`/`data.win.eventdata.subjectUserName` inconsistently. (ii) `ipAddress` (4624 logon source) is `data.win.eventdata.ipAddress` — plausible. (iii) `objectName` for 4663 file access is correct, but **4663 requires SACL auditing**; if not enabled (likely in a lab) there are *zero* 4663 events → file features come only from Sysmon EID 11 (`targetFilename`), which is covered. The risk: if any of these keys are off by case (`Image` vs `image`) the feature is silently empty. Verdict: needs one real alert sample per EID to confirm; treat as P0 until proven, because an empty `image`/`commandLine` kills `process_name`, `nb_processes`, and `entropy_commands` at once.

**Brainstorm.**
- (a) Add a one-time diagnostic mode that prints, for the first N alerts, which expected keys are present/absent — turns "silent empty" into "loud mismatch". Recommend.
- (b) Make field lookups case-insensitive (build a lowercased view of eventdata). Recommend for robustness.

**Plan.** On VM1: `python -m json.tool` a handful of EID 1/3/11/4624/4663/4625 alerts; diff actual keys vs the literals in `:150-172`. **Verify:** real `dataset.csv` has non-empty `process_name`, non-zero `nb_processes`, non-zero `entropy_commands` for sessions that include process events.

---

### 5. `extract_raw_fields` assumes string fields → `AttributeError` on int/null — P1 (code-safe: NO / runs-for-real: maybe)

**Audit.** `:132` `timestamp_str.replace("Z","+00:00")` — if `timestamp` is non-string (rare but possible for `@timestamp` epoch ints), `.replace` raises `AttributeError`, which is **not** caught (only `ValueError` is, `:133`). Same risk `:155` `.strip().lower()` on the username chain: every element is normally a string, but `data.srcuser` or a decoder field could be a number/list → `AttributeError`.

**RCA (named): unchecked `.str-method` on untyped JSON.** The function's contract is "return None if unusable", but type surprises escape as uncaught exceptions and crash the whole run (no per-event guard in `parse_alerts_to_dataframe`).

**Brainstorm.** (a) Coerce: `timestamp_str = str(timestamp_str)`; wrap the username chain element-wise or `str(...)`. (b) Broaden the except to `(ValueError, TypeError, AttributeError)` around parse. Recommend (a)+(b): coerce defensively and catch type errors → return None and increment a dropped-counter (see #14).

**Plan.** Add `str()` coercion + widen except. **Verify:** `extract_raw_fields({"timestamp": 1705312800})` currently raises; after fix returns `None` (or parses if you support epoch).

---

### 6. `event_id` or-chain works only because every map value is a string — P1 (code-safe: yes / runs-for-real: partial)

**Audit.** `:142-147`:
```python
event_id = (str(sysmon.get("eventID","")) or str(_get_nested(...) or "") or str(data.get("id","")) or "").strip()
```
**Hand-trace (probed):** present in sysmon → `"1"`; absent in sysmon but nested present → `"4624"`; sysmon empty-string but `data.id="99"` → `"99"`; int eventID `4624` → `"4624"`; nothing → `""`. **The chain is correct**, not "lucky": `str("")` is falsy so `or` falls through exactly as intended, and `str(4624)` works. The only subtle point is `sysmon.get("eventID","")` and the nested `_get_nested(...)` read the *same* path (`data.win.system.eventID`), so the second clause is **redundant** with the first whenever `sysmon` was successfully extracted at `:139`. The real fragility is downstream: matching at `:214` etc. is `eid in WINDOWS_EVENT_IDS[...]` where the lists are strings; since `event_id` is always coerced to `str`, this is consistent. Good. But `data.get("id")` (Wazuh agent/decoder `id`) is **not** a Windows event id — using it as a 3rd fallback can inject a bogus rule/agent id into `event_id` and cause spurious/missed event-type classification.

**RCA (named): overloaded fallback semantics.** The 3rd fallback conflates "Windows event id" with Wazuh's generic `data.id`.

**Brainstorm.** (a) Drop the redundant 2nd clause and the misleading `data.id` 3rd clause; keep just `str(sysmon.get("eventID","")).strip()`. (b) If a non-Sysmon source needs an id, map it explicitly. Recommend (a).

**Plan.** Simplify chain; **verify** existing tests still pass (`event_id=="4624"` etc.).

---

### 7. `new_ip` is misnamed — it is "≥2 IPs this session", not "previously-unseen IP" — P1 (code-safe: yes / runs-for-real: yes, but semantically wrong)

**Audit.** `:265` `new_ip_flag = int(len(session["ips_seen"]) > 1)`. `ips_seen` is per-session, populated only on login-success (`:216-219`). CONTEXT.md `:120` claims `new_ip` = "1 si une IP inconnue apparaît … Connexion vers un C2".

**RCA (named): no cross-session IP baseline.** There is no persistent per-user IP history in this module, so "new/unknown IP" is impossible to compute here. The feature actually flags sessions that logged in from 2+ distinct IPs — a different (and weaker) signal. For the common case of a single login per session it is always 0. The daemon does keep `df_history` but `new_ip` is not recomputed against it.

**Brainstorm.** (a) Rename to `multi_ip` and fix CONTEXT to match (honest, cheap). (b) Implement true "unseen IP" using a per-user IP set carried across sessions (in `add_zscores`-style stateful pass or daemon history). Recommend (b) for real detection value; at minimum (a).

**Plan.** Either rename or implement history-aware unseen-IP. **Verify:** session with 2 login IPs → 1; with 1 → 0 (current). For (b): an IP not in the user's prior set → 1.

---

### 8. `fromisoformat` is Python-version-sensitive on real Wazuh offsets — P1 (code-safe: depends / runs-for-real: NO on Python <3.11)

**Audit.** `:132`. **Probe on this sandbox (Python 3.12):** real Wazuh `2024-01-15T10:00:00.123+0100` (offset **without colon**), nanosecond `...Z`, and `+00:00` all parse OK. **But** `datetime.fromisoformat` only learned to parse offset-without-colon and `Z`/fractional-extended forms in **Python 3.11**. Wazuh's `alerts.json` `timestamp` is exactly `YYYY-MM-DDThh:mm:ss.sss±hhmm` (no colon in offset).

**RCA (named): interpreter-dependent parsing.** On Python 3.10/3.9 (very common on Ubuntu 22.04 / older VM images), `fromisoformat("2024-01-15T10:00:00.123+0100")` raises `ValueError` → caught at `:133` → returns `None` → **every real alert is dropped**, `raw_events` empty, pipeline prints "0 sessions" and exits. Silent total failure. The README/CONTEXT do not pin a Python version. VM1 is Ubuntu 24.04 (Python 3.12) per CONTEXT — so probably fine *there* — but this is a latent portability landmine and the `.replace("Z",...)` only patches the `Z` case, not the no-colon offset.

**Brainstorm.** (a) Pin `python_requires>=3.11` in pyproject + document. (b) Use a tolerant parser (`dateutil.parser.isoparse`, already transitively common) for robustness across versions and odd offsets. Recommend (b).

**Plan.** Swap to `dateutil.isoparse` or add a regex-normalizer for the offset colon. **Verify:** parse `2024-01-15T10:00:00.123+0100` succeeds on 3.9–3.12.

---

### 9. `nb_processes` double-counts Security 4688 + Sysmon EID 1 — P2

**Audit.** `:49` `"process": ["4688","1"]`; `:227-229` appends to `process_names` for either. A single process creation logged by **both** Security (4688) and Sysmon (1) is counted twice.

**RCA (named): overlapping event sources for one fact.** Inflates `nb_processes`, `velocity` (no—velocity uses files), and shifts the synthetic-vs-real distribution. Synthetic data sets `nb_processes` directly, so the model's notion of "normal process count" won't match a live system that emits both channels.

**Brainstorm.** (a) Dedup by process GUID/PID+image within session. (b) Prefer one source (Sysmon EID1, richer) and ignore 4688 for counting. Recommend (b) — simplest, and CONTEXT already says EID1 has "plus de détails".

**Plan.** Drop `4688` from the `process` list (or dedupe). **Verify:** a session with one process emitting both 4688 & 1 yields `nb_processes==1`.

---

### 10. Corrupt / huge-file handling — P2

**Audit.** `:83` `path.read_text(...).strip()` loads the **entire** file into memory (alerts.json can be GBs on a busy manager). `:85-91` if it starts with `[`, a single `JSONDecodeError` anywhere makes it `pass` and fall through to NDJSON mode (`:93`), which will then fail to parse the array-formatted content line-by-line and produce mostly `[WARN]` + near-empty `alerts`. Partial last line in NDJSON is dropped (fine). `errors="replace"` mangles non-UTF-8 bytes silently into `�` which can corrupt paths/usernames.

**RCA (named): all-or-nothing array parse + full-file read.** Robustness/scale gap; also a silent-degradation path (array file with one bad record → almost everything lost, only a WARN per line).

**Brainstorm.** (a) Stream line-by-line for NDJSON (the real Wazuh format **is** NDJSON, not an array) and only attempt array-mode for small files. (b) Don't fall through array→NDJSON silently; report which mode and how many records. Recommend (a)+(b).

**Plan.** Detect format by extension/first non-ws char, stream NDJSON. **Verify:** a 1-line-corrupt array file reports the failure instead of silently dropping all.

---

### 11. Cold-start user → z-score always 0 — P2

**Audit.** `:296-302` per-user groupby; `len(x)<=1 → 0.0`; `ddof=1` needs ≥2. A brand-new user with one session gets `z_score_files=z_score_logins=0`.

**RCA (named): per-user baseline needs history.** A first-ever session for a user (or the daemon's first sighting) can never be flagged by the z-features — exactly when an attacker using a fresh/compromised account is most interesting. Documented behavior, but a real detection blind spot. The daemon mitigates partially via `df_history` (history_size 500) but a genuinely new user still starts at 0.

**Brainstorm.** (a) Fall back to a global (all-users) z-score when a user has <N sessions. (b) Seed new users with population mean/std. Recommend (a).

**Plan.** Add global fallback in `add_zscores`. **Verify:** single-session new user gets a non-zero z when its value is a population outlier.

---

### 12. `command_line` / `process_name` exported but not modeled — P3

**Audit.** `DATASET_COLUMNS` (`:64`) includes `process_name`, `command_line`; `NUMERIC_FEATURES` (daemon `:63`, notebook) excludes them. Only `entropy_commands` derives signal from `command_lines`. The headline "`-enc` = obfuscation" detection in CONTEXT `:123` is **not implemented** — no token/keyword feature on command_line.

**RCA.** Documentation overstates what the models see. The text columns are informational only (used in alert `indicators`, daemon `:230`).

**Brainstorm.** (a) Add a `cmd_suspicious` keyword flag (`-enc`,`-w hidden`,`frombase64`,`iex`) as a numeric feature. (b) Char-level entropy of the command string (not list-of-strings entropy — see note). Recommend (a); high detection ROI.

**Plan.** Add keyword feature to `build_features` + `NUMERIC_FEATURES`. Retrain. **Verify:** malware sample with `-enc` flags 1.

> Note on `entropy_commands`: `_entropy` computes Shannon entropy over the *multiset of distinct command strings* in the session (variety of commands), **not** character entropy of an obfuscated blob. CONTEXT `:127` ("commandes très variées") matches the code, but a single long obfuscated PowerShell command yields entropy 0 (one unique string) — so it will **miss** the classic single obfuscated command. Worth flagging.

---

### 13. `is_night` inclusive end boundary — P3

**Audit.** `:271` `int(hour < WORK_HOUR_START or hour >= WORK_HOUR_END)` → with end=18, `hour==18` (18:00–18:59) counts as night. CONTEXT says "9h-18h". Defensible (18:00 = after hours) but the `>=` vs `>` is undocumented and tests don't cover the boundary.

**Brainstorm.** Document the convention or use `> WORK_HOUR_END-1`. Low priority; recommend just documenting.

---

### 14. Silent session/event drops without counts — P3

**Audit.** `extract_raw_fields` returns `None` for missing/invalid ts (`:129-134`); `parse_alerts_to_dataframe:335` filters them with a comprehension and only prints the *kept* count. No visibility into how many events were dropped or why.

**RCA (named): observability gap (SRE lens).** On real data a decoder change could silently halve the dataset and the only signal is a smaller "événements valides extraits" number with no baseline. Fails quietly rather than loudly.

**Brainstorm.** Count and log dropped events by reason (no-ts, bad-ts, type-error). Recommend.

**Plan.** Accumulate counters; print `[WARN] N alerts dropped (no_ts=.., bad_ts=.., type=..)`. **Verify:** feed 10 alerts, 3 without timestamp → log says dropped=3.

---

## CONFIRMED FINE

- **`load_alerts` NDJSON path & per-line skip** (`:93-103`): correct for the real Wazuh format (NDJSON); bad lines are skipped with a WARN and line number. Good.
- **`event_id` or-chain logic itself** (`:142-147`): traced for present/absent/empty/int/none — returns the right string in every case (falsy `str("")` fall-through is intentional, not accidental). The *content* of the 3rd fallback is questionable (#6) but the mechanics are sound.
- **`_get_nested`** (`:109-116`): safely handles non-dict intermediates and missing keys → returns default. Correct.
- **`_parse_int`** (`:119-123`): catches `TypeError/ValueError` → 0. Correct (though it only matters for the dead `bytes_sent`).
- **`group_by_session` ordering & gap logic** (when timestamps are uniformly tz-aware): sort by `(username, ts)`, first event `gap=0` via `current.get("last_ts", ts)` with the `if current` guard, user-change cut, `>session*60` cut, final flush at `:195`. Off-by-one is correct: a gap of *exactly* 60min stays in-session (`> `, not `>=`); the test uses 2h01 to force a split. No off-by-one. Multi-user interleaving handled by the sort. **Caveat:** only fine when timestamps are all aware or all naive (see #2).
- **`_new_session` / `_update_session` event routing** (`:200-233`): each EID maps to the right accumulator; guards on empty `src_ip`/`file_path`/`process_name`/`command_line` before appending. Correct.
- **`_entropy`** (`:239-247`): standard Shannon entropy; empty→0, single→0, uniform-4→2.0; matches all 4 unit tests. Correct (semantic scope caveat in #12).
- **`add_zscores` mechanics** (`:288-306`): per-user groupby+transform, `ddof=1`, single-row→0, `fillna(0)`, missing-column→0 column. Correct; cold-start limitation is #11, not a bug.
- **`DATASET_COLUMNS` vs `NUMERIC_FEATURES` ordering:** DATASET_COLUMNS is a superset (adds timestamp/username/process_name/command_line/session_duration_min); the 14 numeric features are all present and the notebook/daemon select by name (not position) into `NUMERIC_FEATURES`, so column *order* mismatch is harmless. The daemon and notebook `NUMERIC_FEATURES` lists are **identical** (14 features) — consistent contract. Good.
- **`add_zscores` import-vs-inline parity:** notebook's inline fallback `add_zscores` is byte-identical in logic to the module version → no drift between train and the module.
- **`main` CLI:** argparse, output dir `mkdir(parents=True, exist_ok=True)`, `--session-min` plumbed through, empty-df → exit(1). Correct. (Minor: `--config` arg is accepted but **never used** — `args.config` is ignored; config is loaded at import time only. Cosmetic.)
- **`py_compile`**: module compiles clean on Python 3.12.

---

## NOT VERIFIABLE WITHOUT VM (reasoned from documented Wazuh/Sysmon schema)

1. **#1 `bytes_sent` absence on Sysmon EID3** — reasoned from the published Sysmon EID3 schema (no byte field). Confirm with a real EID3 alert on VM1.
2. **#4 eventdata key casing/paths** (`image`, `targetFilename`, `commandLine`, `subjectUserName`, `ipAddress`, `objectName`) — depend on the exact Wazuh ruleset/decoder version on VM1. Need real sample alerts per EID.
3. **4663 file-access presence** — requires SACL object-access auditing enabled on VM2; if off, file features come solely from Sysmon EID11. Check VM2 audit policy.
4. **Whether real alerts ever carry naive timestamps** (#2) — depends on which Wazuh field is populated; the `timestamp` field is offset-aware, but confirm no code path yields `@timestamp` naive on VM1.
5. **Real distribution of features vs synthetic** (#1, #9, #12) — only measurable by running `parse_logs.py` on a real multi-day `alerts.json` and comparing `dataset.csv` describe() against the notebook's synthetic ranges.
6. **Interpreter version on the actual VM** (#8) — CONTEXT says Ubuntu 24.04 (3.12, OK) but the deployed image should be confirmed (`python3 --version` on VM1).
