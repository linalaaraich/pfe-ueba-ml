# Audit — PACKAGING & REPRODUCIBILITY

Area: `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `Makefile`, `scripts/export_dataset.sh`, `scripts/run_daemon.sh`, `.gitignore`, build/install parts of `README.md` (+ notebook setup cells as cross-ref).
Repo: `/home/lina/pfe-ueba-ml`, branch `fix/colab-training-blocker`. Read-only audit. Build verified in temp venv (then removed).

## STEP 1 — 5-line mental model of install/repro flow

1. **Colab path (LIVE):** notebook cell 2 → `git clone https://github.com/assia-xnz/pfe-ueba-ml.git` → `pip install -q -e .`. This reads ONLY `pyproject.toml` `dependencies` (the LOOSE `>=` ranges). `requirements.txt` is **never** read on Colab.
2. **Local path:** `pip install -e .` / `make install` → again only pyproject ranges. `requirements.txt` is referenced by README only as an alternative ("ou") and by `requirements-dev.txt` via `-r`.
3. **VM1 path (deploy):** README systemd snippet runs `/opt/ueba-ml/venv/bin/python -m ueba.integration.daemon`. No documented install command for the VM venv → ambiguous whether VM uses pyproject ranges or pinned requirements.txt. Daemon `joblib.load`s the sklearn `.pkl` produced on Colab.
4. **LIVE deps = pyproject ranges** (numpy>=1.26, tensorflow>=2.16, scikit-learn>=1.5, …). **DECLARED-BUT-DEAD = requirements.txt exact pins** (numpy==1.26.4, tf==2.16.1, sklearn==1.5.0, keras==3.3.3) — they are documentation, not the resolved env.
5. Therefore: train env (Colab, latest resolvable libs) ≠ pinned versions, and the model producer (Colab sklearn N) can differ from the model consumer (VM sklearn M) → pickle/version-skew risk. Reproducibility "in 6 months" depends on the pins, but the pins are in a file nobody installs.

## Severity-ranked findings

| # | Title | Severity | code-safe? | runs-for-real? | One-line RCA |
|---|-------|----------|------------|----------------|--------------|
| 1 | Pinned `requirements.txt` is never installed on the LIVE paths (pyproject ranges win) | P1 | YES | PARTIAL — runs today, not reproducible later | Two sources of truth; the install command reads the loose one |
| 2 | sklearn `.pkl` cross-version load: Colab trainer vs VM daemon may differ | P1 | YES | NOT VERIFIABLE WITHOUT VM | No version parity enforcement between train and serve |
| 3 | `tensorflow>=2.16` + `numpy>=1.26` can resolve to NumPy 2.x / newer TF on fresh Colab | P1 | YES | PARTIAL | Open upper bound lets resolver pick NumPy-2-era stack |
| 4 | `keras==3.3.3` pinned in requirements.txt but not a pyproject dep; standalone keras unused | P2 | YES | YES | Redundant dep declared in dead file; code uses `tensorflow.keras` |
| 5 | `make train` calls `jupyter nbconvert` but nbconvert/jupyter not in `[dev]` extras | P2 | YES | NO (make train fails on clean `[dev]` env) | Makefile target assumes a tool that isn't a declared dep |
| 6 | VM1 has no documented install step; systemd assumes `/opt/ueba-ml/venv` pre-built | P2 | YES | NOT VERIFIABLE WITHOUT VM | README jumps from clone to systemd, skips venv+install on VM |
| 7 | `ruff` top-level `select`/`ignore` deprecated; `ruff>=0.4` may warn/break on new ruff | P3 | YES | PARTIAL (warns) | Config uses pre-0.6 layout; lint section not under `[tool.ruff.lint]` |
| 8 | Author email `sia.el2020@gmail.com` baked into pyproject metadata (PII in wheel METADATA) | P3 | YES | YES | Personal email shipped in every built artifact |
| 9 | Scripts call `python` (not `python3`); only Makefile uses `python3` | P3 | YES | PARTIAL | `python` may be absent/py2 on a bare VM |
| 10 | `git clone` URL hardcoded to `assia-xnz/pfe-ueba-ml` in notebook (repro fork hazard) | P3 | YES | YES | Hardcoded upstream; a fork's Colab clones the wrong repo |

---

## Issue 1 — Pinned requirements.txt is never installed on LIVE paths (P1)

**Audit.**
- `notebooks/ueba_ml_pipeline.ipynb` cell 2: `subprocess.check_call([sys.executable,'-m','pip','install','-q','-e','.'])` — installs from pyproject only.
- `pyproject.toml:22-36`: `numpy>=1.26`, `tensorflow>=2.16`, `scikit-learn>=1.5`, … (ranges).
- `requirements.txt:7-28`: `numpy==1.26.4`, `tensorflow==2.16.1`, `scikit-learn==1.5.0`, `keras==3.3.3` (exact).
- `Makefile:23-24` `install: pip install -e .` (ranges). `README.md:79-85` documents `pip install -e .` / `make install` as THE install; requirements.txt appears only as a commented alternative in the notebook's local branch (`# subprocess... requirements.txt`).
- Build evidence (temp venv): `python -m build --wheel` → `METADATA` `Requires-Dist:` lists exactly the loose ranges, confirming requirements.txt has zero influence on the artifact.

**RCA (named): Dual source-of-truth drift.** Pins live in a file (`requirements.txt`) that none of the three documented install flows consume; the consumed file (`pyproject.toml`) carries only floors. Result: the "pinned" versions are decorative.

**Brainstorm.**
- (A) Make pyproject the single source: move exact pins into `dependencies` (e.g. `numpy==1.26.4`). Then Colab/local/VM all get the same versions. Downside: editable installs become rigid (fine for a reproducible PFE).
- (B) Generate a constraints file and install with `pip install -e . -c constraints.txt` everywhere (notebook + Makefile + VM). Keeps pyproject ranges for flexibility while pinning the resolved set. **Recommended** — standard "abstract deps in pyproject, concrete pins in a lockfile/constraints" pattern; smallest behavioral surprise.
- (C) Delete requirements.txt and add upper bounds to pyproject (`>=1.26,<2`). Cheapest but still not byte-reproducible.

**Plan.**
1. Adopt (B): keep `requirements.txt` as the constraints file; change notebook cell 2, `Makefile:install`, and README to `pip install -e . -c requirements.txt`.
2. Document on VM the same command.
3. Verify: in a clean venv `pip install -e . -c requirements.txt` then `pip freeze | grep -E 'numpy|scikit-learn|tensorflow'` matches the pins.

## Issue 2 — sklearn .pkl cross-version load (train→serve) (P1)

**Audit.**
- Producer: notebook saves `joblib.dump(scaler|iso_forest|ocsvm, …)` (`.pkl`).
- Consumer: `src/ueba/integration/daemon.py:80-91` `joblib.load("scaler.pkl"|"isolation_forest.pkl"|"one_class_svm.pkl")`. No version check; on mismatch sklearn emits `InconsistentVersionWarning` and may silently mis-deserialize estimator internals.
- Good: the Autoencoder is saved/loaded as native `.keras` (`daemon.py:95-108` comment explicitly avoids pickle for Keras 3) — that one is safe.
- The skew is real precisely because of Issue 1: Colab resolves latest sklearn, VM (if it ever installs requirements.txt) gets 1.5.0.

**RCA (named): Train/serve version skew on a pickle boundary.** Pickled sklearn estimators are not guaranteed loadable across sklearn versions, and nothing pins both ends to the same version.

**Brainstorm.**
- (A) Fix Issue 1 so both ends pin identical sklearn → eliminates the skew at the source. **Recommended.**
- (B) Add a startup guard in daemon: read `sklearn.__version__`, compare to a version stamped into a sidecar `models/manifest.json` written at train time; refuse to load on mismatch (fail loud > silent corruption).
- Recommend A+B together: A prevents it, B detects it.

**Plan.**
1. Pin sklearn identically (Issue 1 plan).
2. (Optional hardening) emit `{"sklearn": <ver>}` at dump time and assert at load.
3. Verify: NOT VERIFIABLE WITHOUT VM — needs a model trained on Colab then loaded by the VM venv. Locally reproducible by training under sklearn 1.6 and loading under 1.5 and observing the warning.

## Issue 3 — NumPy 2.x / newer-TF resolution on fresh Colab (P1)

**Audit.**
- `pyproject.toml:23,27`: `numpy>=1.26`, `tensorflow>=2.16` (no upper bound).
- `requirements.txt` pins tf==2.16.1 (built against NumPy 1.x) + numpy==1.26.4 — but per Issue 1 these are not installed on Colab.
- A fresh `pip install -e .` lets the resolver choose the newest compatible TF and NumPy. NumPy 2.0 broke ABI for libs compiled against 1.x; TF 2.16.x predates official NumPy-2 support (added ~2.17+). Mixing pinned-2.16.1 with NumPy 2 would crash at import; with ranges the resolver normally pulls a newer TF + NumPy 2, which usually works but is a different stack than the "tested" 2.16.1 — i.e. the documented env is not what runs.
- Cached vs fresh Colab differ: a warm runtime may already have a NumPy/TF that the resolver leaves untouched, so two students get two stacks.

**RCA (named): Unbounded major-version drift.** Open upper bounds on a tightly-ABI-coupled trio (numpy/tensorflow/keras) let the resolver pick a NumPy-2-era stack that diverges from the pinned, tested combination.

**Brainstorm.**
- (A) Add upper bounds in pyproject (`numpy>=1.26,<2`, `tensorflow>=2.16,<2.17`) — pins the tested era while staying a range. **Recommended** as a minimum; pairs with Issue 1 (B).
- (B) Full exact pins via constraints (Issue 1 B) — strongest.
- (C) Leave as-is and rely on Colab's preinstalled stack — fragile, breaks the "reproducible in 6 months" goal.

**Plan.**
1. Add `<2` to numpy and a TF upper bound consistent with the pinned tf, OR adopt constraints install.
2. Verify: NOT fully verifiable here without installing TF (heavy, out of scope). Dry-run `pip install --dry-run -e .` on a clean index would show the resolved versions.

## Issue 4 — `keras==3.3.3` declared but unused / not a pyproject dep (P2)

**Audit.**
- `requirements.txt:19` `keras==3.3.3`; absent from `pyproject.toml` dependencies.
- All code uses `from tensorflow import keras` / `tensorflow.keras` (notebook cell 4; `daemon.py:106`). TF 2.16 vendors Keras 3, so a separate `keras` install is redundant and can even shadow `tf.keras`.

**RCA (named): Vestigial dependency.** Standalone keras left over from a pre-TF-2.16 layout; harmless on LIVE path (it's in the dead file) but misleading.

**Brainstorm.** (A) Drop `keras` from requirements.txt. **Recommended.** (B) If a standalone keras is ever wanted, add it to pyproject and set `TF_USE_LEGACY_KERAS` policy explicitly — overkill here.

**Plan.** Remove line; verify notebook + daemon still import via `tensorflow.keras` (already the case).

## Issue 5 — `make train` needs nbconvert/jupyter not in `[dev]` (P2)

**Audit.**
- `Makefile:34-38`: `train:` runs `jupyter nbconvert --to notebook --execute …`.
- `pyproject.toml [project.optional-dependencies] dev` (38-46): pytest, pytest-cov, black, ruff, ipykernel, notebook — **no nbconvert, no `jupyter` CLI**. (`notebook>=7.2` pulls nbconvert transitively in practice, but the `jupyter` console entry point is provided by `jupyter-core`/`jupyter-console`, not guaranteed.)
- `requirements-dev.txt:20` DOES list `nbconvert==7.16.4` — but `make install-dev` installs `.[dev]`, not requirements-dev.txt. Same dual-source drift as Issue 1.
- `make train` also doesn't ensure the venv has the package installed; it relies on ambient `jupyter`.

**RCA (named): Makefile target depends on undeclared tooling.** The extras set consumed by `make install-dev` omits the tool `make train` invokes.

**Brainstorm.**
- (A) Add `nbconvert>=7.16` (and ensure a `jupyter` entry point) to `[project.optional-dependencies].dev`. **Recommended** — keeps `make install-dev && make train` self-consistent.
- (B) Change `make train` to `python -m nbconvert …` (more robust than the `jupyter` shim) and add nbconvert to dev.

**Plan.** Add nbconvert to `[dev]`; optionally switch Makefile to `python -m jupyter nbconvert`. Verify `make install-dev && make train` on a clean venv.

## Issue 6 — VM1 install undocumented (P2)

**Audit.** `README.md:193-215` systemd unit references `/opt/ueba-ml/venv/bin/python` and `WorkingDirectory=/opt/ueba-ml`, but nothing documents creating that venv or running `pip install`/which dependency file. Combined with Issue 1, the VM env is undefined → it could be the loose ranges or the pins, nondeterministically.

**RCA (named): Missing deploy bootstrap.** Docs cover clone+train (Colab) and the final systemd unit, but skip the VM provisioning step that determines serve-side versions.

**Brainstorm.** (A) Add a VM section: `python3 -m venv /opt/ueba-ml/venv && /opt/ueba-ml/venv/bin/pip install -e . -c requirements.txt`. **Recommended** (ties to Issue 1/2 fix). (B) Ship the trained `models/` to the VM out-of-band and document copying them (since models/ is gitignored — see Issue below).

**Plan.** Document VM venv + install + model transfer. Verify: NOT VERIFIABLE WITHOUT VM.

## Issue 7 — ruff config uses deprecated top-level select/ignore (P3)

**Audit.** `pyproject.toml:55-59` `[tool.ruff]` with `select`/`ignore` at top level. Dep floor `ruff>=0.4`. Ruff ≥0.6 deprecated top-level `select`/`ignore` in favor of `[tool.ruff.lint]`; with the open `>=0.4`, `make install-dev` gets the latest ruff and `make lint` emits a deprecation warning (still runs today, may error in a future major).

**RCA (named): Lint config schema drift vs unbounded ruff.** Pre-0.6 config layout combined with an open ruff floor.

**Brainstorm.** (A) Move `line-length`/`target-version` keep top-level, move `select`/`ignore` under `[tool.ruff.lint]`. **Recommended.** (B) Cap `ruff<0.6` — discourages updates, worse.

**Plan.** Restructure to `[tool.ruff.lint]`. Verify `ruff check src/ tests/` no deprecation warning.

## Issue 8 — Author personal email in metadata (P3)

**Audit.** `pyproject.toml:9` `authors = [{name="Assia", email="sia.el2020@gmail.com"}]`. Build evidence: this is copied verbatim into wheel `METADATA` (`Author-email`). Note the project also belongs to user linalaaraich2002@gmail.com — author attribution mismatch plus PII leakage into every artifact and (if ever published) PyPI.

**RCA (named): PII in distributable metadata.** Personal email hardcoded in package metadata.

**Brainstorm.** (A) Use a role/team alias or the actual maintainer's chosen contact. **Recommended.** (B) Remove the email field, keep name only. Minor; not a security vuln, an info-leak/correctness nit.

**Plan.** Update authors field; rebuild and confirm METADATA `Author-email`.

## Issue 9 — scripts call `python` not `python3` (P3)

**Audit.** `scripts/export_dataset.sh:14` and `scripts/run_daemon.sh:15` call `python …`. Makefile uses `python3`. On a fresh Ubuntu 24.04 VM, `python` may be unmapped (only `python3`), or inside the venv `python` exists — so it works IFF the venv is activated. README invokes scripts without mentioning activation.

**RCA (named): Interpreter name assumption.** `python` vs `python3` inconsistency; depends on PATH/venv state.

**Brainstorm.** (A) Use `python3` in scripts for parity with Makefile. (B) Prepend a `${PYTHON:-python3}` indirection. **Recommend (A)** for simplicity (note: inside an activated venv `python3` also resolves).

**Plan.** Swap `python` → `python3` in both scripts; verify `bash scripts/export_dataset.sh --help`-style dry run resolves the interpreter.

## Issue 10 — Hardcoded upstream clone URL in notebook (P3)

**Audit.** Notebook cell 2 clones `https://github.com/assia-xnz/pfe-ueba-ml.git`; `git remote` of this checkout = same. If a student forks (e.g. under linalaaraich2002), opening the notebook in Colab still clones the ORIGINAL repo, silently ignoring the fork's changes — a reproducibility footgun.

**RCA (named): Hardcoded upstream.** Clone URL not parameterized.

**Brainstorm.** (A) Parameterize `REPO_URL = os.environ.get('UEBA_REPO_URL', '<default>')`. (B) Document "edit this URL if you forked." **Recommend (A).**

**Plan.** Make URL a variable; verify clone still succeeds with default.

---

## CONFIRMED FINE

- **Build backend fix (the already-applied fix):** `pyproject.toml:3` `build-backend = "setuptools.build_meta"` is correct. Verified: `python -m build --wheel` (isolated) in a temp venv → `Successfully built ueba_ml-0.1.0-py3-none-any.whl`. (A `--no-isolation` build fails only because the bare venv lacks setuptools — expected, not a defect.)
- **src layout / package discovery:** `[tool.setuptools.packages.find] where=["src"]` (pyproject:52-53) correct. Wheel contains `ueba/`, `ueba/features/`, `ueba/integration/`, `ueba/config.py`; `top_level.txt = ueba`. Distribution name `ueba-ml` ≠ import name `ueba` — intentional and consistent everywhere (README `pip install -e .`, imports `from ueba…`).
- **Entry points resolve to real callables:** wheel `entry_points.txt` → `ueba-export = ueba.features.parse_logs:main`, `ueba-daemon = ueba.integration.daemon:main`. Both `main()` exist (`parse_logs.py:358`, `daemon.py:379`); `ueba-export` has the required argparse `filepath` arg.
- **Keras model serialization:** saved/loaded as native `.keras` (notebook `.save(... .keras)`, `daemon.py:103-107`) — correctly avoids the pickle cross-version trap for the deep model. The pickle risk is sklearn-only (Issue 2).
- **Shell scripts hygiene:** both scripts have `set -euo pipefail` and robust `cd "$(dirname "$0")/.."` so they work from any CWD. (Only nit is `python` vs `python3`, Issue 9.)
- **.gitignore — intentional model/data exclusion is correct:** `models/*.pkl|*.keras|*.json` and `data/*.csv|*.json` ignored (lines 23-27). The notebook handles a fresh clone with no models/data: it `os.makedirs(MODELS_DIR, exist_ok=True)` before dumping, and defaults to synthetic data (`USE_REAL_DATA=False`, README:101). `models/.gitkeep` and `data/.gitkeep` keep the dirs present. No accidental inclusion of secrets; no accidental exclusion of source. Note `models/*.json` being ignored also hides `ae_threshold.json`/manifest — fine since they're regenerated, but worth knowing for VM deploy (must copy models out-of-band, see Issue 6).
- **No secrets / no untrusted pip source:** scripts and pyproject contain no tokens/keys; only install source is the public GitHub repo over HTTPS + PyPI. The author email (Issue 8) is the only PII.
- **Makefile correctness (besides Issue 5):** install/install-dev/test/lint/format/clean targets use `python3 -m <tool>`; pytest/ruff/black are in `[dev]`, so `make install-dev` then test/lint/format are self-consistent. `make export-dataset`/`run-daemon` correctly use `python3 -m ueba.…`. `clean` is idempotent. `.PHONY` is complete.

## NOT VERIFIABLE WITHOUT VM (or heavy install)

- Issue 2 cross-version pickle load: needs a model trained on the real Colab stack loaded by the real VM venv.
- Issue 3 exact resolved NumPy/TF on a fresh Colab: would require installing tensorflow (out of scope — heavy); the risk is structural (open upper bounds), the realized versions depend on Colab's index at run time.
- Issue 6 VM provisioning: no VM available to confirm `/opt/ueba-ml/venv` workflow.
- Whether `make train`'s `jupyter` entry point exists after `make install-dev` depends on the transitive deps of `notebook>=7.2` at install time (not pinned) — verifiable only by installing the dev extras.
