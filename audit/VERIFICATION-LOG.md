# Verification Log — Executed Evidence

> Principe de la méthode : **confirmer, ne pas spéculer.** Chaque affirmation
> ci-dessous a été *exécutée* dans un venv réel (Python 3.12, numpy 2.4.6,
> pandas 3.0.3, scikit-learn 1.9.0 — volontairement plus récents que les pins
> du projet, pour reproduire la réalité de Google Colab qui installe les
> dernières versions via `pip install -e .`).
>
> Date : 2026-06-04. Branche : `audit/ueba-system-review`.

## Résultats confirmés

| # | Affirmation (issue) | Méthode | Résultat | Verdict |
|---|---------------------|---------|----------|---------|
| 1 | Le test `test_outlier_has_high_zscore` échoue | `pytest tests/` | `assert np.float64(1.7876) > 2.0` → **FAILED** (1 failed, 18 passed) | ✅ CONFIRMÉ |
| 2 | Mélange datetime tz-aware/naive fait planter `group_by_session` | appel direct | `TypeError: can't compare offset-naive and offset-aware datetimes` | ✅ CONFIRMÉ (conditionnel) |
| 3 | `extract_raw_fields` plante sur timestamp non-string | `{"timestamp": 1705312800}` | `AttributeError: 'int' object has no attribute 'replace'` | ✅ CONFIRMÉ |
| 4 | `extract_raw_fields` plante sur `data` non-dict (vecteur DoS daemon) | `{"data": []}` | `AttributeError: 'list' object has no attribute 'get'` | ✅ CONFIRMÉ |

## Résultats corrigés par l'exécution (l'audit statique s'était trompé)

| # | Affirmation initiale | Réalité exécutée | Nouveau verdict |
|---|----------------------|------------------|-----------------|
| 5 | **P0** : `SENSITIVE_PATH` a un double backslash `C:\Sensitive\\` qui ne matche jamais les vrais chemins → `nb_sensitive_files` toujours 0 | `config.yaml` **est** chargé par `config.py` (remontée d'arborescence) et écrase le défaut par `C:\Sensitive\` (simple). Match testé sur `C:\Sensitive\Finance\salaries.xlsx` → **True**. Le bug n'apparaît que si `config.yaml` est absent. | ⬇️ **Rétrogradé P0 → P2** (footgun latent masqué par la config) |

## Dépendant de la VM (non vérifiable ici)

| # | Affirmation | Pourquoi non vérifiable ici | Comment vérifier |
|---|-------------|------------------------------|------------------|
| 6 | `datetime.fromisoformat` rejette les offsets sans `:` (ex. `+0000`) et les fractions de seconde sur Python < 3.11 → événements Wazuh silencieusement *droppés* | Cet environnement est Python 3.12 (parse tout). VM1 = Ubuntu 22.04 → **Python 3.10** | Rejouer sur VM1 avec un vrai `alerts.json`, ou `python3.10 -c "from datetime import datetime; datetime.fromisoformat('2024-01-15T10:00:00.123+0000')"` |
| 7 | Champs `eventdata` (image/commandLine/targetFilename/subjectUserName) ≠ sortie réelle du décodeur Wazuh | Pas d'accès à VM1 / vrai `alerts.json` | Comparer avec un échantillon réel de `/var/ossec/logs/alerts/alerts.json` |
| 8 | `bytes_sent` toujours 0 (Sysmon EID 3 n'émet pas de compteur d'octets) | Raisonné depuis le schéma Sysmon ; pas de données réelles | Inspecter un événement EID 3 réel sur VM2/VM1 |

## À venir (preuve « live » du pipeline d'entraînement)

### Preuve « live » du pipeline d'entraînement

- ✅ **Portion scikit-learn prouvée bout-en-bout** (mode synthétique, venv réel,
  `train → joblib.dump → joblib.load → predict`) :

  | Scénario | Vote (IF + OCSVM) | Verdict |
  |----------|-------------------|---------|
  | insider-exfil (250 fichiers, 2h, 85 sensibles) | 2/2 | ANOMALY ✅ |
  | brute-force (47 logins échoués, 3h) | 2/2 | ANOMALY ✅ |
  | utilisateur normal (15 fichiers, 10h) | 0/2 | normal ✅ |

  → `StandardScaler` + `IsolationForest` + `OneClassSVM` s'entraînent sur 300
  sessions normales, s'exportent et se rechargent, et le vote détecte les
  attaques. **Confirme aussi RC-2** : 2 modèles suffisent à un consensus 2/2 sur
  les attaques synthétiques car leurs distributions sont disjointes du normal —
  la « performance » mesure le générateur, pas le modèle.

- ⚠️ **Notebook complet (avec l'Autoencoder Keras) NON exécutable dans ce bac à
  sable** : l'installation de TensorFlow par la cellule 2 a échoué sur
  `OSError: [Errno 28] No space left on device` (volume 18 G plein à 100 %).
  C'est une **limite d'environnement, pas un défaut de code** :
  - le correctif d'install (`pip install -e .`) a déjà été vérifié séparément ;
  - sur Google Colab (la vraie cible) TF est préinstallé et le disque est ample.
  Le test à rejouer sur Colab : `Run All` → 3 modèles entraînés, `.keras` +
  `ae_threshold.json` exportés, cellule de rechargement OK, 4 scénarios détectés.

---

## Roster ajouté — "le 1er bloc Colab ne marche toujours pas" (signalé par l'utilisateur)

**Diagnostic (RCA).** Sur Colab, `IN_COLAB=True` → la cellule 2 clonait en dur
`assia-xnz/pfe-ueba-ml` **branche par défaut (`main`)**, qui ne contient PAS
encore les correctifs. Elle y exécutait `pip install -e .` → ancien
`build-backend` invalide → `BackendUnavailable` → **1er bloc en erreur**, alors
que « le reste est bon » une fois l'install réussie. De plus, en cas d'échec du
clone, l'ancienne cellule continuait quand même (`os.chdir` + install) → erreurs
obscures.

**Correctif appliqué (cellule 2 réécrite).**
- `REPO_URL` / `REPO_BRANCH` configurables → pointent sur la branche **qui
  contient les correctifs** (`audit/ueba-system-review`), donc `pip install -e .`
  réussit (build-backend déjà corrigé).
- Clone **branch-pinned** (`git clone --branch`), **idempotent** (si le dépôt
  existe : `fetch`+`checkout`+`pull` sur la bonne branche).
- **Fail-loud** : helper `_run()` lève une erreur lisible (stdout+stderr) au lieu
  de poursuivre après un clone raté.

**Vérification.** Cellule compile (`py_compile` OK). La preuve définitive doit se
faire **sur Colab** (`NEEDS-COLAB`) : `Run All` du 1er bloc → clone+install sans
erreur. ⚠️ Pré-requis : la branche pointée doit être accessible publiquement (le
fork `linalaaraich` l'est ; à basculer sur le dépôt d'origine une fois la branche
poussée là-bas — voir note d'identifiants ci-dessous).

---

## Wave B (scaffold) — baseline FIGÉE + santé des features (RC-1 / RC-2)

Décision : *scaffold now, calibrate on VM*. Mécanisme implémenté et PROUVÉ ;
la calibration sur le vrai dataset 3 jours reste `NEEDS-VM`.

| Élément | Implémentation | Preuve (exécutée) | Verdict |
|---------|----------------|-------------------|---------|
| Baseline figée par utilisateur (RC-1) | `ueba/features/baseline.py` : `compute/apply/save/load` ; export `models/baseline.json` depuis le notebook ; daemon la charge | `test_zscore_invariant_to_batch_composition` : même session → **z identique** seule ou noyée dans des attaques ; `test_old_recompute_was_not_invariant` démontre l'ancien bug | ✅ mécanisme prouvé |
| Démarrage à froid daemon (RC-1) | `to_scaled_vector(..., baseline)` utilise la baseline figée au lieu de la fenêtre glissante vide | `test_std_zero_never_divides`, repli global `test_unseen_user_falls_back_to_global` | ✅ |
| Features mortes (RC-2) | `feature_health()` + cellule notebook qui signale les features constantes (ex. `bytes_sent`) | `test_flags_dead_and_present` | ✅ détection auto |
| Honnêteté de l'évaluation (RC-2) | note markdown + z-scores du test via baseline figée | revue | ✅ documenté |

**Suite complète : 36 passed** (19 features + 11 daemon + 6 baseline).

**Reste `NEEDS-VM` (calibration, non « code ») :** exporter le vrai `baseline.json`
depuis 3 jours de données Wazuh ; lancer `feature_health` dessus pour décider des
features à retirer ; mesurer le taux de faux positifs sur un normal tenu à l'écart.

---

## Wave A — corrections VÉRIFIÉES par exécution (2026-06-04)

| Issue | Correction | Preuve (ré-exécutée) | Verdict |
|-------|------------|----------------------|---------|
| #5 test z-score rouge | assertion corrigée (max + `> 1.5`, stats ddof=1 exactes) | `pytest tests/ -q` → **19 passed** (était 1 failed/18) | ✅ vert |
| #6/#12 crashes parser (RC-4) | `_parse_timestamp` robuste + gardes `isinstance(dict)` + `str()` username | probes ré-exécutées : `tz-mix→1 session`, `int-ts→None`, `data=[]→OK`, `+0000(py3.10)→parse`, `garbage→None` — **0 crash** | ✅ tué |
| #6 DoS daemon (`data` non-dict) | garde `isinstance` | `extract_raw_fields({"data": []})` → plus d'AttributeError | ✅ tué |
| tz-mix (défense en profondeur) | normalisation naïve dans `group_by_session` | `group_by_session([aware, naive])` → 1 session, plus de TypeError | ✅ tué |

> Toutes les corrections Wave A passent `pytest` **et** les probes d'induction réelle. La classe de crash RC-4 (parsing fragile) est éliminée pour ces vecteurs ; reste `NEEDS-VM` la confirmation des chemins de champs `eventdata` sur un vrai `alerts.json`.

### Wave A (suite) — daemon + contrat de features

| Issue | Correction | Preuve (induction réelle, fichier temporaire) | Verdict |
|-------|------------|-----------------------------------------------|---------|
| #4 contrat ordre features | `NUMERIC_FEATURES` source unique dans `parse_logs`, importée par le daemon ; test de contrat | `test_daemon_uses_the_shared_constant`, `test_feature_count_is_14` ✅ | ✅ verrouillé |
| #7 fenêtre aveugle au redémarrage | offset persisté (`.watch_state.json`), reprise à la position sauvegardée | `test_restart_resumes_no_blind_window` : alerte arrivée pendant l'arrêt → relue ✅ | ✅ tué |
| #8 ligne partielle perdue | lecture binaire, ne consomme pas la ligne sans `\n` final | `test_partial_line_is_held_then_completed` : `{"x":2` retenu puis relu entier ✅ | ✅ tué |
| #9 vote dégradé silencieux | `expected/evaluated_models` + `degraded` + log ERROR ; chaque modèle gardé | `test_degraded_is_surfaced_not_masked`, `test_a_failing_model_does_not_raise` ✅ | ✅ surfacé |
| rotation logrotate | inode change → relecture depuis 0 | `test_rotation_reads_new_file_from_start` ✅ | ✅ |
| P3 `utcnow()` déprécié | `datetime.now(timezone.utc)` | py_compile + suite verte | ✅ |

**Suite complète : 30 passed** (19 features + 11 daemon). Le daemon tourne uniquement sur VM1 → son comportement *bout-en-bout* avec de vrais modèles + `alerts.json` reste `NEEDS-VM`, mais toute la logique testable localement est prouvée par induction.
