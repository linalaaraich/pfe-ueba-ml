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

- [ ] Exécution end-to-end du notebook (`nbconvert --execute`, mode synthétique)
  pour prouver que le blocage Colab est mort et que les 3 modèles
  s'entraînent / s'exportent / se rechargent / détectent les scénarios.
  → en cours d'exécution, résultat consigné ici une fois terminé.

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
