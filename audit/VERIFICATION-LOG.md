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
  → exécuté en arrière-plan, résultat consigné ici une fois terminé.
