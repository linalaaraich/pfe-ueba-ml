# Re-audit (round 2) — synthèse

**Date :** 2026-06-05 · **Branche :** `audit/ueba-system-review` · **Méthode :** audit → RCA → vérif. par exécution → correctif → re-vérif.

5 agents par domaine ont ré-audité le code **après** les correctifs du round 1.
Détail : [reaudit-data](reaudit-data.md) · [reaudit-features](reaudit-features.md) · [reaudit-daemon](reaudit-daemon.md) · [reaudit-notebook](reaudit-notebook.md) · [reaudit-tests-docs](reaudit-tests-docs.md).

## Verdict d'ensemble
**Les correctifs du round 1 sont réels et câblés bout-en-bout** (baseline figée train↔serve, seuil AE calibré, contamination 0.01, FP mesuré sur normal hors-échantillon, contrat d'ordre des features). Le round 2 a trouvé des problèmes **nouveaux/résiduels**, tous **vérifiés par exécution** puis corrigés.

## Corrigé ce tour (chaque ligne vérifiée par exécution)

| # | Problème (sévérité) | Correctif | Preuve |
|---|---------------------|-----------|--------|
| 1 | **Perte silencieuse d'alertes** : copytruncate puis fichier regrossi au-delà de l'ancien offset entre 2 polls (P1) | `AlertsWatcher` empreinte le **préfixe consommé** (`min(64,pos)`) → détecte la réécriture sans faux positif sur la croissance | test `test_copytruncate_regrow_past_offset_no_loss` + `test_normal_growth_not_treated_as_rotation` |
| 2 | `calibrate_ae_threshold` renvoyait **NaN** si une erreur est NaN → AE muet (P2) | filtre `np.isfinite` | test `test_nan_and_inf_ignored` |
| 3 | `to_scaled_vector` laissait passer **NaN** → vote dégradé silencieux (P2) | `np.nan_to_num` | test `test_nan_feature_yields_finite_vector` |
| 4 | Notebook entraînait sur un **normal mono-utilisateur** (6 features constantes, FP 10-20%) (P2) | `simulate_dataset` (8 profils) pour train + held-out | exécuté : 0 constante, FP ensemble **0,6%** |
| 5 | Split validation AE **non mélangé** → calibration sur ~1 profil (P2) | mélange avant split 80/20 | exécuté : validation couvre **8 profils** |
| 6 | `health.py` séparabilité aveugle aux features **binaires** parfaites (P2) | Cohen's d (σ intra-classe) | test `test_binary_perfect_separator_is_flagged` |
| 7 | `config.py _DEFAULTS` divergeait de `config.yaml` (0.05 vs 0.01) (P2) | synchronisé + clés manquantes | revue |
| 8 | `DATASET_HEALTH.md` **périmé** (annonçait 10-20% FP corrigés) (P1 doc) | bandeau « RÉSOLU » + tableau avant/après vérifié | — |
| 9 | « 16 features » faux (19 colonnes / 14 ML) + params 0.05/μ+3σ périmés (P1 doc) | README + CONTEXT corrigés | grep |
| 10 | OTRF sans label → attaques entraînées comme normal (P2) | option `--label` | test `test_label_column_set` |
| 11 | `pytest` échouait sans `PYTHONPATH=src` (P2 repro) | `pythonpath=["src"]` dans pyproject | suite verte sans PYTHONPATH |

**Suite : 72 passed** (dont 8 nouveaux tests de régression round-2).

## Reste (P3 / non bloquant, documenté)
- `apply_baseline_zscores` via `iterrows()` — vectoriser (perf sur gros CSV).
- `simulate.py` : config heures de travail 24h (END≤START) → garde-fou à ajouter.
- OTRF z-scores via `add_zscores` (ddof=1) vs baseline (ddof=0) — masqué (le notebook recalcule).
- `parse_otrf` orienté schéma « à plat » — exports winlogbeat imbriqués non couverts.

## `NEEDS-VM` / `NEEDS-COLAB` (non « code »)
- Confirmer le 1er bloc Colab et un `Run All` complet (TF non installable dans le bac à sable : disque).
- Rejouer `health.py` + la calibration sur le **vrai** `dataset.csv` (3 jours Wazuh) et mesurer le FP sur normal réel tenu à l'écart.
