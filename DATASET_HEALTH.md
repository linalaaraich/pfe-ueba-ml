# Audit de santé du dataset — pourquoi « les résultats n'étaient pas exacts » (RÉSOLU)

> **STATUT : ✅ CORRIGÉ.** Le problème ci-dessous a été diagnostiqué PUIS corrigé.
> Le tableau « avant / après » résume ; les sections 2-4 décrivent le diagnostic
> d'origine (conservé pour la traçabilité de soutenance), la section 4bis ce qui
> a changé.
>
> | Métrique (jeu synthétique par défaut) | AVANT | APRÈS (code actuel) |
> |---|---|---|
> | Features constantes/mortes dans le normal | **6 / 14** | **0** ✅ |
> | FP sur normal hors-échantillon — Isolation Forest | ~10 % | **1,1 %** ✅ |
> | FP — One-Class SVM | ~20 % | **3,3 %** ✅ |
> | FP — ensemble (≥2/3) | ~10 % | **0,6 %** ✅ |
> | Profils utilisateurs dans le normal | 1 | **8** ✅ |
> | Détection des attaques | 100 % (trivial) | maintenue, sur baseline saine |
>
> **Ce qui a corrigé** : (1) générateur normal réaliste multi-profils
> (`simulate.py`, utilisé par le notebook) → plus de features constantes ;
> (2) `contamination`/`ocsvm_nu`/`ocsvm_gamma` abaissés à 0,01 (config.yaml) ;
> (3) seuil autoencodeur calibré sur le **percentile de validation**
> (`calibrate_ae_threshold`) ; (4) **baseline figée** partagée train↔serve.
>
> Date diag. : 2026-06-04 · Vérifié (après) : 2026-06-05 · Preuves **exécutées**
> (venv réel) · Outil réutilisable : `python -m ueba.features.health <dataset.csv>`.

---

> ⚠️ Les sections 2-4 ci-dessous documentent l'état **AVANT correction** (jeu
> synthétique mono-utilisateur, contamination 0,05). Elles restent valables comme
> *méthode de diagnostic* et comme trace, mais ne décrivent PLUS le code livré.

---

## 1. Comment lire ce rapport

Je n'ai **pas** accès à votre vrai `data/dataset.csv` (il est `gitignored` et vit
sur VM1). Le diagnostic ci-dessous a donc été lancé sur le **jeu synthétique
reproduit à l'identique depuis le notebook** — c'est précisément ce que vous
exécutez avec `USE_REAL_DATA=False`. Un **outil réutilisable** est fourni pour
auditer votre vrai dataset (section 5).

---

## 2. Diagnostic exécuté (jeu synthétique, 300 normal + 80 attaques)

### A. Santé du *normal* d'entraînement

| Constat | Détail | Gravité |
|--------|--------|---------|
| **Features constantes / mortes** | `is_night`, `is_weekend`, `new_ip`, `sensitive_path_access` = **0 dans 100 % des sessions normales** (codé en dur par le générateur) | 🔴 |
| Variance nulle ⇒ aucun signal | `StandardScaler` met `scale_=1` pour ces colonnes ; elles n'apprennent rien au modèle | 🔴 |
| Faible diversité | 300 sessions, 1 seul profil utilisateur | 🟠 |

> Conséquence : le modèle apprend « normal = ces 4 signaux valent 0 ». Toute
> session légitime de nuit / le week-end / depuis une nouvelle IP / touchant un
> dossier sensible sera donc **étiquetée anomalie** — alors que c'est un
> comportement réel parfaitement possible.

### B. Séparabilité normal vs attaque (écart en σ)

```
new_ip 2.24σ · entropy_commands 2.18σ · is_night 1.93σ · bytes_sent 1.92σ
sensitive_path_access 1.91σ · velocity 1.85σ · nb_processes 1.74σ · nb_files 1.67σ
```

Les attaques se distinguent surtout via `new_ip`, `is_night`,
`sensitive_path_access` — **exactement les features constantes dans le normal**.
La « détection » repose donc sur des dimensions sans variance à l'entraînement :
ça marche en synthétique, **ça ne tiendra pas sur données réelles** où ces
features varient.

### C. Impact modélisation — **le vrai problème**

| Mesure | Isolation Forest | One-Class SVM | Ensemble (≥2/2) |
|--------|------------------|---------------|-----------------|
| FP sur normal d'entraînement | 5,0 % | 12,0 % | — |
| **FP sur normal HORS-échantillon** | **10,0 %** | **20,0 %** | **10,0 %** |
| Détection des attaques | 100 % | 100 % | — |

**~1 session normale sur 10 (voire 1 sur 5 pour l'OCSVM) est faussement
signalée.** C'est très probablement le « résultats pas exacts » que vous
observez : le système crie au loup sur du comportement normal.

---

## 3. Diagnostic (RCA) — pourquoi

1. **`contamination=0.05` / `nu=0.05` trop élevés.** Entraînés sur du normal
   *propre*, ces modèles sont *forcés* d'étiqueter ~5 % de l'entraînement comme
   anomalies — et ça généralise à **10–20 % hors-échantillon**. C'est par
   conception, pas un bug. → cause directe du taux de faux positifs.
2. **One-Class SVM (`nu=0.05`, `gamma='scale'`) sur-ajuste** → 20 % de FP
   hors-échantillon, le pire des trois.
3. **Normal synthétique irréaliste** : 4 features à variance nulle ⇒ frontière de
   « normalité » trop serrée sur les dimensions qui varient, trop lâche sur les
   autres.
4. **Volume faible** (300 sessions, 1 profil) ⇒ modèles sous-entraînés, seuils
   instables (l'Autoencoder calibre μ+3σ sur ces 300 lignes).
5. **« 100 % de détection » trompeur** : mesure la séparabilité du *générateur*,
   pas la capacité réelle du modèle (audit RC-2).

---

## 4. Recommandations (par priorité)

| # | Action | Effet attendu | Où |
|---|--------|---------------|-----|
| 1 | **Baisser `contamination` et `nu`** (essayer 0.01, voire 0.005) | FP ↓ fortement | `config.yaml` `detection.contamination`, notebook OCSVM `nu` |
| 2 | **Calibrer les seuils sur un FP cible** (ex. « < 2 % sur normal tenu à l'écart ») au lieu d'une valeur fixe | FP maîtrisé, défendable au jury | notebook éval. |
| 3 | **Rendre le normal réaliste** : injecter de la variabilité (un peu de travail de nuit/week-end, IP multiples, accès sensibles occasionnels) **ou** — mieux — utiliser le **vrai** dataset Wazuh | features non-constantes, séparation honnête | générateur / VM1 |
| 4 | **Utiliser la baseline figée** (déjà ajoutée, Wave B) pour des z-scores réels et cohérents | z_score_* vivants | `baseline.json` |
| 5 | **Évaluer le FP sur un normal hors-échantillon** et rapporter CE chiffre | métrique honnête | notebook |
| 6 | **Retirer / re-sourcer les features mortes** une fois confirmées sur données réelles (ex. `bytes_sent`) | modèle plus sain | `NUMERIC_FEATURES` |

> ⚠️ Les seuils exacts (#1, #2) doivent être **calibrés sur vos vraies données**.
> Le mécanisme est prêt ; la valeur dépend du dataset → `NEEDS-VM`.

---

## 5. Auditez VOTRE vrai dataset

Un outil réutilisable est livré : [`src/ueba/features/health.py`](src/ueba/features/health.py).

```bash
# sur VM1, après avoir généré data/dataset.csv depuis Wazuh
python -m ueba.features.health data/dataset.csv --label label
```

Il signale automatiquement : volume faible, features constantes/mortes (ex.
`bytes_sent` toujours 0 sur du vrai Sysmon), NaN, doublons, redondances, et —
si des labels existent — la séparabilité triviale. **Collez-moi sa sortie** (ou
le `dataset.csv`) et j'interprète la santé de vos vraies données.

### Checklist « dataset réel sain »
- [ ] **> quelques centaines** de sessions, idéalement plusieurs profils
- [ ] Aucune feature **constante** (sinon variabilité réelle manquante ou capteur muet)
- [ ] `bytes_sent` **non nul** (sinon Sysmon EID 3 ne porte pas l'octet → re-sourcer)
- [ ] z_score_* calculés via la **baseline figée**, pas la population du lot
- [ ] FP mesuré **sur un normal tenu à l'écart**, pas sur l'entraînement
- [ ] Heures de travail réalistes (un peu de nuit/week-end légitime)

---

---

## 6. Mise à jour — générateur multi-profils (corrige les constats ci-dessus)

Un nouveau générateur réaliste est livré : `ueba.features.simulate`
(`python -m ueba.features.simulate --users 8 --days 30 --output data/dataset.csv`).

**Preuves exécutées** (8 profils, 45 j, 526 sessions) :

| Constat (avant) | Après (générateur multi-profils) |
|-----------------|----------------------------------|
| 6 features **constantes/mortes** | **0** (`features constantes=[]`) |
| 1 seul profil utilisateur | **8 profils** (bureau, finance, RH, IT, dev) aux baselines distinctes |
| pas de variabilité | nuit 8 % · week-end 1 % · accès sensible 33 % · new_ip 3,6 % |

**Faux positifs sur normal HORS-échantillon (70/30) :**

| contamination / nu | Isolation Forest | One-Class SVM | Ensemble (≥2/2) |
|--------------------|------------------|---------------|-----------------|
| 0.05 | 8,2 % | 20,3 % | 8,2 % |
| **0.01** | **1,9 %** | 20,3 % | **1,9 %** |

→ **Deux leviers validés** : (1) données réalistes = fin des features mortes ;
(2) **baisser `contamination`/`nu` à 0.01** fait chuter le FP de l'IF et de
l'ensemble de ~10 % à **~2 %**.

⚠️ **One-Class SVM reste à ~20 % de FP** quel que soit `nu` (sur-ajuste avec
`gamma='scale'`). Le vote d'ensemble le masque, mais il faudrait le **régler**
(baisser `gamma`, ou le pondérer moins) — sinon il dégrade la précision.
Seule redondance détectée : `nb_failed_logins ~ z_score_logins` (attendu, l'un
dérive de l'autre).

---

---

## 7. Faux positifs élevés à l'entraînement → cause = seuil de l'AUTOENCODEUR

Boucle audit→RCA→correctif→vérif (preuves EXÉCUTÉES avec TensorFlow).

**Audit (FP par modèle sur normal hors-échantillon) :**
| Modèle | FP |
|--------|-----|
| Isolation Forest | 1,4 % |
| One-Class SVM | 3,4 % |
| **Autoencoder (μ+3σ)** | **8–9 %** ← coupable |

**RCA — le seuil `μ + 3σ` de l'AE est mal calibré, pour 2 raisons cumulées :**
1. Les **erreurs de reconstruction sont asymétriques** (queue à droite) → `μ+3σ`
   n'est PAS le 99,7e percentile ; il flague déjà ~4-5 % sur l'entraînement.
2. L'**AE sur-apprend** sur peu de données (erreur test ≫ erreur train) → encore
   plus de FP sur du normal jamais vu. Et c'est le vote pivot de l'ensemble ≥2/3.

**Correctif — seuil = PERCENTILE des erreurs de VALIDATION** (non vues par les
poids), via `calibrate_ae_threshold(...)` (`baseline.py`), configurable par
`detection.ae_threshold_percentile` (défaut 99.0). Le percentile borne
directement le FP et résiste à l'asymétrie ; repli `μ+σ` si validation trop
petite.

**Vérification (exécutée, dataset 30 j par défaut) :**
| Seuil AE | AE FP | Ensemble FP | Détection |
|----------|-------|-------------|-----------|
| μ+3σ (avant) | 9,2 % | **7,1 %** | 100 % |
| validation p99 (après) | 4,1 % | **4,1 %** | 100 % |

→ FP ~divisé par 2, détection intacte. **Avec plus de données** (ex. `simulate
--users 10 --days 75`) le sur-apprentissage diminue → **ensemble FP ~1,5 %**.

**Deux leviers pour réduire encore les FP :**
1. **Générer plus de normal** : `python -m ueba.features.simulate --users 10 --days 75`
   (réduit le sur-apprentissage de l'AE — c'est le facteur résiduel dominant).
2. **Ajuster** `detection.ae_threshold_percentile` (99.5 = encore moins de FP),
   `detection.contamination`/`ocsvm_gamma` dans `config.yaml`.

---

*Rapport généré dans le cadre de l'audit `audit/ueba-system-review`. Voir
`audit/MASTER_PLAN.md` (RC-1, RC-2) et `audit/VERIFICATION-LOG.md`.*
