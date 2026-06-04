# CONTEXT.md — Résumé complet du projet pfe-ueba-ml
> Ce fichier explique tout ce qui a été construit, pourquoi, et comment.  
> Il sert de mémoire pour reprendre la conversation avec Claude.

---

## 1. Contexte du projet

**Titre du PFE :**  
"Design and Implementation of a Portable UEBA System for Threat Hunting in SOC:  
A Machine Learning Approach for Insider Threat and Malware Detection"

**Entreprise :** Cires Technologies (filiale de Tanger Med Group)  
**Étudiante :** Assia

### Infrastructure Azure (2 VMs)

| VM | OS | Rôle |
|----|----|------|
| VM1 | Ubuntu 24.04 | Wazuh Manager + Dashboard + Indexer |
| VM2 | Windows Server 2022 | Active Directory + Wazuh Agent + Sysmon |

- **Domaine Active Directory :** `ueba.local`
- **Utilisateur simulé :** `user_normal` (travaille 9h-18h, lundi-vendredi)
- **Repository GitHub :** `https://github.com/assia-xnz/pfe-ueba-ml`

---

## 2. Objectif du système UEBA

**UEBA = User and Entity Behavior Analytics**

L'idée est simple : apprendre ce qu'est un comportement **normal** pour un utilisateur, puis détecter automatiquement tout ce qui s'en écarte (anomalie).

Le système détecte deux types de menaces :
- **Insider Threat** : un employé malveillant qui vole des données (accès la nuit, copie de fichiers sensibles, exfiltration)
- **Malware** : un logiciel malveillant qui tourne sur la machine (PowerShell obfusqué, connexions vers des IPs inconnues, beaucoup de processus créés)

**Pourquoi "portable" ?**  
Le système ne dépend pas des valeurs brutes de Wazuh. Il utilise des **déviations comportementales** (z-scores, entropie, ratios) qui fonctionnent quel que soit le SIEM. On peut l'adapter à Splunk, Elastic, ou autre sans changer les modèles ML.

---

## 3. Flux de données (du log à l'alerte)

```
Windows Server 2022 (VM2)
    │
    │  Events Windows : 4624, 4625, 4634, 4688, 4663
    │  Events Sysmon  : 1, 3, 11, 13, 22
    │
    ▼
Wazuh Agent (VM2) ──────────────────────────────────────▶ Wazuh Manager (VM1)
                                                                │
                                                                │ Stocke dans :
                                                                ▼
                                              /var/ossec/logs/alerts/alerts.json
                                                                │
                                                                ▼
                                              parse_logs.py (Feature Engineering)
                                                                │
                                                                ▼
                                                       data/dataset.csv
                                                     (16 features par session)
                                                                │
                                                                ▼
                                              ueba_ml_pipeline.ipynb
                                              ┌─────────────────────────────┐
                                              │  StandardScaler             │
                                              │  Isolation Forest  ──┐      │
                                              │  One-Class SVM     ──┼──▶ Vote ≥2/3 │
                                              │  Autoencoder       ──┘      │
                                              └─────────────────────────────┘
                                                                │
                                                         models/*.pkl
                                                                │
                                                                ▼
                                              daemon.py (temps réel)
                                                                │
                                                                ▼
                                              /var/log/ueba_alerts.json
```

---

## 4. Les Event IDs surveillés

Wazuh collecte les logs Windows et Sysmon. Voici les événements importants :

| Event ID | Source | Ce que ça signifie |
|----------|--------|--------------------|
| 4624 | Windows Security | Login réussi |
| 4625 | Windows Security | Login échoué (tentative ratée) |
| 4634 | Windows Security | Déconnexion |
| 4688 | Windows Security | Nouveau processus créé |
| 4663 | Windows Security | Fichier accédé |
| 1 | Sysmon | Processus créé (plus de détails que 4688) |
| 3 | Sysmon | Connexion réseau sortante |
| 11 | Sysmon | Fichier créé |
| 13 | Sysmon | Valeur de registre modifiée |
| 22 | Sysmon | Requête DNS |

---

## 5. Les 16 features UEBA extraites

Une **session** = séquence d'activité d'un utilisateur sans pause de plus de 60 minutes.  
Pour chaque session, on calcule 16 features :

| Feature | Comment elle est calculée | Pourquoi c'est important |
|---------|--------------------------|--------------------------|
| `hour` | Heure de début de session (0-23) | Un admin qui se connecte à 3h du matin, c'est suspect |
| `is_night` | 1 si hour < 9 ou hour ≥ 18 | Travail hors horaires = signal d'alerte |
| `is_weekend` | 1 si samedi ou dimanche | Idem |
| `nb_files_accessed` | Nombre de fichiers touchés dans la session | Un insider qui exfiltre accède à beaucoup de fichiers d'un coup |
| `nb_sensitive_files` | Fichiers dans `C:\Sensitive\` | Chemin critique configuré comme sensible |
| `nb_failed_logins` | Count Event 4625 dans la session | Brute force = beaucoup d'échecs d'affilée |
| `nb_processes` | Nombre de processus créés | Un malware crée souvent beaucoup de processus |
| `bytes_sent` | Volume réseau sortant | Exfiltration = gros volume envoyé |
| `new_ip` | 1 si une IP inconnue apparaît | Connexion vers un C2 (serveur de commande malware) |
| `sensitive_path_access` | 1 si `C:\Sensitive\` a été accédé | Binaire : oui/non |
| `process_name` | Nom du premier processus (texte) | `xcopy.exe`, `powershell.exe` = suspects |
| `command_line` | Ligne de commande (texte) | `-enc` dans PowerShell = obfuscation |
| `z_score_files` | Déviation de `nb_files_accessed` par rapport à la moyenne de cet utilisateur | Si tu accèdes d'habitude à 10 fichiers et que là tu en accèdes 300, le z-score explose |
| `z_score_logins` | Idem pour les logins échoués | |
| `velocity` | `nb_files / durée_session_minutes` | Accès rapide à beaucoup de fichiers = copie en masse |
| `entropy_commands` | Entropie de Shannon des commandes lancées | Haute entropie = commandes très variées = comportement inhabituel |

**Pourquoi les z-scores rendent le système portable ?**  
Au lieu de dire "si l'utilisateur accède à plus de 50 fichiers → alerte", on dit "si l'utilisateur accède à beaucoup **plus que d'habitude** → alerte". Ça s'adapte automatiquement à chaque utilisateur et chaque environnement.

---

## 6. Le pipeline ML — les 3 modèles

Tous les modèles sont **non supervisés** : ils apprennent uniquement sur des données normales. Pas besoin d'exemples d'attaques labellisées.

### Modèle 1 : Isolation Forest
- **Idée :** Un point anormal est facile à isoler dans un arbre de décision aléatoire. Les anomalies ont des chemins courts, les données normales ont des chemins longs.
- **Cible :** Anomalies comportementales globales (Insider Threat + Malware)
- **Paramètre clé :** `contamination=0.05` → on suppose que 5% du jeu d'entraînement peut contenir des anomalies
- **Output :** -1 = anomalie, 1 = normal

### Modèle 2 : One-Class SVM
- **Idée :** Apprendre une frontière autour des données normales. Tout ce qui tombe en dehors est une anomalie.
- **Cible :** Compromission de compte (profil comportemental très différent)
- **Paramètre clé :** `nu=0.05` (similaire à contamination), `kernel='rbf'`
- **Limitation :** Lent sur grands datasets → on sous-échantillonne à 2000 sessions max
- **Output :** -1 = anomalie, 1 = normal

### Modèle 3 : Autoencoder (Deep Learning)
- **Idée :** Un réseau de neurones compresse les données en une représentation réduite (espace latent de dimension 4), puis les reconstruit. Si la reconstruction est mauvaise (erreur MSE élevée), la donnée est anormale.
- **Architecture :** Encodeur 64→32→16→4 / Décodeur 4→16→32→64 / BatchNorm + Dropout
- **Cible :** Anomalies subtiles que IF et OCSVM ratent
- **Seuil :** μ + 3σ des erreurs sur données normales (couvre 99.7% du normal)
- **Output :** MSE > seuil = anomalie

### Vote d'ensemble (≥ 2/3)
```
Isolation Forest  → vote
One-Class SVM     → vote   →  ≥ 2 votes = ALERTE
Autoencoder       → vote
```
Si 2 ou 3 modèles sont d'accord → alerte levée. Ça réduit les faux positifs.

**Sévérité de l'alerte :**
- `HIGH` : 3 votes, ou 2 votes + accès sensitif ou nuit ou brute force
- `MEDIUM` : 2 votes sans facteur aggravant
- `LOW` : 1 vote (pas d'alerte, juste log)

---

## 7. Structure des fichiers — ce que fait chaque fichier

### `config/config.yaml`
Fichier de configuration central. **Toutes** les constantes du projet sont ici : chemin alerts.json, seuils ML, paramètres du daemon, horaires de travail. Ne pas hardcoder ces valeurs dans le code.

### `src/ueba/config.py`
Chargeur du fichier YAML. Remonte l'arborescence depuis `__file__` pour trouver `config/config.yaml`, quelle que soit la façon dont on lance le script.

### `src/ueba/features/parse_logs.py`
**Cœur du système.** Lit `alerts.json` de Wazuh et produit `data/dataset.csv`.

Pipeline interne :
1. `load_alerts()` → lit le JSON (supporte NDJSON et JSON array)
2. `extract_raw_fields()` → extrait timestamp, username, event_id, file_path, etc.
3. `group_by_session()` → regroupe les événements en sessions (coupure si >60 min d'inactivité)
4. `build_features()` → calcule les 16 features pour chaque session
5. `add_zscores()` → ajoute les z-scores **par utilisateur** (pas globaux)

Usage CLI :
```bash
python -m ueba.features.parse_logs /var/ossec/logs/alerts/alerts.json
# → produit data/dataset.csv
```

### `src/ueba/integration/daemon.py`
Daemon qui tourne en continu sur VM1. Surveille `alerts.json` comme un `tail -f` (détecte aussi la rotation logrotate). Pour chaque nouvelle alerte :
1. Extrait les événements bruts
2. Regroupe en sessions
3. Calcule les features
4. Normalise avec le scaler
5. Applique les 3 modèles
6. Vote → si anomalie → écrit dans `/var/log/ueba_alerts.json`

Gère les signaux SIGTERM/SIGINT pour un arrêt propre. Configurable comme service systemd.

### `notebooks/ueba_ml_pipeline.ipynb`
Notebook Jupyter en 13 sections. Fonctionne sur Google Colab ou en local.

**Flag important :**
```python
USE_REAL_DATA = False  # True pour charger data/dataset.csv
```
- `False` → génère 300 sessions normales synthétiques pour tester le pipeline
- `True` → charge le vrai `dataset.csv` exporté depuis Wazuh

Le notebook entraîne les 3 modèles et les exporte dans `models/`.

### `tests/test_features.py`
14 tests unitaires qui vérifient :
- `extract_raw_fields()` : parsing correct des alertes
- `group_by_session()` : coupure correcte des sessions
- `build_features()` : calcul correct des features (is_night, velocity, sensitive_path, entropy)
- `add_zscores()` : outlier détecté, valeur unique → 0
- `_entropy()` : distribution uniforme = entropie maximale

### `Makefile`
Raccourcis pour les commandes courantes :
```bash
make install        # pip install -e .
make export-dataset # parse_logs.py → data/dataset.csv
make train          # jupyter nbconvert --execute
make run-daemon     # python -m ueba.integration.daemon
make test           # pytest tests/ --cov
make lint           # ruff check
make format         # black
make clean          # supprime __pycache__, .pytest_cache, etc.
```

### `pyproject.toml`
Définit le projet comme package Python installable (`pip install -e .`). Déclare deux entry points CLI :
- `ueba-export` → `ueba.features.parse_logs:main`
- `ueba-daemon` → `ueba.integration.daemon:main`

### `.gitignore`
Exclut du dépôt : `models/*.pkl`, `data/*.csv`, `__pycache__/`, `.ipynb_checkpoints/`, `.env`, `venv/`.

---

## 8. Workflow complet — du zéro à la détection

```
Étape 1 — Sur VM2 (Windows Server) :
  Simuler l'utilisateur user_normal pendant 3+ jours
  Wazuh Agent + Sysmon collectent les logs automatiquement

Étape 2 — Sur VM1 (Ubuntu) :
  python -m ueba.features.parse_logs \
    /var/ossec/logs/alerts/alerts.json \
    --output data/dataset.csv

Étape 3 — Sur Google Colab ou local :
  Ouvrir notebooks/ueba_ml_pipeline.ipynb
  Mettre USE_REAL_DATA = True
  Run All → entraîne les 3 modèles → exporte dans models/

Étape 4 — Copier les modèles sur VM1 :
  scp models/*.pkl user@vm1:/opt/ueba-ml/models/
  scp models/ae_threshold.json user@vm1:/opt/ueba-ml/models/
  scp models/autoencoder.keras user@vm1:/opt/ueba-ml/models/

Étape 5 — Lancer le daemon sur VM1 :
  python -m ueba.integration.daemon --config config/config.yaml

Étape 6 — Simuler une attaque sur VM2 :
  → Insider Threat : connexion à 2h du matin, copier C:\Sensitive\
  → Malware : lancer powershell.exe -enc ...
  → Vérifier les alertes : tail -f /var/log/ueba_alerts.json
```

---

## 9. Décisions d'architecture importantes

### Pourquoi 3 modèles et pas 1 seul ?
Chaque modèle a des forces différentes :
- IF est rapide et bon sur les anomalies globales
- OCSVM trace une frontière précise mais est lent
- L'Autoencoder capte des patterns complexes que les modèles linéaires ratent
Le vote d'ensemble combine leurs forces et réduit les faux positifs.

### Pourquoi des z-scores par utilisateur et non globaux ?
Un utilisateur qui accède à 100 fichiers/jour est normal pour lui, pas pour un autre. Le z-score individuel compare chaque session au **profil de cet utilisateur**, pas à la moyenne globale. C'est ce qui rend le système précis.

### Pourquoi `contamination=0.05` ?
On suppose que même dans les données d'entraînement (censées être normales), il peut y avoir jusqu'à 5% d'anomalies légères. Ce paramètre calibre le seuil de décision des modèles.

### Pourquoi session_minutes=60 ?
Une pause de plus de 60 minutes sans activité signifie probablement que l'utilisateur est passé à autre chose. On coupe la session et on en commence une nouvelle. C'est un compromis raisonnable pour un environnement bureau.

### Pourquoi PyYAML et config.yaml ?
Éviter le hardcoding. Si le chemin de alerts.json change sur VM1, on modifie `config.yaml` sans toucher au code Python. C'est une bonne pratique ingénieur.

---

## 10. Ce qui reste à faire (pistes d'amélioration)

1. **Simulation d'attaques réelles sur VM2** → générer de vraies alertes Wazuh et mesurer les vrais taux de détection
2. **Intégration Wazuh active response** → déclencher un blocage automatique quand une alerte HIGH est levée
3. **Dashboard Wazuh custom** → afficher les alertes UEBA directement dans le dashboard Wazuh
4. **Affinage des seuils** → après les vrais tests, ajuster `contamination` et `ae_threshold_sigma`
5. **Ajout de features** → registry modifications, DNS queries, login type (réseau vs local)
6. **Baseline multi-utilisateurs** → tester avec plusieurs utilisateurs pour valider la généralisation

---

## 11. Résumé des fichiers GitHub

**Repository :** `https://github.com/assia-xnz/pfe-ueba-ml`  
**Branche principale :** `main`

```
pfe-ueba-ml/
├── config/config.yaml
├── data/.gitkeep                  ← dataset.csv va ici (gitignored)
├── models/.gitkeep                ← .pkl vont ici (gitignored)
├── notebooks/ueba_ml_pipeline.ipynb
├── scripts/export_dataset.sh
├── scripts/run_daemon.sh
├── src/ueba/__init__.py
├── src/ueba/config.py
├── src/ueba/features/parse_logs.py
├── src/ueba/integration/daemon.py
├── tests/test_features.py
├── .gitignore
├── LICENSE (MIT)
├── Makefile
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

---

## 12. Comment reprendre cette conversation avec Claude

Donner ce fichier à Claude avec le message suivant :

> "Voici le contexte de mon projet PFE UEBA. Le code est sur https://github.com/assia-xnz/pfe-ueba-ml.
> [Décrire ce que tu veux faire ensuite]"

Claude pourra cloner le repo, lire le code, et continuer exactement là où on s'est arrêtés.

---

*Généré le 2026-06-04 — Claude Sonnet 4.6*
