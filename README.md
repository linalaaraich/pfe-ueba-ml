# pfe-ueba-ml

> Système UEBA Portable — Détection d'Insider Threat & Malware par Machine Learning  
> **PFE — Cires Technologies / Tanger Med Group**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.16-orange?logo=tensorflow)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-f7931e?logo=scikitlearn)
![License](https://img.shields.io/badge/License-MIT-green)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-red)

---

## Architecture

```
VM2 — Windows Server 2022              VM1 — Ubuntu 22.04 (GCP)
┌──────────────────────────┐           ┌──────────────────────────────────────┐
│  Active Directory        │           │  Wazuh Manager + Dashboard           │
│  Wazuh Agent             │──────────▶│  /var/ossec/logs/alerts/alerts.json  │
│  Sysmon                  │           │              │                        │
└──────────────────────────┘           │              ▼                        │
                                       │  src/ueba/features/parse_logs.py     │
                                       │  → data/dataset.csv                  │
                                       │              │                        │
                                       │              ▼                        │
                                       │  notebooks/ueba_ml_pipeline.ipynb    │
                                       │  ┌─────────────────────────────────┐ │
                                       │  │ Isolation Forest  (IF)          │ │
                                       │  │ One-Class SVM     (OCSVM)       │ │
                                       │  │ Autoencoder       (AE)          │ │
                                       │  │ Vote ≥ 2/3  →  models/*.pkl     │ │
                                       │  └─────────────────────────────────┘ │
                                       │              │                        │
                                       │              ▼                        │
                                       │  src/ueba/integration/daemon.py      │
                                       │  → /var/log/ueba_alerts.json         │
                                       └──────────────────────────────────────┘
```

---

## Structure du projet

```
pfe-ueba-ml/
├── config/
│   └── config.yaml                  # Configuration centralisée
├── data/
│   └── dataset.csv                  # Généré par parse_logs.py (gitignored)
├── models/                          # Modèles .pkl exportés (gitignored)
├── notebooks/
│   └── ueba_ml_pipeline.ipynb       # Pipeline ML complet (Google Colab ready)
├── scripts/
│   ├── export_dataset.sh            # Exporter dataset.csv depuis alerts.json
│   └── run_daemon.sh                # Lancer le daemon de détection
├── src/ueba/
│   ├── config.py                    # Chargeur config.yaml
│   ├── features/
│   │   └── parse_logs.py            # alerts.json → features UEBA
│   └── integration/
│       └── daemon.py                # Daemon temps réel Wazuh
├── tests/
│   └── test_features.py             # Tests unitaires
├── .gitignore
├── LICENSE
├── Makefile                         # Commandes de dev
├── pyproject.toml                   # Packaging Python
├── requirements.txt
└── requirements-dev.txt
```

---

## Démarrage rapide

### 1. Installation

```bash
git clone https://github.com/assia-xnz/pfe-ueba-ml.git
cd pfe-ueba-ml
pip install -e .
# ou
make install
```

### 2. Exporter le dataset depuis Wazuh (sur VM1)

```bash
# Depuis la racine du projet
make export-dataset
# ou directement :
python -m ueba.features.parse_logs /var/ossec/logs/alerts/alerts.json
# → produit data/dataset.csv
```

### 3. Entraîner les modèles (notebook)

Ouvrir `notebooks/ueba_ml_pipeline.ipynb` dans **Jupyter** ou **Google Colab**.

- `USE_REAL_DATA = False` → données synthétiques (test rapide)
- `USE_REAL_DATA = True`  → charge `data/dataset.csv`

Les modèles sont exportés dans `models/`.

### 4. Lancer le daemon temps réel (sur VM1)

```bash
make run-daemon
# ou :
python -m ueba.integration.daemon --config config/config.yaml --verbose
# ou via le script shell :
./scripts/run_daemon.sh --verbose
```

---

## Configuration

Toutes les constantes sont centralisées dans [`config/config.yaml`](config/config.yaml) :

```yaml
wazuh:
  alerts_path: /var/ossec/logs/alerts/alerts.json
  session_minutes: 60

detection:
  contamination: 0.01          # Taux d'anomalies attendu (abaissé 0.05→0.01 : FP)
  ensemble_threshold: 2        # Votes minimum / 3

daemon:
  poll_seconds: 30
  history_size: 500
```

---

## Features UEBA

`parse_logs.py` exporte **19 colonnes** par session, dont **14 features
numériques** réellement consommées par les modèles (`NUMERIC_FEATURES`).
`process_name` et `command_line` sont **textuels** : utilisés pour enrichir les
alertes et calculer `entropy_commands`, mais **pas** passés aux modèles.

| Feature (numérique, ML) | Description |
|---------|-------------|
| `hour`, `is_night`, `is_weekend` | Contexte temporel |
| `nb_files_accessed`, `nb_sensitive_files` | Activité fichiers |
| `nb_failed_logins` | Tentatives d'authentification |
| `nb_processes` | Activité processus |
| `bytes_sent`, `new_ip` | Activité réseau |
| `sensitive_path_access` | Accès à `C:\Sensitive\` |
| `z_score_files`, `z_score_logins` | Déviations individuelles |
| `velocity` | Fichiers accédés / minute |
| `entropy_commands` | Diversité des commandes (calculée depuis `command_line`) |

> Colonnes textuelles additionnelles (non-ML) : `process_name`, `command_line`
> ; plus `timestamp`, `username`, `session_duration_min` dans le CSV.

---

## Modèles ML (100% non supervisé)

| Modèle | Objectif | Fichier |
|--------|----------|---------|
| Isolation Forest | Anomalies comportementales | `models/isolation_forest.pkl` |
| One-Class SVM | Compromission de compte | `models/one_class_svm.pkl` |
| Autoencoder (Keras) | Anomalies subtiles | `models/autoencoder.keras` |
| StandardScaler | Normalisation | `models/scaler.pkl` |

Vote majoritaire : **alerte levée si ≥ 2 modèles sur 3 détectent une anomalie**.

---

## Commandes Makefile

```bash
make install        # Installer les dépendances
make install-dev    # + outils de dev (pytest, ruff, black)
make export-dataset # Exporter data/dataset.csv
make train          # Exécuter le notebook
make run-daemon     # Lancer le daemon
make test           # Tests unitaires
make lint           # Vérification du code (ruff)
make format         # Formatage (black)
make clean          # Nettoyer les fichiers temporaires
```

---

## Tests

```bash
make test
# ou
pytest tests/ -v --cov=src/ueba
```

---

## Déploiement systemd (production — VM1)

```ini
# /etc/systemd/system/ueba.service
[Unit]
Description=UEBA Detection Daemon
After=network.target

[Service]
Type=simple
User=wazuh
WorkingDirectory=/opt/ueba-ml
ExecStart=/opt/ueba-ml/venv/bin/python -m ueba.integration.daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now ueba
```

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| SIEM | Wazuh 4.9.2 |
| Cloud | Google Cloud Platform (2 VMs, e2-standard-2) |
| OS | Ubuntu 22.04 LTS / Windows Server 2022 |
| ML | scikit-learn 1.5, TensorFlow 2.16 |
| Langage | Python 3.10+ |

---

## Licence

MIT — voir [LICENSE](LICENSE)
